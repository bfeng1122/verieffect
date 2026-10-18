"""
Probes — deterministic checks against systems of record.

Rules (non-negotiable, from SPEC.md):
- No LLM. Every probe reads ground truth directly.
- Probes NEVER mutate their target. Read-only by construction.
- Every probe returns (observed: dict, verdict: str). verdict is one of
  PASS / FAIL / UNVERIFIABLE. UNVERIFIABLE means the probe could not reach
  ground truth (missing dep, network error) — it is NOT a silent pass.
- `expect` semantics are exact-match on the declared fields; extra observed
  data is recorded but not judged.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

PASS, FAIL, UNVERIFIABLE = "PASS", "FAIL", "UNVERIFIABLE"


def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- file_exists

def probe_file_exists(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: filesystem path. expect keys (all optional):
    min_bytes, max_bytes, sha256, modified_within_s, modified_after /
    modified_before (ISO8601 window, UTC assumed if no offset),
    contains (text substring).
    """
    expect = expect or {}
    p = Path(target)
    observed: dict[str, Any] = {"path": str(p)}
    try:
        st = p.stat()
    except FileNotFoundError:
        observed["exists"] = False
        return observed, FAIL
    except OSError as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE

    observed.update({
        "exists": True,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    })
    if expect.get("sha256") or expect.get("contains"):
        try:
            observed["sha256"] = _sha256_file(p)
        except OSError as e:
            observed["hash_error"] = str(e)
            return observed, UNVERIFIABLE

    verdict = PASS
    if "min_bytes" in expect and st.st_size < expect["min_bytes"]:
        verdict = FAIL
    if "max_bytes" in expect and st.st_size > expect["max_bytes"]:
        verdict = FAIL
    if "sha256" in expect and observed.get("sha256") != expect["sha256"]:
        verdict = FAIL
    if "modified_within_s" in expect:
        import time
        age = time.time() - st.st_mtime
        observed["age_s"] = round(age, 1)
        if age > expect["modified_within_s"]:
            verdict = FAIL
    if "modified_after" in expect or "modified_before" in expect:
        from datetime import datetime, timezone

        def _parse(s: str):
            dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

        try:
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            observed["mtime_iso"] = mtime.isoformat()
            if "modified_after" in expect and mtime <= _parse(expect["modified_after"]):
                verdict = FAIL
            if "modified_before" in expect and mtime > _parse(expect["modified_before"]):
                verdict = FAIL
        except ValueError as e:
            observed["modified_window_error"] = str(e)
            return observed, UNVERIFIABLE
    if "contains" in expect:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            found = expect["contains"] in text
            observed["contains_found"] = found
            if not found:
                verdict = FAIL
        except OSError as e:
            observed["read_error"] = str(e)
            return observed, UNVERIFIABLE
    return observed, verdict


# ---------------------------------------------------------------- http_ok

def probe_http_ok(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: URL. expect keys (all optional):
    status (int, default 200), body_contains (str), body_sha256 (str),
    method (GET default), timeout_s (default 15).
    Probe performs the request ITSELF — the claimer's reported response is
    never trusted.
    """
    expect = expect or {}
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}, UNVERIFIABLE

    method = expect.get("method", "GET").upper()
    timeout = expect.get("timeout_s", 15)
    observed: dict[str, Any] = {"url": target, "method": method}
    try:
        resp = requests.request(method, target, timeout=timeout)
    except Exception as e:  # noqa: BLE001 — network errors are UNVERIFIABLE
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE

    body = resp.content
    observed.update({
        "status": resp.status_code,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    })

    verdict = PASS
    want_status = expect.get("status", 200)
    if resp.status_code != want_status:
        verdict = FAIL
    if "body_contains" in expect:
        try:
            text = body.decode("utf-8", errors="replace")
            found = expect["body_contains"] in text
        except Exception:  # noqa: BLE001
            found = False
        observed["body_contains_found"] = found
        if not found:
            verdict = FAIL
    if "body_sha256" in expect and observed["body_sha256"] != expect["body_sha256"]:
        verdict = FAIL
    return observed, verdict


# ---------------------------------------------------------------- db_row_matches

def _numeq(a: Any, b: Any) -> bool:
    """Compare values; int/float compare numerically, bools never equal ints."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b if isinstance(a, bool) and isinstance(b, bool) else a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    return a == b


def _row_eq(observed_row: Any, expected_row: Any) -> bool:
    if isinstance(observed_row, (list, tuple)) and isinstance(expected_row, (list, tuple)):
        return len(observed_row) == len(expected_row) and all(
            _numeq(o, e) for o, e in zip(observed_row, expected_row))
    return _numeq(observed_row, expected_row)


def probe_db_row_matches(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: one of
      sqlite:///<path>  (or a bare path ending .db/.sqlite/.sqlite3)
      <path>.jsonl      (append-only row store, e.g. the trading ledger)
      <path>.json       (single-document store, e.g. portfolio.json)

    expect keys by backend:
      sqlite: {"query": "SELECT ...", "rows": [[...], ...]?, "row_count": int?}
              Query MUST be SELECT/WITH; it is executed against a READ-ONLY
              connection. If neither rows nor row_count given, PASS = query ran
              (evidence snapshot only).
      jsonl:  {"where": {...}?, "match": {...}, "occurrence": "last"|"first"|"any"}
              where filters rows (all listed fields equal); match is checked on
              the selected row. Default: last row matching where.
      json:   {"fields": {"dotted.path": value, ...}}  e.g. {"cash": 999266.8,
              "positions.AA.qty": 233}. List indices as ints in the path.

    A missing target file is FAIL (the claimed record does not exist), matching
    file_exists semantics. Backend/driver errors are UNVERIFIABLE.
    """
    expect = expect or {}

    # --- resolve backend + path
    path = target
    backend = None
    if target.startswith("sqlite:///"):
        backend, path = "sqlite", target[len("sqlite:///"):]
    elif target.startswith("sqlite://"):
        backend, path = "sqlite", target[len("sqlite://"):]
    low = path.lower()
    if backend is None:
        if low.endswith((".db", ".sqlite", ".sqlite3")):
            backend = "sqlite"
        elif low.endswith(".jsonl"):
            backend = "jsonl"
        elif low.endswith(".json"):
            backend = "json"
        else:
            return {"target": target, "error": "cannot infer backend from target "
                    "(use sqlite:///, or a .db/.jsonl/.json path)"}, UNVERIFIABLE

    p = Path(path)
    observed: dict[str, Any] = {"target": target, "backend": backend}
    if not p.exists():
        observed["exists"] = False
        return observed, FAIL
    observed["exists"] = True

    # --- sqlite
    if backend == "sqlite":
        import sqlite3
        query = expect.get("query")
        if not query or not isinstance(query, str):
            observed["error"] = "expect.query (SELECT statement) is required"
            return observed, UNVERIFIABLE
        head = query.strip().lower()
        if not (head.startswith("select") or head.startswith("with")):
            observed["error"] = "refused: query must be SELECT/WITH (read-only by construction)"
            return observed, UNVERIFIABLE
        try:
            con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True,
                                  timeout=expect.get("timeout_s", 10))
            cur = con.execute(query)
            rows = cur.fetchall()
            con.close()
        except sqlite3.Error as e:
            observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        observed["row_count"] = len(rows)
        observed["rows"] = [list(r) for r in rows[:50]]
        verdict = PASS
        if "row_count" in expect and not _numeq(len(rows), expect["row_count"]):
            verdict = FAIL
        if "rows" in expect:
            exp_rows = expect["rows"]
            ok = (len(rows) == len(exp_rows) and
                  all(_row_eq(o, e) for o, e in zip(rows, exp_rows)))
            observed["rows_match"] = ok
            if not ok:
                verdict = FAIL
        return observed, verdict

    # --- jsonl
    if backend == "jsonl":
        import json as _json
        try:
            lines = p.read_text(encoding="utf-8").strip().splitlines()
            records = [_json.loads(x) for x in lines if x.strip()]
        except (OSError, ValueError) as e:
            observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        observed["total_rows"] = len(records)
        where = expect.get("where") or {}
        match = expect.get("match")
        if not match or not isinstance(match, dict):
            observed["error"] = "expect.match (dict of field->value) is required"
            return observed, UNVERIFIABLE
        matched = [r for r in records if isinstance(r, dict) and
                   all(_numeq(r.get(k), v) for k, v in where.items())]
        observed["matched_rows"] = len(matched)
        if not matched:
            observed["selected"] = None
            return observed, FAIL
        occurrence = expect.get("occurrence", "last")
        if occurrence == "count":
            expected_n = match.get("_count")
            ok = _numeq(len(matched), expected_n) if expected_n is not None else False
            observed["count_match"] = ok
            return observed, PASS if ok else FAIL
        row = matched[-1] if occurrence != "first" else matched[0]
        observed["selected"] = {k: row.get(k) for k in list(where) + list(match)}
        results = {}
        for k, v in match.items():
            found = _get_dotted(row, k) if "." in k else row.get(k)
            results[k] = {"expected": v, "observed": found, "ok": _numeq(found, v)}
        observed["match_results"] = results
        if occurrence == "any":
            ok = all(any(_numeq(_dot_or_get(r, k), v) for r in matched)
                     for k, v in match.items())
            observed["any_match"] = ok
            return observed, PASS if ok else FAIL
        verdict = PASS if all(r["ok"] for r in results.values()) else FAIL
        return observed, verdict

    # --- json document
    import json as _json
    try:
        doc = _json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE
    fields = expect.get("fields")
    if not fields or not isinstance(fields, dict):
        observed["error"] = "expect.fields (dict of dotted-path->value) is required"
        return observed, UNVERIFIABLE
    results = {}
    for k, v in fields.items():
        found = _get_dotted(doc, k)
        results[k] = {"expected": v, "observed": found, "ok": _numeq(found, v)}
    observed["match_results"] = results
    verdict = PASS if all(r["ok"] for r in results.values()) else FAIL
    return observed, verdict


_MISSING = object()


def _get_dotted(doc: Any, path: str) -> Any:
    cur = doc
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return _MISSING
        else:
            return _MISSING
    return cur


def _dot_or_get(row: Any, key: str) -> Any:
    return _get_dotted(row, key) if "." in key else row.get(key) if isinstance(row, dict) else _MISSING


# ---------------------------------------------------------------- exit_code

def probe_exit_code(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: shell command re-run BY agentproof (the claimer's reported
    result is never trusted). expect keys (all optional):
      exit_code (int, default 0), stdout_contains (str), stdout_sha256 (str),
      timeout_s (default 30), workdir (cwd for the run).

    MVP sandbox = hard timeout + output caps + no stdin + isolated run. The
    command still executes with agentproof's OS privileges — only run claims
    from agents the operator controls (SPEC: operator-supplied trust boundary).
    Timeout -> FAIL (observed.timed_out). Cannot-spawn (missing binary, OS
    error) -> UNVERIFIABLE.
    """
    import subprocess

    expect = expect or {}
    timeout = expect.get("timeout_s", 30)
    workdir = expect.get("workdir") or None
    observed: dict[str, Any] = {"command": target, "timeout_s": timeout}
    try:
        cp = subprocess.run(
            target, shell=True, cwd=workdir,
            capture_output=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        observed["timed_out"] = True
        return observed, FAIL
    except OSError as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE

    stdout = cp.stdout or b""
    stderr = cp.stderr or b""
    observed.update({
        "exit_code": cp.returncode,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_tail": stderr.decode("utf-8", errors="replace")[-256:],
    })
    stdout_text = stdout.decode("utf-8", errors="replace")
    observed["stdout_head"] = stdout_text[:1024]

    verdict = PASS
    want = expect.get("exit_code", 0)
    if cp.returncode != want:
        verdict = FAIL
    if "stdout_contains" in expect:
        found = expect["stdout_contains"] in stdout_text
        observed["stdout_contains_found"] = found
        if not found:
            verdict = FAIL
    if "stdout_sha256" in expect and observed["stdout_sha256"] != expect["stdout_sha256"]:
        verdict = FAIL
    return observed, verdict


# ---------------------------------------------------------------- registry

PROBES = {
    "file_exists": probe_file_exists,
    "http_ok": probe_http_ok,
    "db_row_matches": probe_db_row_matches,
    "exit_code": probe_exit_code,
}
