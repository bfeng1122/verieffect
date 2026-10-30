#!/usr/bin/env python3
"""agentproof test suite — run with .venv/Scripts/python.exe tests/test_all.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentproof.core import (  # noqa: E402
    ChainStore, Keyring, canonical_json, sha256_hex,
    receipt_body, sign_receipt, verify_chain, verify_receipt, GENESIS_HASH,
)
from agentproof.probes import (  # noqa: E402
    probe_file_exists, probe_http_ok, probe_db_row_matches, probe_exit_code,
    PASS, FAIL, UNVERIFIABLE,
)

# Interpreter for subprocess-based CLI tests: default to the local venv python
# (Windows), overridable so CI can use the ambient interpreter on any OS.
_default_py = ROOT / ".venv" / "Scripts" / "python.exe"
if not _default_py.exists():
    _default_py = ROOT / ".venv" / "bin" / "python"
PY = os.environ.get("AGENTPROOF_TEST_PY") or (
    str(_default_py) if _default_py.exists() else sys.executable)
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("  PASS " if cond else "  FAIL ") + name)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)

    print("== keyring ==")
    kr = Keyring(tmp / "keys")
    priv = kr.load_or_create()
    check("key files created", kr.priv_path.exists() and kr.pub_path.exists())
    priv2 = Keyring(tmp / "keys").load_or_create()
    check("key reload is stable",
          priv2.public_key().public_bytes_raw() == priv.public_key().public_bytes_raw())
    pub_pem = kr.public_key_pem()

    print("== sign / verify ==")
    store = ChainStore(tmp / "chains")
    body = receipt_body("c1", "agent-a", "file_exists", "x", {}, {"ok": 1}, "PASS",
                        store.last_hash("agent-a"))
    check("genesis prev-hash", body["prev_receipt_hash"] == GENESIS_HASH)
    r1 = sign_receipt(body, priv)
    ok, why = verify_receipt(r1, pub_pem)
    check(f"valid signature verifies ({why})", ok)
    check("sig restored after verify (no mutation)", "sig" in r1)

    tampered = dict(r1); tampered["verdict"] = "FAIL"
    ok2, _ = verify_receipt(tampered, pub_pem)
    check("tampered verdict rejected", not ok2)

    tampered2 = dict(r1); tampered2["sig"] = "ed25519:" + "00" * 64
    ok3, _ = verify_receipt(tampered2, pub_pem)
    check("forged signature rejected", not ok3)

    print("== chain ==")
    store.append(r1)
    b2 = receipt_body("c2", "agent-a", "file_exists", "y", {}, {"ok": 2}, "PASS",
                      store.last_hash("agent-a"))
    r2 = sign_receipt(b2, priv)
    store.append(r2)
    problems = verify_chain(store.read_all("agent-a"), pub_pem)
    check("intact chain audits clean", problems == [])

    # flip a stored receipt on disk -> chain must break
    chain_file = store._path("agent-a")
    lines = chain_file.read_text(encoding="utf-8").splitlines()
    evil = json.loads(lines[0]); evil["verdict"] = "FAIL"
    lines[0] = json.dumps(evil, sort_keys=True, ensure_ascii=False)
    chain_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems2 = verify_chain(store.read_all("agent-a"), pub_pem)
    check("on-disk tamper detected", len(problems2) >= 1)

    print("== probe: file_exists ==")
    f = tmp / "out.csv"
    f.write_bytes(b"A" * 2048)
    obs, v = probe_file_exists(str(f), {"min_bytes": 1024})
    check("file present + big enough -> PASS", v == PASS and obs["size"] == 2048)
    obs, v = probe_file_exists(str(f), {"min_bytes": 4096})
    check("too small -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(tmp / "nope.bin"), {"min_bytes": 1})
    check("missing file -> FAIL (not UNVERIFIABLE)", v == FAIL)
    obs, v = probe_file_exists(str(f), {"sha256": "0" * 64})
    check("wrong hash -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(f), {"contains": "AAA"})
    check("contains -> PASS", v == PASS and obs["contains_found"] is True)
    obs, v = probe_file_exists(str(f), {"modified_after": "1970-01-02T00:00:00Z"})
    check("modified_after old cutoff -> PASS", v == PASS)
    obs, v = probe_file_exists(str(f), {"modified_after": "2999-01-01T00:00:00Z"})
    check("modified_after future cutoff -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(f), {"modified_before": "2999-01-01T00:00:00Z"})
    check("modified_before future cutoff -> PASS", v == PASS)
    obs, v = probe_file_exists(str(f), {"modified_before": "1970-01-02T00:00:00Z"})
    check("modified_before past cutoff -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(f), {"modified_after": "not-a-date"})
    check("modified_after garbage -> UNVERIFIABLE", v == UNVERIFIABLE)

    print("== probe: http_ok ==")
    obs, v = probe_http_ok("https://example.com/", {"status": 200})
    check("live GET 200 -> PASS (network permitting)",
          v == PASS or v == UNVERIFIABLE)
    obs, v = probe_http_ok("https://example.com/", {"status": 418})
    check("wrong expected status -> FAIL (or UNVERIFIABLE offline)",
          v in (FAIL, UNVERIFIABLE))
    obs, v = probe_http_ok("https://definitely-not-a-real-host-9x7q.invalid/", {})
    check("unreachable host -> UNVERIFIABLE, never PASS", v == UNVERIFIABLE)

    print("== db_row_matches (sqlite) ==")
    import sqlite3
    dbp = tmp / "t.db"
    con = sqlite3.connect(str(dbp))
    con.execute("CREATE TABLE fills (id INTEGER, ticker TEXT, qty INTEGER, px REAL)")
    con.executemany("INSERT INTO fills VALUES (?,?,?,?)",
                    [(1, "AA", 233, 42.79), (2, "MU", 19, 1048.85)])
    con.commit(); con.close()
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT ticker, qty FROM fills WHERE id=1",
                                             "rows": [["AA", 233]]})
    check("sqlite exact row -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT ticker, qty FROM fills WHERE id=1",
                                             "rows": [["AA", 999]]})
    check("sqlite wrong row -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT COUNT(*) FROM fills",
                                             "rows": [[2]]})
    check("sqlite row_count via rows -> PASS", v == PASS)
    obs, v = probe_db_row_matches(f"sqlite:///{dbp}", {"query": "SELECT * FROM fills",
                                                       "row_count": 2})
    check("sqlite:// scheme + row_count -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(dbp), {"query": "DELETE FROM fills"})
    check("non-SELECT refused -> UNVERIFIABLE", v == UNVERIFIABLE)
    con = sqlite3.connect(str(dbp)); n = con.execute("SELECT COUNT(*) FROM fills").fetchone()[0]; con.close()
    check("refused write left table intact", n == 2)
    obs, v = probe_db_row_matches(str(tmp / "nope.db"), {"query": "SELECT 1"})
    check("missing db -> FAIL not UNVERIFIABLE", v == FAIL)

    print("== db_row_matches (jsonl ledger) ==")
    jl = tmp / "ledger.jsonl"
    jl.write_text('{"ts":"a","ticker":"NVDA","side":"buy","qty":5,"price":1.0}\n'
                  '{"ts":"b","ticker":"AA","side":"buy","qty":233,"price":42.79}\n'
                  '{"ts":"c","ticker":"AA","side":"sell","qty":233,"price":41.5}\n',
                  encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl), {"where": {"ticker": "AA", "side": "sell"},
                                            "match": {"qty": 233, "price": 41.5}})
    check("jsonl where+match last row -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(jl), {"where": {"ticker": "AA", "side": "sell"},
                                            "match": {"qty": 100}})
    check("jsonl wrong match -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(jl), {"where": {"ticker": "ZZZ"}, "match": {"qty": 1}})
    check("jsonl no matching row -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(jl), {"occurrence": "any",
                                            "match": {"ticker": "NVDA"}})
    check("jsonl occurrence=any finds earlier row -> PASS", v == PASS)
    # bool trap regression: True must never match a numeric 1
    jl2 = tmp / "booltrap.jsonl"
    jl2.write_text('{"qty": 1, "flag": true}\n', encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl2), {"match": {"qty": True}})
    check("bool True does NOT match numeric 1", v == FAIL)
    obs, v = probe_db_row_matches(str(jl2), {"match": {"flag": True}})
    check("bool True matches bool true", v == PASS)
    obs, v = probe_db_row_matches(str(jl2), {"match": {"qty": 1}})
    check("numeric 1 still matches numeric 1", v == PASS)
    obs, v = probe_db_row_matches(str(jl), {})
    check("jsonl missing match -> UNVERIFIABLE", v == UNVERIFIABLE)

    print("== db_row_matches (json doc) ==")
    jj = tmp / "portfolio.json"
    jj.write_text('{"cash": 999266.8, "positions": {"AA": {"qty": 233}}, "closed": [{"pnl": -300.57}]}',
                  encoding="utf-8")
    obs, v = probe_db_row_matches(str(jj), {"fields": {"cash": 999266.8,
                                                       "positions.AA.qty": 233,
                                                       "closed.0.pnl": -300.57}})
    check("json dotted fields -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(jj), {"fields": {"cash": 1.0}})
    check("json wrong field -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(jj), {"fields": {"positions.NVDA.qty": 1}})
    check("json missing path -> FAIL (not error)", v == FAIL)
    obs, v = probe_db_row_matches(str(tmp / "no-such-file.json"), {"fields": {"x": 1}})
    check("missing json file -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches("target.txt", {})
    check("unrecognized backend -> UNVERIFIABLE", v == UNVERIFIABLE)

    print("== exit_code ==")
    SHELL_OK = {"allow_shell": True}
    obs, v = probe_exit_code(f'"{PY}" -c "print(2+2)"',
                             {**SHELL_OK, "exit_code": 0, "stdout_contains": "4"})
    check("command exit 0 + stdout -> PASS", v == PASS)
    check("exit_code observed in receipt", obs.get("exit_code") == 0)
    obs, v = probe_exit_code(f'"{PY}" -c "print(2+2)"', {"exit_code": 0})
    check("exit_code WITHOUT allow_shell -> refused FAIL", v == FAIL and "refused" in str(obs.get("error", "")))
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', {**SHELL_OK, "exit_code": 3})
    check("nonzero exit matches expected -> PASS", v == PASS)
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', SHELL_OK)
    check("nonzero exit vs default 0 -> FAIL", v == FAIL)
    obs, v = probe_exit_code(f'"{PY}" -c "import time; time.sleep(30)"',
                             {**SHELL_OK, "timeout_s": 2})
    check("timeout -> FAIL with timed_out flag", v == FAIL and obs.get("timed_out") is True)
    obs, v = probe_exit_code(f'"{PY}" -c "print(\'x\')"',
                             {**SHELL_OK, "stdout_sha256": "0" * 64})
    check("wrong stdout_sha256 -> FAIL", v == FAIL)

    # --- SQL guard rejects lookalike keywords (tightened regex) ---
    sq = tmp / "guard.db"
    import sqlite3 as _sq3
    _con = _sq3.connect(str(sq)); _con.execute("CREATE TABLE t (x INTEGER)"); _con.commit(); _con.close()
    obs, v = probe_db_row_matches(f"sqlite:///{sq.as_posix()}", {"query": "selectfoo 1"})
    check("'selectfoo' rejected by keyword guard", v == UNVERIFIABLE and "refused" in str(obs.get("error", "")))
    obs, v = probe_db_row_matches(f"sqlite:///{sq.as_posix()}", {"query": "SELECT COUNT(*) FROM t", "row_count": 0})
    check("legit SELECT still passes guard", v == PASS)
    obs, v = probe_db_row_matches(f"sqlite:///{sq.as_posix()}", {"query": "select"})
    check("bare 'select' (keyword + EOL) reaches sqlite, errors cleanly",
          v == UNVERIFIABLE and "refused" not in str(obs.get("error", "")))

    print("== CLI end-to-end ==")
    env = dict(os.environ, AGENTPROOF_HOME=str(tmp / "cli_home"))
    cp = subprocess.run(
        [PY, "-m", "agentproof.cli", "claim", "file_exists",
         "--agent", "cli-agent", "--target", str(f),
         "--expect", json.dumps({"min_bytes": 1024}),
         "--out", str(tmp / "receipt.json")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("claim PASS exit code 0", cp.returncode == 0)
    rec = json.loads((tmp / "receipt.json").read_text(encoding="utf-8"))
    check("receipt has sig + verdict PASS", rec.get("verdict") == "PASS" and "sig" in rec)

    cp2 = subprocess.run(
        [PY, "-m", "agentproof.cli", "claim", "file_exists",
         "--agent", "cli-agent", "--target", str(tmp / "ghost.txt"),
         "--expect", "{}"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("claim FAIL exit code 1", cp2.returncode == 1)

    cp3 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"),
         "--pubkey", str(tmp / "cli_home" / "keys" / "agentproof_ed25519.pub"),
         str(tmp / "receipt.json")],
        capture_output=True, text=True, cwd=str(ROOT))
    check("standalone offline verifier validates receipt",
          cp3.returncode == 0 and "VALID" in cp3.stdout)

    cp4 = subprocess.run(
        [PY, "-m", "agentproof.cli", "audit", "--agent", "cli-agent"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("CLI audit of 2-receipt chain clean", cp4.returncode == 0)

    # --- truncation detection via anchored head/count (the fix for C1) ---
    import re
    m = re.search(r"chain head: ([0-9a-f]{64})", cp4.stdout)
    check("audit prints chain head", bool(m))
    head = m.group(1) if m else ""
    chain_files = list((tmp / "cli_home" / "chains").glob("chain_cli-agent*.jsonl"))
    lines = chain_files[0].read_text(encoding="utf-8").splitlines()
    chain_files[0].write_text("\n".join(lines[:1]) + "\n", encoding="utf-8")  # drop newest
    cp5 = subprocess.run(
        [PY, "-m", "agentproof.cli", "audit", "--agent", "cli-agent",
         "--expect-count", "2", "--expect-head", head],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("tail truncation detected via anchored count+head",
          cp5.returncode == 1 and "truncation" in cp5.stdout)
    chain_files[0].write_text("\n".join(lines) + "\n", encoding="utf-8")  # restore

    # --- chain relabeling rejected (the fix for C2) ---
    evil_chain = (tmp / "cli_home" / "chains" / chain_files[0].name.replace("cli-agent", "other-agent"))
    evil_chain.write_text(chain_files[0].read_text(encoding="utf-8"), encoding="utf-8")
    cp6 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"), "--agent", "other-agent", "--chain",
         "--pubkey", str(tmp / "cli_home" / "keys" / "agentproof_ed25519.pub"),
         str(evil_chain)],
        capture_output=True, text=True, cwd=str(ROOT))
    check("relabeled chain rejected (agent binding)",
          cp6.returncode == 1 and "agent_ok=False" in cp6.stdout)
    evil_chain.unlink()

    # --- NaN rejected in --expect (m3) ---
    cp7 = subprocess.run(
        [PY, "-m", "agentproof.cli", "claim", "file_exists",
         "--agent", "cli-agent", "--target", str(f),
         "--expect", '{"min_bytes": NaN}'],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("NaN in --expect rejected with exit 2", cp7.returncode == 2)

    # --- http_ok refuses non-GET/HEAD methods by default (M3 partial) ---
    obs, v = probe_http_ok("http://127.0.0.1:1/", {"method": "DELETE"})
    check("http_ok DELETE refused without allow_unsafe_method",
          v == FAIL and "refused" in str(obs.get("error", "")))

    # --- verify_receipt robustness: non-string sig no longer raises (M4) ---
    ok_r, why_r = verify_receipt({"v": 1, "sig": 123, "claim_id": "x"}, pub_pem)
    check("non-string sig -> clean rejection, no crash", not ok_r)
    ok_v, why_v = verify_receipt({"v": 99, "sig": "ed25519:" + "00" * 64}, pub_pem)
    check("unknown schema version rejected", not ok_v and "version" in why_v)

    # --- legacy chain fallback must not let colliding ids share a file (re-review #1) ---
    store2 = ChainStore(tmp / "chains2")
    # simulate a pre-hash-format legacy chain owned by "a_b"
    legacy_p = tmp / "chains2" / "chain_a_b.jsonl"
    legacy_p.parent.mkdir(parents=True, exist_ok=True)
    bA = receipt_body("cA", "a_b", "file_exists", "x", {}, {}, "PASS", GENESIS_HASH)
    legacy_p.write_text(json.dumps(sign_receipt(bA, priv), sort_keys=True) + "\n",
                        encoding="utf-8")
    pA = store2._path("a_b")
    pB = store2._path("a b")
    check("'a_b' resolves to its legacy file", pA == legacy_p)
    check("colliding id 'a b' does NOT inherit a_b's legacy file", pA != pB)
    check("'a b' resolves to its own (new) chain file", not pB.exists())

    # --- --expect-head tolerates stray whitespace (re-review #3) ---
    m2 = re.search(r"chain head: ([0-9a-f]{64})", cp4.stdout)
    cp8 = subprocess.run(
        [PY, "-m", "agentproof.cli", "audit", "--agent", "cli-agent",
         "--expect-head", (m2.group(1) if m2 else "") + "  \n"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("head with trailing whitespace still matches", cp8.returncode == 0)

    # --- internal CLI verify: malformed receipt JSON -> clean exit 2, no traceback ---
    bad_receipt = tmp / "bad_receipt.json"
    bad_receipt.write_text("{not json", encoding="utf-8")
    cp9 = subprocess.run(
        [PY, "-m", "agentproof.cli", "verify", str(bad_receipt)],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("cli verify on malformed JSON: exit 2, no traceback",
          cp9.returncode == 2 and "Traceback" not in cp9.stderr)

    # --- checkpoint subcommand: anchor matches audit expectations ---
    cp10 = subprocess.run(
        [PY, "-m", "agentproof.cli", "checkpoint", "--agent", "cli-agent", "--json"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    cpj = json.loads(cp10.stdout) if cp10.returncode == 0 else {}
    check("checkpoint --json prints agent/count/head",
          cp10.returncode == 0 and cpj.get("agent_id") == "cli-agent"
          and cpj.get("count") == 2 and len(cpj.get("head", "")) == 64)
    cp11 = subprocess.run(
        [PY, "-m", "agentproof.cli", "audit", "--agent", "cli-agent",
         "--expect-count", str(cpj.get("count")), "--expect-head", cpj.get("head", "")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("audit with checkpoint anchor passes (round-trip)", cp11.returncode == 0)

    print("== deep-review regression tests ==")
    # verify_receipt must not mutate the caller's dict AT ALL (copy-not-pop)
    rec_copy = json.loads(json.dumps(rec))
    verify_receipt(rec, pub_pem)
    check("verify_receipt leaves caller dict untouched", rec == rec_copy)

    # read_all: corrupt line -> structured RuntimeError naming the line
    corrupt_store = ChainStore(tmp / "corrupt_chains")
    corrupt_store.append(sign_receipt(
        receipt_body("cX", "cx", "file_exists", "x", {}, {}, "PASS", GENESIS_HASH), priv))
    cpath = corrupt_store._path("cx")
    cpath.write_text(cpath.read_text(encoding="utf-8") + "{broken json\n",
                     encoding="utf-8")
    try:
        corrupt_store.read_all("cx")
        check("read_all corrupt line raises structured error", False)
    except RuntimeError as e:
        check("read_all corrupt line raises structured error",
              "corrupt line 2" in str(e))

    # timestamp regression detection (backdating guard)
    ts_store = ChainStore(tmp / "ts_chains")
    b_old = receipt_body("t1", "ts-agent", "file_exists", "x", {}, {}, "PASS", GENESIS_HASH)
    b_old["checked_at"] = "2026-10-02T00:00:00Z"
    r_old = sign_receipt(b_old, priv)
    ts_store.append(r_old)
    b_new = receipt_body("t2", "ts-agent", "file_exists", "x", {}, {}, "PASS",
                         sha256_hex(canonical_json(r_old)))
    b_new["checked_at"] = "2026-10-01T00:00:00Z"  # EARLIER than previous
    ts_store.append(sign_receipt(b_new, priv))
    ts_problems = verify_chain(ts_store.read_all("ts-agent"), pub_pem)
    check("backdated receipt flagged as timestamp regression",
          any("timestamp regression" in p for p in ts_problems))

    # file_exists contains: match spanning a chunk boundary (streaming reader)
    big = tmp / "big.bin"
    needle = b"NEEDLE-ACROSS-BORDER"
    big.write_bytes(b"A" * ((1 << 20) - 5) + needle + b"B" * 100)
    obs_big, v_big = probe_file_exists(str(big), {"contains": needle.decode()})
    check("contains match spanning 1MiB chunk boundary found", v_big == PASS)
    obs_big2, v_big2 = probe_file_exists(str(big), {"contains": "NOT-PRESENT"})
    check("contains negative still FAILs on big file", v_big2 == FAIL)

    # cli verify on a FORGED receipt must label fields unverified, not echo PASS
    forged = json.loads((tmp / "receipt.json").read_text(encoding="utf-8"))
    forged["verdict"] = "PASS"
    forged["sig"] = "ed25519:" + "ab" * 64
    forged_p = tmp / "forged.json"
    forged_p.write_text(json.dumps(forged), encoding="utf-8")
    cp12 = subprocess.run(
        [PY, "-m", "agentproof.cli", "verify", str(forged_p)],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("forged receipt: verdict labeled unverified_claim, not echoed as truth",
          cp12.returncode == 1 and "unverified_claim" in cp12.stdout)

    # --- concurrent claims must not fork the chain (transaction lock) ---
    conc_home = tmp / "conc_home"
    conc_code = (
        "import sys; sys.path.insert(0, r'%s')\n"
        "from agentproof.core import ChainStore, Keyring, receipt_body, sign_receipt\n"
        "from pathlib import Path\n"
        "import os\n"
        "home = Path(os.environ['AGENTPROOF_HOME'])\n"
        "store = ChainStore(home / 'chains'); kr = Keyring(home / 'keys')\n"
        "priv = kr.load_or_create()\n"
        "for i in range(10):\n"
        "    with store.transaction('conc'):\n"
        "        b = receipt_body(f'c{i}', 'conc', 'file_exists', 'x', {}, {'i': i}, 'PASS', store.last_hash('conc'))\n"
        "        store.append(sign_receipt(b, priv))\n" % str(ROOT)
    )
    cenv = dict(os.environ, AGENTPROOF_HOME=str(conc_home))
    procs = [subprocess.Popen([PY, "-c", conc_code], env=cenv,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for _ in range(2)]
    rcs = [p.wait() for p in procs]
    conc_store = ChainStore(conc_home / "chains")
    conc_pub = (conc_home / "keys" / "agentproof_ed25519.pub").read_text(encoding="utf-8")
    conc_problems = verify_chain(conc_store.read_all("conc"), conc_pub) if all(
        rc == 0 for rc in rcs) else ["worker crashed"]
    check("two concurrent writers: 20 receipts, no chain fork",
          len(conc_store.read_all("conc")) == 20 and conc_problems == [])

    # --- thread stress: 4 threads x 10 claims in ONE process (fuzz F2) ---
    import threading as _th
    th_home = tmp / "th_home"
    th_store = ChainStore(th_home / "chains")
    th_kr = Keyring(th_home / "keys")
    th_priv = th_kr.load_or_create()
    th_pub = th_kr.public_key_pem()
    th_errors = []

    def _th_worker(tid):
        try:
            for i in range(10):
                with th_store.transaction("th"):
                    b = receipt_body(f"t{tid}-{i}", "th", "file_exists", "x", {},
                                     {"i": i}, "PASS", th_store.last_hash("th"))
                    th_store.append(sign_receipt(b, th_priv))
        except Exception as e:  # noqa: BLE001
            th_errors.append(f"{tid}: {e}")

    threads = [_th.Thread(target=_th_worker, args=(t,)) for t in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    th_receipts = th_store.read_all("th")
    check("4 threads x 10 claims: no errors", th_errors == [])
    check("4 threads x 10 claims: all 40 on disk", len(th_receipts) == 40)
    check("4 threads x 10 claims: chain intact (no fork)",
          verify_chain(th_receipts, th_pub) == [])

    # --- uppercase-hex sig rejected (fuzz #3) ---
    up = json.loads(json.dumps(rec))
    up["sig"] = "ed25519:" + up["sig"][len("ed25519:"):].upper()
    ok_up, why_up = verify_receipt(up, pub_pem)
    check("uppercase-hex sig rejected (canonical form enforced)",
          not ok_up and "lowercase" in why_up)

    # --- verify_chain hostile elements: never raises (fuzz #2) ---
    try:
        p1 = verify_chain([1, "junk", None], pub_pem)
        p2 = verify_chain([{"v": 1, "expect": float("nan"), "sig": "ed25519:" + "00"*64,
                            "prev_receipt_hash": GENESIS_HASH}], pub_pem)
        check("verify_chain survives non-dict + NaN receipts",
              len(p1) == 3 and len(p2) >= 1)
    except Exception as e:  # noqa: BLE001
        check(f"verify_chain survives non-dict + NaN receipts (raised {e!r})", False)

    # --- standalone verifier: invalid UTF-8 chain + BOM chain, no traceback (fuzz #1/#4) ---
    utf8_chain = tmp / "bad_utf8.jsonl"
    good_line = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
    utf8_chain.write_bytes(good_line + b"\n" + b'{"claim_id": "\xed\xa0\x80"}\n')
    cp13 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"),
         "--pubkey", str(tmp / "cli_home" / "keys" / "agentproof_ed25519.pub"),
         "--chain", str(utf8_chain)],
        capture_output=True, text=True, cwd=str(ROOT), encoding="utf-8", errors="replace")
    check("invalid-UTF8 chain: no traceback, malformed line reported",
          "Traceback" not in cp13.stderr and cp13.returncode == 1)
    bom_chain = tmp / "bom_chain.jsonl"
    bom_chain.write_bytes(b"\xef\xbb\xbf" + json.dumps(rec).encode("utf-8") + b"\n")
    cp14 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"),
         "--pubkey", str(tmp / "cli_home" / "keys" / "agentproof_ed25519.pub"),
         "--chain", str(bom_chain)],
        capture_output=True, text=True, cwd=str(ROOT))
    check("BOM-prefixed chain: first receipt still verifies (utf-8-sig)",
          cp14.returncode == 0 and "0 bad" in cp14.stdout)

    # --- cli verify/audit on a missing --pubkey: clean exit 2, no traceback ---
    cp15 = subprocess.run(
        [PY, "-m", "agentproof.cli", "verify", str(tmp / "receipt.json"),
         "--pubkey", str(tmp / "no-such-key.pub")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("cli verify missing pubkey: exit 2, no traceback",
          cp15.returncode == 2 and "Traceback" not in cp15.stderr)
    cp16 = subprocess.run(
        [PY, "-m", "agentproof.cli", "audit", "--agent", "cli-agent",
         "--pubkey", str(tmp / "no-such-key.pub")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("cli audit missing pubkey: exit 2, no traceback",
          cp16.returncode == 2 and "Traceback" not in cp16.stderr)

print()
n_pass = sum(1 for _, ok in results if ok)
print(f"RESULT: {n_pass}/{len(results)} passed")
sys.exit(0 if n_pass == len(results) else 1)
