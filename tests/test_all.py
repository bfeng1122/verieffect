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

PY = str(ROOT / ".venv" / "Scripts" / "python.exe")
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
    chain_file = tmp / "chains" / "chain_agent-a.jsonl"
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
    obs, v = probe_exit_code(f'"{PY}" -c "print(2+2)"',
                             {"exit_code": 0, "stdout_contains": "4"})
    check("command exit 0 + stdout -> PASS", v == PASS)
    check("exit_code observed in receipt", obs.get("exit_code") == 0)
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', {"exit_code": 3})
    check("nonzero exit matches expected -> PASS", v == PASS)
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', {})
    check("nonzero exit vs default 0 -> FAIL", v == FAIL)
    obs, v = probe_exit_code(f'"{PY}" -c "import time; time.sleep(30)"',
                             {"timeout_s": 2})
    check("timeout -> FAIL with timed_out flag", v == FAIL and obs.get("timed_out") is True)
    obs, v = probe_exit_code(f'"{PY}" -c "print(\'x\')"',
                             {"stdout_sha256": "0" * 64})
    check("wrong stdout_sha256 -> FAIL", v == FAIL)

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

print()
n_pass = sum(1 for _, ok in results if ok)
print(f"RESULT: {n_pass}/{len(results)} passed")
sys.exit(0 if n_pass == len(results) else 1)
