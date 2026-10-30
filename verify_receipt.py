#!/usr/bin/env python3
"""Standalone offline verifier — needs only `cryptography`, no agentproof install.

This file is what we publish with the receipt JSON schema: anyone (operator,
auditor, a different machine) can validate a receipt or a whole chain file
using only `cryptography`. Deliberately zero internal imports. It prints
INVALID/malformed rather than ever raising on untrusted input.

Usage:
  python verify_receipt.py --pubkey agentproof_ed25519.pub receipt.json
  python verify_receipt.py --pubkey agentproof_ed25519.pub --chain chain_myagent.jsonl
      [--agent myagent] [--expect-count N] [--expect-head HASH]

Chain mode walks FORWARD from genesis, so it detects edited receipts and
mid-chain deletions. It CANNOT detect tail truncation or regeneration by the
key holder — pass --expect-count / --expect-head (an externally anchored head
hash + count) to catch those. See docs/receipt-schema.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

# Windows consoles may default to cp1252; our output uses ✓/… — force UTF-8
# so prints never crash with UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


SCHEMA_VERSION = 1
GENESIS = "0" * 64


def verify_one(receipt, pub) -> tuple[bool, str]:
    """Never raises — returns (ok, reason) even on hostile/malformed input."""
    if not isinstance(receipt, dict):
        return False, "not a JSON object"
    if receipt.get("v") != SCHEMA_VERSION:
        return False, f"unsupported schema version {receipt.get('v')!r}"
    sig_field = receipt.get("sig")
    if not isinstance(sig_field, str) or not sig_field.startswith("ed25519:"):
        return False, "missing/unsupported signature"
    hex_part = sig_field[len("ed25519:"):]
    if hex_part != hex_part.lower():
        # spec mandates lowercase hex; rejecting uppercase keeps the canonical
        # form (and thus chain-head hashes) unambiguous
        return False, "signature hex must be lowercase (canonical form)"
    body = {k: v for k, v in receipt.items() if k != "sig"}
    try:
        sig = bytes.fromhex(hex_part)
    except ValueError:
        return False, "malformed signature encoding"
    try:
        canon = canonical_json(body)
    except (ValueError, TypeError) as e:
        return False, f"non-canonicalizable body: {e}"
    try:
        pub.verify(sig, canon)
    except InvalidSignature:
        return False, "INVALID SIGNATURE"
    except Exception as e:  # noqa: BLE001 — any crypto error is just "invalid"
        return False, f"verification error: {e}"
    return True, "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("file", help="receipt .json or chain .jsonl (with --chain)")
    ap.add_argument("--chain", action="store_true")
    ap.add_argument("--agent", default=None,
                    help="expected agent_id for every receipt in the chain")
    ap.add_argument("--expect-count", type=int, default=None,
                    help="externally anchored receipt count — detects tail truncation")
    ap.add_argument("--expect-head", default=None,
                    help="externally anchored sha256 of the last receipt — "
                         "detects truncation/regeneration")
    args = ap.parse_args()

    try:
        pub = serialization.load_pem_public_key(open(args.pubkey, "rb").read())
    except Exception as e:  # noqa: BLE001
        print(f"INVALID: cannot load public key: {e}")
        return 1

    if not args.chain:
        try:
            with open(args.file, encoding="utf-8-sig", errors="replace") as rf:
                receipt = json.load(rf)
        except Exception as e:  # noqa: BLE001
            print(f"INVALID: cannot parse receipt file: {e}")
            return 1
        ok, why = verify_one(receipt, pub)
        cid = receipt.get("claim_id") if isinstance(receipt, dict) else "?"
        vd = receipt.get("verdict") if isinstance(receipt, dict) else "?"
        print(f"{'VALID' if ok else 'INVALID'}: {why} (claim {cid}, verdict {vd})")
        return 0 if ok else 1

    prev = GENESIS
    n = 0
    bad = 0
    last = None
    prev_checked_at = None
    try:
        # utf-8-sig strips a Windows-editor BOM; errors="replace" keeps the
        # walk alive on invalid bytes (the replaced line then fails JSON
        # parsing and is reported as malformed — never a traceback)
        fh = open(args.file, encoding="utf-8-sig", errors="replace")
    except OSError as e:
        print(f"INVALID: cannot open chain file: {e}")
        return 1
    with fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                r = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                n += 1
                bad += 1
                print(f"  [{n}] malformed JSON line: {e}")
                continue
            n += 1
            ok, why = verify_one(r, pub)
            chain_ok = isinstance(r, dict) and r.get("prev_receipt_hash") == prev
            agent_ok = (args.agent is None
                        or (isinstance(r, dict) and r.get("agent_id") == args.agent))
            ts_ok = True
            if isinstance(r, dict):
                ts = r.get("checked_at")
                if isinstance(ts, str):
                    if prev_checked_at is not None and ts < prev_checked_at:
                        ts_ok = False
                    prev_checked_at = ts
            if not ok or not chain_ok or not agent_ok or not ts_ok:
                bad += 1
                note = f"sig={why} chain_ok={chain_ok}"
                if args.agent is not None:
                    note += f" agent_ok={agent_ok}"
                if not ts_ok:
                    note += " ts_regression=True"
                cid = r.get("claim_id") if isinstance(r, dict) else "?"
                print(f"  [{n}] {cid}: {note}")
            if isinstance(r, dict):
                try:
                    prev = sha256_hex(canonical_json(r))
                except (ValueError, TypeError):
                    # non-canonicalizable line (e.g. NaN): fall back to default
                    # json semantics so the walk continues and the bad receipt
                    # is still flagged by verify_one
                    prev = sha256_hex(json.dumps(r, sort_keys=True,
                                                 ensure_ascii=False).encode("utf-8"))
                last = r

    head = GENESIS if last is None else prev
    if args.expect_count is not None and n != args.expect_count:
        bad += 1
        print(f"  count mismatch: expected {args.expect_count}, found {n} "
              "(possible tail truncation)")
    if args.expect_head and head != args.expect_head.strip().lower():
        bad += 1
        print(f"  head mismatch: expected {args.expect_head.strip()[:16]}…, got "
              f"{head[:16]}… (possible truncation/regeneration)")
    print(f"chain head: {head}")
    print(f"chain audit: {n} receipts, {bad} bad")
    if bad == 0 and args.expect_count is None and not args.expect_head:
        print("note: forward-walk intact. Tail truncation/regeneration is only "
              "detectable with --expect-count/--expect-head (anchor the head "
              "externally).")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
