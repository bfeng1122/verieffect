#!/usr/bin/env python3
"""Standalone offline verifier — no agentproof install needed.

This file is what we publish with the receipt JSON schema: anyone (operator,
auditor, a different machine) can validate a receipt or a whole chain file
using only `cryptography`. Deliberately zero internal imports.

Usage:
  python verify_receipt.py --pubkey agentproof_ed25519.pub receipt.json
  python verify_receipt.py --pubkey agentproof_ed25519.pub --chain chain_myagent.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def verify_one(receipt: dict, pub) -> tuple[bool, str]:
    sig_field = receipt.get("sig")
    if not sig_field or not str(sig_field).startswith("ed25519:"):
        return False, "missing/unsupported signature"
    body = {k: v for k, v in receipt.items() if k != "sig"}
    try:
        pub.verify(bytes.fromhex(sig_field[len("ed25519:"):]), canonical_json(body))
    except InvalidSignature:
        return False, "INVALID SIGNATURE"
    return True, "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("file", help="receipt .json or chain .jsonl (with --chain)")
    ap.add_argument("--chain", action="store_true")
    args = ap.parse_args()

    pub = serialization.load_pem_public_key(
        open(args.pubkey, "rb").read())

    if not args.chain:
        receipt = json.load(open(args.file, encoding="utf-8"))
        ok, why = verify_one(receipt, pub)
        print(f"{'VALID' if ok else 'INVALID'}: {why} "
              f"(claim {receipt.get('claim_id')}, verdict {receipt.get('verdict')})")
        return 0 if ok else 1

    prev = "0" * 64
    n = 0
    bad = 0
    with open(args.file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            n += 1
            ok, why = verify_one(r, pub)
            chain_ok = r.get("prev_receipt_hash") == prev
            if not ok or not chain_ok:
                bad += 1
                print(f"  [{n}] {r.get('claim_id')}: sig={why} chain_ok={chain_ok}")
            prev = sha256_hex(canonical_json(r))
    print(f"chain audit: {n} receipts, {bad} bad")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
