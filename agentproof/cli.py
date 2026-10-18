"""
agentproof CLI — claim → probe → signed receipt.

Usage:
  agentproof claim file_exists --agent my-agent --target E:/reports/out.csv \
      --expect '{"min_bytes": 1024}'
  agentproof claim http_ok --agent my-agent --target https://example.com \
      --expect '{"status": 200, "body_contains": "Example"}'
  agentproof verify < receipt.json          # single receipt (offline)
  agentproof audit --agent my-agent         # full chain audit
  agentproof pubkey                          # print verifier public key (PEM)

Data/key layout (default under ./data, override with AGENTPROOF_HOME):
  data/keys/agentproof_ed25519.{pem,pub}
  data/chains/chain_<agent>.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from .core import (
    ChainStore, Keyring, receipt_body, sign_receipt,
    verify_chain, verify_receipt,
)
from .probes import PROBES


def home() -> Path:
    return Path(os.environ.get("AGENTPROOF_HOME", Path.cwd() / "data"))


def cmd_claim(args: argparse.Namespace) -> int:
    if args.kind not in PROBES:
        print(f"unknown claim kind: {args.kind} (have: {', '.join(PROBES)})",
              file=sys.stderr)
        return 2
    try:
        expect = json.loads(args.expect) if args.expect else {}
    except json.JSONDecodeError as e:
        print(f"--expect must be valid JSON: {e}", file=sys.stderr)
        return 2

    store = ChainStore(home() / "chains")
    keyring = Keyring(home() / "keys")
    priv = keyring.load_or_create()

    observed, verdict = PROBES[args.kind](args.target, expect)
    body = receipt_body(
        claim_id=str(uuid.uuid4()),
        agent_id=args.agent,
        kind=args.kind,
        target=args.target,
        expect=expect,
        observed=observed,
        verdict=verdict,
        prev_hash=store.last_hash(args.agent),
    )
    receipt = sign_receipt(body, priv)
    store.append(receipt)

    out = json.dumps(receipt, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    print(out)
    # exit code: 0 PASS, 1 FAIL/UNVERIFIABLE — scripts can branch on it
    return 0 if verdict == "PASS" else 1


def cmd_verify(args: argparse.Namespace) -> int:
    receipt = json.load(args.receipt)
    pub = Path(args.pubkey or (home() / "keys" / "agentproof_ed25519.pub")).read_text()
    ok, why = verify_receipt(receipt, pub)
    print(json.dumps({"signature_ok": ok, "detail": why,
                      "verdict": receipt.get("verdict"),
                      "claim_id": receipt.get("claim_id")}, indent=2))
    return 0 if ok else 1


def cmd_audit(args: argparse.Namespace) -> int:
    store = ChainStore(home() / "chains")
    receipts = store.read_all(args.agent)
    if not receipts:
        print(f"no receipts for agent {args.agent}")
        return 2
    pub = Path(args.pubkey or (home() / "keys" / "agentproof_ed25519.pub")).read_text()
    problems = verify_chain(receipts, pub)
    print(f"audited {len(receipts)} receipts for agent '{args.agent}'")
    if problems:
        print("CHAIN BROKEN / SIGNATURES INVALID:")
        for p in problems:
            print(" ", p)
        return 1
    print("chain intact, all signatures valid ✓")
    return 0


def cmd_pubkey(_: argparse.Namespace) -> int:
    keyring = Keyring(home() / "keys")
    keyring.load_or_create()
    print(keyring.public_key_pem())
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentproof")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("claim", help="run a probe and emit a signed receipt")
    c.add_argument("kind", choices=sorted(PROBES))
    c.add_argument("--agent", required=True)
    c.add_argument("--target", required=True)
    c.add_argument("--expect", default=None, help="JSON object of expectations")
    c.add_argument("--out", default=None, help="also write receipt to this file")
    c.set_defaults(fn=cmd_claim)

    v = sub.add_parser("verify", help="verify one receipt's signature (offline)")
    v.add_argument("receipt", type=argparse.FileType("r", encoding="utf-8"))
    v.add_argument("--pubkey", default=None)
    v.set_defaults(fn=cmd_verify)

    a = sub.add_parser("audit", help="verify a full agent chain")
    a.add_argument("--agent", required=True)
    a.add_argument("--pubkey", default=None)
    a.set_defaults(fn=cmd_audit)

    p = sub.add_parser("pubkey", help="print the verifier public key")
    p.set_defaults(fn=cmd_pubkey)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
