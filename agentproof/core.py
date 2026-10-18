"""
agentproof — deterministic claim verification with signed, hash-chained receipts.

Core invariant: NO LLM in the verdict path. Verdicts come only from probes that
read systems of record (filesystem, HTTP, DB, process state). The claimer never
self-reports success — agentproof owns the check.

Receipt integrity:
- Ed25519 keypair, private key stored locally (0600), never leaves the machine.
- Per-agent hash chain: each receipt embeds sha256 of the previous receipt for
  that agent_id, so tampering/deletion is detectable offline.
- Canonical JSON (sorted keys, UTF-8, no extra whitespace) is what gets signed.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------- canonical json

def canonical_json(obj: Any) -> bytes:
    """Stable serialization: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- key management

class Keyring:
    """Ed25519 identity for the agentproof verifier itself."""

    def __init__(self, key_dir: Path):
        self.key_dir = Path(key_dir)
        self.priv_path = self.key_dir / "agentproof_ed25519.pem"
        self.pub_path = self.key_dir / "agentproof_ed25519.pub"

    def load_or_create(self) -> Ed25519PrivateKey:
        if self.priv_path.exists():
            key = serialization.load_pem_private_key(
                self.priv_path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise TypeError("existing key is not Ed25519")
            return key
        key = Ed25519PrivateKey.generate()
        self.key_dir.mkdir(parents=True, exist_ok=True)
        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # best-effort 0600 (Windows ACLs are coarser; POSIX honored directly)
        self.priv_path.write_bytes(priv_pem)
        try:
            os.chmod(self.priv_path, 0o600)
        except OSError:
            pass
        self.pub_path.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return key

    def public_key_pem(self) -> str:
        return self.pub_path.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------- claim store

class ChainStore:
    """SQLite-free JSONL chain store (one file per agent_id).

    Kept deliberately dumb: append-only JSONL + per-agent last-hash tracking.
    Migrating to SQLite is trivial later; JSONL is inspectable by humans, which
    is the point of an audit product.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, agent_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in agent_id)
        return self.data_dir / f"chain_{safe}.jsonl"

    def last_hash(self, agent_id: str) -> str:
        p = self._path(agent_id)
        if not p.exists():
            return GENESIS_HASH
        last = None
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return GENESIS_HASH
        return sha256_hex(canonical_json(json.loads(last)))

    def append(self, receipt: dict) -> None:
        p = self._path(receipt["agent_id"])
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(receipt, sort_keys=True, ensure_ascii=False) + "\n")

    def read_all(self, agent_id: str) -> list[dict]:
        p = self._path(agent_id)
        if not p.exists():
            return []
        out = []
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out


# ---------------------------------------------------------------- receipts

def receipt_body(claim_id: str, agent_id: str, kind: str, target: Any,
                 expect: Any, observed: Any, verdict: str,
                 prev_hash: str) -> dict:
    """The signed payload — everything except `sig`."""
    return {
        "v": SCHEMA_VERSION,
        "claim_id": claim_id,
        "agent_id": agent_id,
        "kind": kind,
        "target": target,
        "expect": expect,
        "observed": observed,
        "verdict": verdict,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "prev_receipt_hash": prev_hash,
    }


def sign_receipt(body: dict, priv: Ed25519PrivateKey) -> dict:
    sig = priv.sign(canonical_json(body))
    receipt = dict(body)
    receipt["sig"] = "ed25519:" + sig.hex()
    return receipt


def verify_receipt(receipt: dict, pub_pem: str | bytes) -> tuple[bool, str]:
    """Offline verification: signature + chain-hash field presence.

    Returns (ok, reason). Does NOT re-run probes (receipts are point-in-time
    evidence); chain-integrity across a file is checked by verify_chain().
    """
    if not isinstance(receipt, dict) or "sig" not in receipt:
        return False, "missing signature"
    sig_field = receipt.pop("sig") if isinstance(receipt, dict) else None
    try:
        if not sig_field.startswith("ed25519:"):
            return False, "unsupported signature scheme"
        sig = bytes.fromhex(sig_field[len("ed25519:"):])
    except ValueError:
        return False, "malformed signature encoding"
    try:
        pub = serialization.load_pem_public_key(
            pub_pem.encode() if isinstance(pub_pem, str) else pub_pem)
        if not isinstance(pub, Ed25519PublicKey):
            return False, "public key is not Ed25519"
        pub.verify(sig, canonical_json(receipt))
    except InvalidSignature:
        return False, "INVALID SIGNATURE"
    except Exception as e:  # noqa: BLE001
        return False, f"verification error: {e}"
    finally:
        receipt["sig"] = sig_field  # restore — never mutate caller's receipt
    return True, "signature valid"


def verify_chain(receipts: list[dict], pub_pem: str | bytes) -> list[str]:
    """Full audit: every signature valid AND hash chain unbroken from genesis."""
    problems = []
    prev = GENESIS_HASH
    for i, r in enumerate(receipts):
        ok, why = verify_receipt(r, pub_pem)
        if not ok:
            problems.append(f"[{i}] {r.get('claim_id','?')}: {why}")
        if r.get("prev_receipt_hash") != prev:
            problems.append(
                f"[{i}] {r.get('claim_id','?')}: chain break — expected prev "
                f"{prev[:12]}…, got {str(r.get('prev_receipt_hash'))[:12]}…")
        prev = sha256_hex(canonical_json(r))
    return problems
