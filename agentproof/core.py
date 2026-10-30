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
    """Stable serialization: sorted keys, compact separators, UTF-8.

    Rejects non-finite floats (NaN/Infinity) — they are invalid JSON per
    RFC 8259 and would poison cross-language verification.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


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
        # Best-effort permission tightening. POSIX: chmod 0600 (real).
        # Windows: os.chmod only toggles the read-only bit — it does NOT
        # restrict other local users. For real isolation on Windows, run the
        # verifier as a separate OS user or use an encrypted key (roadmap).
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
        # suffix a short hash of the RAW id so ids that sanitize identically
        # ("a b" vs "a_b") never share a chain file
        tag = sha256_hex(agent_id.encode("utf-8"))[:8]
        new = self.data_dir / f"chain_{safe}_{tag}.jsonl"
        if not new.exists():
            # legacy pre-hash filenames keep resolving (read/append compatibility)
            # — but only if the legacy chain actually belongs to THIS agent_id
            # (otherwise "a b" would inherit "a_b"'s legacy file)
            legacy = self.data_dir / f"chain_{safe}.jsonl"
            if legacy.exists() and self._legacy_belongs_to(legacy, agent_id):
                return legacy
        return new

    @staticmethod
    def _legacy_belongs_to(path: Path, agent_id: str) -> bool:
        try:
            with path.open("r", encoding="utf-8") as f:
                first = f.readline().strip()
            return bool(first) and json.loads(first).get("agent_id") == agent_id
        except (OSError, json.JSONDecodeError, ValueError):
            return False

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
        try:
            return sha256_hex(canonical_json(json.loads(last)))
        except (json.JSONDecodeError, ValueError) as e:
            raise RuntimeError(
                f"last line of {p.name} is corrupt ({e}) — repair or remove it "
                "before issuing new claims for this agent") from e

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
    if receipt.get("v") != SCHEMA_VERSION:
        return False, f"unsupported schema version {receipt.get('v')!r}"
    sig_field = receipt.pop("sig")
    try:
        if not isinstance(sig_field, str) or not sig_field.startswith("ed25519:"):
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


def verify_chain(receipts: list[dict], pub_pem: str | bytes,
                 expected_agent_id: str | None = None) -> list[str]:
    """Full audit: every signature valid, hash chain unbroken from genesis,
    and (when expected_agent_id is given) every receipt belongs to that agent.

    NOTE: verify_chain walks FORWARD from genesis, so it detects edits and
    mid-chain deletions but NOT tail truncation (removing the newest receipts)
    or wholesale regeneration by the key holder. To detect those, anchor the
    chain head externally (e.g. publish sha256 of the last receipt + count) and
    compare on audit. See docs/receipt-schema.md, Threat Model.
    """
    problems = []
    prev = GENESIS_HASH
    for i, r in enumerate(receipts):
        ok, why = verify_receipt(r, pub_pem)
        if not ok:
            problems.append(f"[{i}] {r.get('claim_id','?')}: {why}")
        if expected_agent_id is not None and r.get("agent_id") != expected_agent_id:
            problems.append(
                f"[{i}] {r.get('claim_id','?')}: agent mismatch — chain is for "
                f"{expected_agent_id!r}, receipt claims {r.get('agent_id')!r}")
        if r.get("prev_receipt_hash") != prev:
            problems.append(
                f"[{i}] {r.get('claim_id','?')}: chain break — expected prev "
                f"{prev[:12]}…, got {str(r.get('prev_receipt_hash'))[:12]}…")
        prev = sha256_hex(canonical_json(r))
    return problems
