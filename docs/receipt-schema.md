# AgentProof Receipt Format — v1

A receipt is a JSON object proving that a deterministic check ran against a real
system at a specific time, signed by the verifier. This document is the normative
spec; `verify_receipt.py` in the repository root is the reference verifier.

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | int | yes | Schema version. Currently `1`. |
| `claim_id` | string (uuid4) | yes | Unique id of this claim. |
| `agent_id` | string | yes | Identity of the agent whose work is verified. Chains are per-agent. |
| `kind` | string | yes | Probe kind: `file_exists`, `http_ok`, `db_row_matches`, `exit_code`. |
| `target` | string | yes | What was probed: path, URL, DB target, or command line. |
| `expect` | object | yes | The claimer's expectations (may be `{}`). |
| `observed` | object | yes | What the probe actually measured. Structure depends on `kind`. |
| `verdict` | string | yes | `PASS` — evidence satisfies every expectation. `FAIL` — evidence contradicts at least one. `UNVERIFIABLE` — ground truth could not be reached (network error, unreadable file, spawn failure). |
| `checked_at` | string | yes | UTC timestamp, `%Y-%m-%dT%H:%M:%SZ`. |
| `prev_receipt_hash` | string | yes | SHA-256 of the canonical JSON of this agent's previous receipt, or 64 zeros (`0`×64) for the genesis receipt. |
| `sig` | string | yes | `ed25519:` + lowercase hex Ed25519 signature over the canonical JSON of all fields except `sig`. |

## Canonical JSON (what gets signed / hashed)

- `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded UTF-8.
- Applies to the receipt **without** the `sig` field when signing.
- Chain hash = SHA-256 hex digest of the canonical JSON of the **full stored receipt
  including `sig`**.

## Verification procedure

Single receipt:
1. Remove `sig`; recompute canonical JSON of the remainder.
2. Verify the Ed25519 signature against the verifier's public key.
3. Any failure ⇒ receipt invalid. (Verdicts are point-in-time evidence; verification
   does NOT re-run probes.)

Chain (audit):
1. Start with `prev = "0"*64`.
2. For each receipt in chain order: verify signature; assert
   `prev_receipt_hash == prev`; then `prev = sha256(canonical(receipt))`.
3. Any signature failure or chain break ⇒ tamper or gap detected; report the index.

## Verdict semantics

- A probe NEVER returns `PASS` when ground truth was unreachable. Missing optional
  dependencies (e.g. `requests`) and network/spawn errors yield `UNVERIFIABLE`.
- A missing target file is `FAIL` for `file_exists`/`db_row_matches` (the claimed
  record does not exist), not `UNVERIFIABLE`.
- `db_row_matches` accepts read-only queries only (`SELECT`/`WITH` for sqlite);
  anything else is rejected before execution.
- `exit_code` runs the command with a hard timeout (default 30 s), no stdin, and
  output caps. Timeout ⇒ `FAIL` (`observed.timed_out: true`).

## Threat model (what receipts do and don't prove)

Proves: a check with these expectations ran at this time against this target, the
observed values were as recorded, and the receipt was not altered or reordered
afterwards (given the verifier's key is trusted and its chain is complete).

Does NOT prove: the claimer's *interpretation* was correct, that nothing else
happened between probe and read, or anything about systems outside the probe's
reach. The verifier's signing key is the root of trust — protect it (file is stored
0600; it never leaves the machine).

## Versioning

Additive fields within v1 are permitted (verifiers MUST ignore unknown fields).
Breaking changes increment `v`. Verifiers SHOULD reject `v` they don't understand.
