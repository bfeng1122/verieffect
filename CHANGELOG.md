# Changelog

## v0.1.0-alpha — 2026-10-31

First tagged release, under the new name.

### Renamed from AgentProof
"AgentProof" collided with 5+ existing products, including `agent-proof.dev`
(deterministic side-effect verification for agents — same thesis, same name).
**Verieffect** was verified free on PyPI, GitHub and npm, with all domains
available and no product or research collisions.

Signing key and receipt format are unchanged, so receipts issued before the rename
still verify. The repo keeps its full history; GitHub redirects the old URL.

## v0.1.0 — 2026-10-31

First tagged release. MVP of the receipt protocol and tooling.

### What's in
- Four deterministic probes: `file_exists`, `http_ok`, `db_row_matches`
  (sqlite/JSONL/JSON), `exit_code` — no LLM in the verdict path, ever
- Three-verdict contract: PASS / FAIL / UNVERIFIABLE
- Ed25519-signed receipts, per-agent hash chains (JSONL, append-only)
- Standalone offline verifier (`verify_receipt.py`, zero internal imports)
  with strict schema validation and three-level validity reporting
  (signature / schema / chain)
- `checkpoint` subcommand + `audit --expect-head/--expect-count` for
  externally anchored tail-truncation detection
- Concurrency-safe chain appends (file locking, thread-aware, never
  proceeds unlocked silently)
- Safety gates: `exit_code` off by default (`allow_shell`), `http_ok`
  GET/HEAD-only by default, streaming output/body caps, sqlite read-only
  (SELECT-only + `query_only`), timestamp-regression and agent-binding
  checks in audits
- CLI exit codes 0/1/2 for cron/CI branching; `pyproject.toml` packaging
  with `verieffect` console script
- 91-test suite; CI on ubuntu+windows × Python 3.10–3.12
- Docs: honest threat model, receipt schema spec, examples for all probes,
  CONTRIBUTING, SECURITY policy

### Known limitations (documented, by design)
- Signing key is co-located with agents (drift detector, not attestation)
- No key rotation (`kid`) yet; no `claimed_at`/`checked_at` split yet
- Tail truncation detectable only with external head anchoring
