# Changelog

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
  with `agentproof` console script
- 91-test suite; CI on ubuntu+windows × Python 3.10–3.12
- Docs: honest threat model, receipt schema spec, examples for all probes,
  CONTRIBUTING, SECURITY policy

### Known limitations (documented, by design)
- Signing key is co-located with agents (drift detector, not attestation)
- No key rotation (`kid`) yet; no `claimed_at`/`checked_at` split yet
- Tail truncation detectable only with external head anchoring
