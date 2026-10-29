# AgentProof

**Agents claim. AgentProof checks.**

Deterministic verification for AI agent work, with signed, tamper-evident receipts.
When an agent says "I uploaded the file" / "the trade filled" / "the backup ran" —
AgentProof probes ground truth *itself* and issues a receipt anyone can verify offline.

- **No LLM in the verdict path.** Verdicts come from deterministic probes: filesystem
  state, HTTP responses, database rows, command exit codes. A model never *opines*
  that work succeeded; evidence shows it.
- **Signed receipts.** Ed25519 signature + per-agent hash chain, so receipts can't be
  forged, edited, or silently deleted after the fact.
- **Three verdicts, never two.** `PASS` / `FAIL` / `UNVERIFIABLE` — a network error is
  never laundered into a pass, and a missing file is never excused as "couldn't check."

## Why

Independent analysis found **26% of simulated agent tasks falsely reported success**
(Veridatum, 456 GPT-4.1 retail simulations vs. final database state). Autonomous agent
stacks — cron-driven pipelines, CI bots, personal agents — fail the same way: the log
says "done," the side effect never happened. AgentProof makes "done" a verifiable claim.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/python -m pip install cryptography requests   # Linux/macOS: .venv/bin/python
.venv/Scripts/python -m agentproof.cli claim file_exists --agent my-agent \
  --target ./report.csv --expect '{"min_bytes": 1024}'
```

Output (truncated):

```json
{
  "v": 1,
  "claim_id": "…",
  "agent_id": "my-agent",
  "kind": "file_exists",
  "target": "./report.csv",
  "expect": {"min_bytes": 1024},
  "observed": {"exists": true, "size": 4096, "mtime": 1792090847},
  "verdict": "PASS",
  "checked_at": "2026-10-20T23:12:06Z",
  "prev_receipt_hash": "…",
  "sig": "ed25519:…"
}
```

Exit codes: `0` = PASS, `1` = FAIL/UNVERIFIABLE, `2` = usage error — so shell scripts
and cron jobs can branch on verification results directly.

## Claim kinds

| Kind | Target | Proves |
|---|---|---|
| `file_exists` | path | file present; size bounds / sha256 / mtime freshness / text content |
| `http_ok` | URL | endpoint answers; status / body substring / body hash (probe makes the request itself) |
| `db_row_matches` | `sqlite:///x.db`, `x.jsonl`, `x.json` | record state: SELECT-only queries, JSONL row filters, dotted-path JSON fields |
| `exit_code` | shell command | command re-run in a bounded sandbox; exit code / stdout content |

## Offline verification

Receipts are verifiable by anyone with the public key — no AgentProof install needed:

```bash
python verify_receipt.py --pubkey agentproof_ed25519.pub receipt.json
python verify_receipt.py --pubkey agentproof_ed25519.pub --chain chain_my-agent.jsonl
```

The standalone verifier (`verify_receipt.py`) has **zero internal imports** by design —
it is the reference implementation of the receipt format. See
[`docs/receipt-schema.md`](docs/receipt-schema.md) for the full spec.

## Design rules

1. The probe is owned by the verifier, never the claimer. Self-reported results are
   what we're checking, not what we trust.
2. Anything not provable deterministically is `UNVERIFIABLE`, not `PASS`.
3. `db_row_matches` is read-only (non-SELECT rejected); the verifier never mutates
   the systems it audits.
4. The hash chain is the audit trail — append-only, and chain breaks are detected by
   any offline auditor.

## Status

MVP. 50-test suite (`tests/test_all.py`), in daily production use verifying a 24/7
paper-trading agent stack (fills, portfolio state, backups) since Oct 2026.
Roadmap: hosted verifier API, connector library (Stripe/broker/Postgres), MCP server.

MIT licensed.
