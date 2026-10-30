# Show HN draft — AgentProof

**Title:**
Show HN: AgentProof – Signed, tamper-evident receipts for AI agent work claims

**Body:**

I run a 24/7 AI trading pipeline (paper trading, multi-agent: scout, analyst, risk gate, executor, bookkeeper). An analysis of the public τ-bench retail benchmark (Veridatum) found that ~26% of simulated agent tasks disagreed with the database on final state — the log says "done," the side effect never happened. Peer-reviewed work agrees: in OverclaimBench, ~80% of incomplete runs are misleadingly reported. I didn't want to take that risk with my own pipeline, so I built AgentProof:

https://github.com/bfeng1122/agentproof

The idea is simple: when an agent claims "the trade filled" / "the backup ran" / "the report was written," a deterministic probe checks ground truth *itself* — filesystem state, HTTP responses, database rows, exit codes — and issues a receipt signed with Ed25519 and hash-chained per agent. No LLM in the verdict path, ever.

Design choices worth arguing about:

- **Three verdicts, not two.** PASS / FAIL / UNVERIFIABLE. A network error is never laundered into a pass, and a missing file is never excused as "couldn't check."
- **Hash chain per agent, with honest limits.** Receipts can't be silently edited or reordered, chains are bound to an agent_id, and the audit tool supports externally anchored head hashes (--expect-head/--expect-count) to catch tail truncation. The threat model doc states plainly what the chain does NOT protect against (key co-location, key-holder regeneration) — it catches sloppy agents, not adversarial ones.
- **Dangerous probes are gated.** The exit_code probe runs with verifier privileges, so it's OFF by default (explicit allow_shell opt-in); http_ok refuses non-GET/HEAD methods by default.
- **Exit codes as the integration surface.** 0/1/2, so cron jobs and shell scripts branch on verification directly.

On day one of dogfooding it caught my own agent filing a claim about a backup path that didn't exist. It's now been running against my pipeline for two weeks: 38 receipts across fills and backup checks, and a deliberate tamper test that breaks the chain exactly as designed. (Amusingly, before launch I had three AI agents red-team the repo — the security one reproduced a chain-relabeling attack and tail-truncation gap that are now fixed and tested. The tool's whole thesis, applied to itself.)

MIT licensed. ~1,300 lines of Python, deps only `cryptography` + `requests`. 58 tests. I'm looking for harsh feedback on the receipt schema (docs/receipt-schema.md) and claim kinds people actually need.

---

# Timing / logistics notes (delete before posting)

- HN: post Tue–Thu, 6–9 AM Pacific. Reply to every comment in the first 2 hours.
- r/LocalLLaMA and r/ClaudeAI: stagger 2–3 days AFTER HN so they don't compete; Reddit rewards the "saw this on HN, here's the deep dive" angle.
- Have the dogfood/ example + receipt-schema.json landed before posting (polish pass).
