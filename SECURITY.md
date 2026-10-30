# Security Policy

## Scope and posture

AgentProof is a verification tool, so its own security posture matters. Read the
[threat model](docs/receipt-schema.md#threat-model-what-receipts-do-and-dont-prove)
first: AgentProof is a **drift detector, not an attestation system**. The signing
key is co-located with the agents it audits (MVP design); an adversary with local
code execution as the same OS user can forge receipts. This is documented, not
discovered — reports restating it will be closed as by-design.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (main) | Yes — security fixes |
| < 0.1 | No |

## Reporting a vulnerability

**Do not open a public issue for security bugs.** Use
[GitHub Security Advisories](https://github.com/bfeng1122/agentproof/security/advisories/new)
(private draft advisory) on this repository.

Include: reproduction steps, affected probe/verifier, whether the issue allows
forgery, silent PASS, or DoS of the verifier.

Expected response: acknowledgment within ~72h (solo maintainer, best effort);
fix or documented mitigation targeted within 2 weeks for confirmed
forge/silent-PASS issues.

## What counts as a vulnerability here

In scope:
- Signature bypass or forgery without key access
- A FAIL/UNVERIFIABLE condition reported as PASS
- Chain tampering (edit/reorder/relabel) not detected by the documented audit
- Verifier crashes on hostile input (tracebacks, unbounded memory)
- Read-only probe performing a write

Out of scope (documented limitations):
- Attacks requiring the signing key (same-user local code execution)
- Tail truncation / chain regeneration without external head anchoring
  (mitigation is documented: `checkpoint` + `--expect-head`)
- `exit_code` probe behavior when the operator passes `allow_shell: true`
  to an untrusted claimer — that is an operator trust-boundary decision
