# index-one

The verification layer for agent-to-agent communication that proves the chain of permission behind every action.

## What this is

When a human authorizes Agent A, which delegates to Agent B (a different
company), which delegates to Agent C, and money moves or an action is
taken — index-one produces a cryptographically tamper-evident record
proving *whose authority* flowed to that final action, and proves the
record wasn't altered along the way.

The core object is an **append-only capability token** that grows one
signed block per delegation hop:

- **Block 0** — the human root authority: scope, budget, depth limit, expiry.
- **Block N** — each agent's signed, scope-narrowing delegation block, with
  a mandatory `purpose` field.

Verification is **local, stateless, and per-request** — the proof travels
in the token itself, not in a central database. No blockchain.

We sit on top of existing payment/agent rails (Google AP2, Visa TAP,
Mastercard Agent Pay) and solve the multi-hop, cross-organization
attribution problem those rails leave unsolved.

> **Status: early-stage scaffold.** No cryptography is implemented yet —
> see [`/docs/REFERENCE.md`](docs/REFERENCE.md) for the design invariants,
> prior art, and papers this is built from.

## Repo layout

```
core/           Rust workspace -- the capability-token chain engine (built on Biscuit)
  chain/          append-only signed delegation blocks (sign/attenuate/verify)
  crypto/         signature-agility abstraction (Ed25519 now, ML-DSA/hybrid later)
  revocation/     short-TTL + transparency-log revocation

integrations/   Python -- rail integrations and the attack POC
  ap2/            adapters against the AP2 mandate format
  mcp/            MCP request-header signing/verification hooks
  attack/         runnable demo: a single-hop AP2 mandate can't attribute
                  authority across a 3-agent, cross-org delegation chain

sdk/            Thin public SDK (pip install indexone) -- wrap any agent, sign and verify

docs/           Design reference: papers, prior art, standards, invariants (see REFERENCE.md)

benchmarks/     Verification-latency and per-hop-size benchmarks
```

## Design invariants

- Proof lives in the token, not a central database. No blockchain.
- Scope only narrows down a chain, never widens.
- Time/expiry attenuates in one direction only.
- Revocation must survive partial-chain compromise (short-TTL + an
  out-of-chain transparency log).
- Signature algorithm is swappable per block (crypto-agility, PQ-ready).

Full detail, rationale, and the papers/prior art behind each of these:
[`/docs/REFERENCE.md`](docs/REFERENCE.md).

## Getting started

Nothing here is implemented yet beyond stub interfaces — there's no
working build to run against real behavior. To exercise the scaffold:

```bash
# Rust workspace
cd core && cargo test

# Python integrations (editable install + tests)
cd integrations && pip install -e ".[dev]" && pytest

# Python SDK
cd sdk/python && pip install -e ".[dev]" && pytest

# Cross-org attribution attack demo (runnable, no real crypto)
cd integrations && pip install -e . && python -m integrations.attack.poc_cross_org_chain
```

## Team

- **Rust crypto core** (`/core`) — Udaya
- **Python rail integrations + attack POC** (`/integrations`, `/sdk`) — Satyam

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

TODO: confirm MIT vs Apache-2.0 (placeholder in [`LICENSE`](LICENSE) is
Apache-2.0 pending that decision).
