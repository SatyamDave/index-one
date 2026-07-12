# IndexOne

> **IndexOne** (one word, camel case) is the canonical product name. `indexone-*`
> (Rust crates) and `indexone` (Python package) are the code identifiers; the
> repo directory is `index-one`.

The tamper-evident **chain-of-authority** layer for multi-agent actions — the
verification layer for agent-to-agent communication that proves the chain of
permission behind every action. When an action crosses companies and something
goes wrong, IndexOne is the cryptographic proof of *who authorized what*.

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

> **Status: foundation in place.** The Rust core now has real crypto and a
> working verifier: Ed25519 signing, a cryptographically-bound delegation
> chain, a Merkle transparency witness, independent completion attestation,
> and the composed `verify()` that ties them together and fails closed. The
> Day-12 kill test (see [`CLAUDE.md`](CLAUDE.md) §9) is mechanized as tests
> in the `verifier` crate. Still stubbed: `revocation`, and the Python SDK /
> rail integrations. See [`/docs/REFERENCE.md`](docs/REFERENCE.md) for the
> design invariants, prior art, and papers this is built from.

## Repo layout

```
core/           Rust workspace. Grouped by CLAUDE.md §6 (substrate vs. our layer):

  -- SUBSTRATE (integrate/extend, don't reinvent) --
  crypto/         signature agility: real Ed25519 now, ML-DSA/hybrid later
  chain/          append-only signed delegation blocks; cross-org attribution
                  (issue / attenuate / verify, all cryptographically bound)
  revocation/     short-TTL + transparency-log revocation (still stubbed)

  -- OUR LAYER (what the competing drafts punt -- the company) --
  witness/        cross-org Merkle transparency log; makes OMISSION detectable
  attestation/    independent completion attestation (not self-reported)
  verifier/       the composed verify(): chain + witness + attestation,
                  fail-closed. Day-12 kill test lives in its tests.

integrations/   Python -- rail integrations and the attack POC
  ap2/            adapters against the AP2 mandate format
  mcp/            MCP request-header signing/verification hooks
  attack/         runnable demo: a single-hop AP2 mandate can't attribute
                  authority across a 3-agent, cross-org delegation chain

sdk/            Thin public SDK (pip install indexone) -- wrap any agent, sign and verify

docs/           Design reference: papers, prior art, standards, invariants (see REFERENCE.md)

benchmarks/     Verification-latency and per-hop-size benchmarks (real verify())
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

The Rust core builds, verifies real chains, and passes its tests —
including the Day-12 kill test. The Python SDK / integrations are still
thin stubs (except the runnable attack POC).

```bash
# Rust workspace: build, lint, and run the tests (incl. the Day-12 kill test)
cargo test  --manifest-path core/Cargo.toml --workspace
cargo clippy --manifest-path core/Cargo.toml --workspace --all-targets -- -D warnings

# See just the verifier's omission / self-report / equivocation cases
cargo test  --manifest-path core/Cargo.toml -p indexone-verifier

# Cross-org attribution attack demo (runnable; illustrative, not real crypto)
cd integrations && pip install -e . && python -m integrations.attack.poc_cross_org_chain

# Python integrations / SDK (editable install + tests)
cd integrations && pip install -e ".[dev]" && pytest
cd sdk/python   && pip install -e ".[dev]" && pytest
```

## Team

- **Rust crypto core** (`/core`) — Udaya
- **Python rail integrations + attack POC** (`/integrations`, `/sdk`) — Satyam

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

TODO: confirm MIT vs Apache-2.0 (placeholder in [`LICENSE`](LICENSE) is
Apache-2.0 pending that decision).
