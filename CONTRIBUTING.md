# Contributing

index-one is a two-person early-stage project. This document is how we split
the work and the ground rules for the repo — not a public contribution process
(yet). It should stay in sync with the plan in [`ROADMAP.md`](ROADMAP.md), the
guardrails in [`CLAUDE.md`](CLAUDE.md), and the architecture in
[`docs/REFERENCE.md`](docs/REFERENCE.md).

The company reduces to one thing (CLAUDE.md §12): **the witness/anchor crypto
has to be genuinely built, not wrapped.** The split below keeps that on the
load-bearing side and everything that makes it reachable on the other.

## Ownership split

- **Rust crypto core + offensive security (`/core`, `/exploits`) — Udaya.**
  The `crypto`, `chain`, `witness`, `attestation`, `verifier`, and
  `revocation` crates: the actual signing, attenuation, Merkle/inclusion,
  attestation binding, and the composed `verify()`. Plus the attack harness and
  the claim-to-attack matrix. This is where cryptographic correctness matters
  most and where review is strictest.
- **Agent-systems integration + SDK (`/integrations`, `/sdk`) — Satyam.** AP2,
  MCP, A2A/x402 adapters, Web Bot Auth transport, wrapping Biscuit/AIP on the
  runtime path, and the public SDK surface. This code *calls into* `/core`; it
  must not reimplement crypto or chain logic itself.

`/benchmarks`, `/docs`, and the cross-draft `/conformance` suite are shared —
either of us updates them as the relevant crate/package changes.

## Work breakdown — who owns what, and where it stands

Status: ✅ done · 🔨 in progress / next · ⬜ not started. Roadmap column points
at the [`ROADMAP.md`](ROADMAP.md) / [`CLAUDE.md`](CLAUDE.md) §10 day range.

### Udaya — crypto core (the load-bearing half)

| Workstream | Crate / area | Status | Roadmap |
|---|---|---|---|
| Real Ed25519 sign/verify behind the `Signer` trait + dispatcher | `crypto` | ✅ | Days 3–10 |
| Algorithm agility: `MlDsa87` + `Hybrid` (classical+PQ, both must verify) | `crypto` | ⬜ | post-MVP differentiator |
| Cryptographically-bound delegation chain (embedded keys, hash links) | `chain` | ✅ | Days 3–10 |
| Attenuation invariants (scope⊆, expiry↓, depth↓, purpose) + typed errors | `chain` | ✅ | Days 3–10 |
| Structured / datalog scope type (replace opaque permission strings) | `chain` | ⬜ | post-MVP |
| Merkle transparency log: append / root / inclusion proof + verify | `witness` | ✅ | Days 11–16 |
| **Consistency proofs + gossip (non-equivocation / forked-view detection)** | `witness` | 🔨 | Days 11–16 |
| Pluggable root anchor → the **hosted witness network** (the business, §7) | `witness` | ⬜ | mid-term |
| Independent completion attestation (reject self-report) | `attestation` | ✅ | Days 11–16 |
| Counter-sign vs third-party attester flows; threshold attestation | `attestation` | ⬜ | Days 11–16 |
| Composed `verify()` (chain+witness+attestation, fail-closed) | `verifier` | ✅ | Days 11–16 |
| Harden verifier: cross-binding, receipt-splicing, canonical-digest attacks | `verifier` | 🔨 | Days 11–16 |
| Revocation: short-TTL + transparency-log (survives partial-chain compromise) | `revocation` | ⬜ (stub) | adjacent |
| RFC 8785 (JCS) canonicalization (replace deterministic serde_json) | workspace | ⬜ | before wire format |

### Udaya — offensive security (the fundraise artifact)

| Workstream | Area | Status | Roadmap |
|---|---|---|---|
| Claim-to-attack matrix across AIP / APS / DRP / EP (claimed vs. non-goal) | `docs` | ⬜ | Days 1–2 |
| Reproduce each system's headline benchmark (directive 5, no laundered stats) | `docs`, `benchmarks` | ⬜ | Days 1–2 |
| **Omission** flag-plant: all-valid 3-hop chain, AIP=VALID, ours=INVALID | `exploits` | 🔨 (mechanized in `verifier` tests) | Days 3–10 |
| Deterministic exploit harness pinned to upstream versions | `exploits` | ⬜ | Days 3–10 |
| Cross-draft adversarial conformance suite | `conformance` | ⬜ | Days 23–30 |

### Satyam — agent systems, integrations, SDK (make the core reachable)

| Workstream | Area | Status | Roadmap |
|---|---|---|---|
| AP2 mandate adapter against the real spec format (parse + verify) | `integrations/ap2` | ⬜ (stub) | Days 3–10 |
| MCP request-header signing/verification hooks (Web Bot Auth transport) | `integrations/mcp` | ⬜ (stub) | Days 11–16 |
| A2A + x402 wrappers on the agent-to-agent path | `integrations/a2a` | ⬜ | mid-term |
| Attack POC upgraded to drive the **real** Rust chain (AIP-valid → our INVALID) | `integrations/attack` | 🔨 (illustrative today) | Days 3–10 |
| SDK: bind `wrap` / `sign` / `verify` to `/core` (PyO3 or sidecar, not a reimpl) | `sdk/python` | ⬜ (stub) | Days 11–16 |
| TypeScript SDK (thin bindings + integration helpers) | `sdk/typescript` | ⬜ | mid-term |
| Design-partner conversations (agent-payment infra builders) | — | ⬜ | Days 17–22 |

### Shared

| Workstream | Area | Status |
|---|---|---|
| Verification-latency + per-hop-size benchmarks (real `verify()`) | `benchmarks` | 🔨 |
| Standards presence: WIMSE, FIDO Agentic Auth, SCITT mailing lists | — | ⬜ |
| Fundraise artifact: attack paper + OSS hardened verifier + demo | `docs` | ⬜ |

If you pick up an ⬜/🔨 item, say so in the PR (or an issue) so we don't both
land on the same crate. When a status changes, update this table in the same PR.

## Ground rules while we're pre-1.0

- **No crypto or verifier logic lands without both of us reviewing it.** This is
  a security product; a subtly wrong signature scheme, attenuation check,
  inclusion proof, or attestation binding is the kind of bug that only shows up
  when it's exploited.
- **Only attack claimed properties (CLAUDE.md §1.2, §2).** A test or exploit
  that breaks a published *non-goal* is a blog post; one where a verifier
  accepts what it should reject is the company. Comment each such test with the
  exact upstream claim it targets.
- **Fail closed.** Every verifier path returns a typed error naming the property
  that failed. Default-deny, always.
- **Design invariants are non-negotiable without discussion.** Scope only
  narrows, expiry only shortens, revocation survives partial-chain compromise,
  signature algorithm is swappable per block, proof lives in the token (see
  `docs/REFERENCE.md` §5). A change that would violate one is a conversation
  before it's a PR.
- **Don't overclaim (CLAUDE.md §4).** A witness anchors what was *reported*, not
  ground truth. Keep code, comments, and docs inside the scope boundary.
- **Reproduce before you quote.** Any benchmark committed to `/docs` ships with
  the script that produced it.

## Before opening a PR

- Rust: `cargo fmt --manifest-path core/Cargo.toml --all`, then
  `cargo clippy --manifest-path core/Cargo.toml --workspace --all-targets -- -D warnings`,
  then `cargo test --manifest-path core/Cargo.toml --workspace`, then
  `cargo audit --file core/Cargo.lock`.
- Python: `ruff check .`, `black --check .`, `mypy src`, `pytest`, run from
  inside whichever of `integrations/` or `sdk/python/` you touched.
- Install the pre-commit hooks once (`pre-commit install`) and most of the above
  runs automatically on commit.

CI (`.github/workflows/`) runs all of the above plus `cargo audit` / `pip-audit`
on every push and PR. Keep it green.

## License

TODO: we haven't finalized MIT vs Apache-2.0 yet — see `/LICENSE`.
