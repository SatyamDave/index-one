# Contributing

index-one is a two-person early-stage project right now. This document
describes how we split work and the ground rules for the repo, not a
public contribution process (yet).

## Ownership split

- **Rust crypto core (`/core`) — Udaya.** The `chain`, `crypto`, and
  `revocation` crates: the actual signing, attenuation, and verification
  logic, plus the crypto-agility design (Ed25519 now, ML-DSA/hybrid
  post-quantum later). This is where real cryptographic correctness
  matters most, and where review should be strictest.
- **Python rail integration + attack POC (`/integrations`, `/sdk`) —
  Satyam.** AP2 and MCP adapters, the cross-org attribution attack
  harness, and the public SDK surface. This code calls into `/core` (once
  it has real implementations); it should not reimplement crypto or chain
  logic itself.

`/benchmarks` and `/docs` are shared — either of us updates them as the
relevant crate/package changes.

## Ground rules while we're pre-1.0

- **No real cryptography lands without both of us reviewing it.** This is
  a security product; a subtly wrong signature scheme, attenuation check,
  or revocation mechanism is the kind of bug that doesn't show up until
  it's exploited.
- **Stubs stay stubs until they're actually implemented.** Don't quietly
  fill in a `todo!()`/`NotImplementedError` as a side effect of an
  unrelated change — implement it as its own reviewed piece of work.
- **Design invariants are non-negotiable without discussion.** Scope only
  narrows down a chain, expiry only shortens, revocation must survive
  partial-chain compromise, signature algorithm is swappable per block.
  See `/docs/REFERENCE.md`. If a change would violate one of these, that's
  a conversation before it's a PR.

## Before opening a PR

- Rust: `cargo fmt --manifest-path core/Cargo.toml --all`, then
  `cargo clippy --manifest-path core/Cargo.toml --workspace --all-targets -- -D warnings`,
  then `cargo test --manifest-path core/Cargo.toml --workspace`.
- Python: `ruff check .`, `black --check .`, `mypy src`, `pytest`, run from
  inside whichever of `integrations/` or `sdk/python/` you touched.
- Install the pre-commit hooks once (`pre-commit install`) and most of the
  above runs automatically on commit.

CI (`.github/workflows/`) runs all of the above plus `cargo audit` /
`pip-audit` on every push and PR.

## License

TODO: we haven't finalized MIT vs Apache-2.0 yet — see `/LICENSE`.
