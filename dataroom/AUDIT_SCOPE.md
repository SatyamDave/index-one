# IndexOne — Cryptographic Review: Scope of Work

For a cryptographer or audit firm to quote against. IndexOne is the witness and
independent-attestation layer for cross-organization AI-agent delegation: it
proves an agent action chain is complete, attributed across orgs, and honestly
reported — not just signed. The **verifier is the product**, so an independent
human review of the crypto is the gate before any production use or any external
claim that it is production-safe.

## Why this review, now

Everything load-bearing is **machine-verified but not human-reviewed**:

- 125 tests across the core workspace (`cargo test --manifest-path core/Cargo.toml --workspace`).
- 18 property-based (`proptest`) soundness properties over adversarial inputs —
  including "any single mutation of a valid artifact makes `verify()` return
  `Err`, never `Ok`" and "witness proofs are immutable under log growth."
- ~12M libFuzzer executions across the serde-deserialize-then-verify surface
  (`fuzz/`), zero crashes.
- A differential oracle proving the witness's memoized proof generation is
  **byte-identical** to a naive RFC 6962 recomputation for all small sizes.

That covers "the code does what its tests say." It does **not** cover what only a
human cryptographer can judge: whether the *design* is sound, whether the
composition actually composes, whether the claimed properties are the right ones,
and whether the code honestly stays inside its stated limits.
`CONTRIBUTING.md` already requires dual review of all crypto before it ships; this
SOW externalizes that.

## In scope — the trust path (`/core`)

The nine core crates, with emphasis on the five load-bearing ones:

| Crate | What to review |
|---|---|
| `crypto` | Ed25519 (`ed25519-dalek` 2) + **ML-DSA-87 / hybrid** (`fips204` 0.4). Hybrid construction: both-must-verify, unambiguous byte layout, downgrade resistance. ML-DSA usage (deterministic signing, encoding). Per-block algorithm agility. |
| `chain` | Append-only delegation chain: hop-to-hop cryptographic binding (`from_key`==prev `to_key`, hash links), monotonic attenuation (scope ⊆, budget ≤, expiry ↓, depth ↓), the structured `Permission`/`Constraint` narrowing (entailment soundness). |
| `witness` | RFC 6962 Merkle log: inclusion + consistency proofs, domain separation, the **perfect-subtree memoization** (is the "immutable in an append-only log ⇒ no invalidation" argument correct?), signed tree heads, `reconcile_heads` equivocation detection. |
| `attestation` | The independence rule (attester ≠ executor), counter-signer vs third-party roles, **k-of-n threshold** (can it be gamed — same key twice, executor hiding in the bundle, inconsistent binding?). |
| `verifier` | The composed `verify()` / `verify_threshold()`: is it **sound and complete** against its claimed properties, and does it **fail closed on every unresolved step**? Gate ordering (equivocation before inclusion, etc.), the presenter-controlled-sufficiency and canonical-action-digest defenses. |
| `revocation` / `revlog` / `revmap` | Short-TTL + log-backed revocation; does it survive partial-chain compromise; non-inclusion-proof soundness. |
| workspace | RFC 8785 (JCS) canonicalization — signed-byte determinism, any malleability; content-addressing. |

### Specific questions we most want answered

1. **Does the composition compose?** Each gate is individually tested; is the
   *composition* of chain + witness + attestation sound, with no gap a valid-
   looking artifact could slip through?
2. **Scope-boundary honesty (`CLAUDE.md` §4).** We claim to prove *completeness,
   monotonicity, cross-org attribution, non-equivocation, and independent
   attestation* — and explicitly **not** ground truth. Does the code stay inside
   that line, or does anything overclaim?
3. Hybrid + ML-DSA correctness and downgrade resistance.
4. Merkle/RFC 6962 conformance and the memoization's immutability argument.
5. Timing / side-channel exposure in the verification path.
6. Any malleability in the canonical signing bytes.

## Out of scope (unless you want it)

Service infrastructure (`services/*`, axum/tokio HTTP), the Python/TypeScript/
WASM SDKs (thin bindings that call the core — not the trust path themselves), and
the exploit/demo/benchmark harnesses. Flag if you think any of these belong in
scope.

## Deliverables

1. A severity-ranked findings report (critical → informational).
2. An explicit verdict on the **scope-boundary claims** — does the code prove
   what §4 says it proves, and nothing more?
3. A "safe to run in production for value transfer, with these conditions" letter
   we can show diligence.

## Reproduce before you start

```bash
make reproduce      # build + all tests + exploits + conformance + real-upstream side-by-sides
make require-real   # the real AIP reference verifier side-by-side (hash-pinned)
make demo           # the end-to-end story (chain → witness → composed verify)
cargo test --manifest-path core/Cargo.toml --workspace
cargo +nightly fuzz run fuzz_chain_verify --fuzz-dir fuzz -- -max_total_time=600
```

## Logistics — ⚠️ NEEDS HUMAN INPUT

- ⚠️ Budget / rate.
- ⚠️ Timeline (this is a lead-time item — start the conversation now; a review is weeks, not days).
- ⚠️ Firm vs. independent cryptographer (candidates: Trail of Bits, NCC Group, Cure53, Zellic, or an academic cryptographer with CT / capability-token background).
- ⚠️ NDA / disclosure terms; whether the report can be published (a published audit is a fundraise asset).
- ⚠️ Commit hash to pin the review to.
