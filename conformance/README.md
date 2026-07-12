# /conformance — cross-draft adversarial suite

The "SOC 2 for agent authorization" wedge. Owner: **shared** (Udaya leads the
attack cases, Satyam the rail-integration cases).

A conformance suite that is **cross-draft and adversarial** — not scoped to a
single spec. For each property a competing draft claims or explicitly punts
(facts reproduced in [`../docs/RESEARCH_VERIFICATION.md`](../docs/RESEARCH_VERIFICATION.md)),
it builds a real artifact with the core crates and asserts the **IndexOne
verifier** rejects what it should and accepts the honest case. A verifier
"passes conformance" only if it rejects every adversarial case that targets a
property it claims to guarantee, and fails closed on every unresolved step.

**Status: ✅ implemented.** Standalone package (`indexone-conformance`, like
`/exploits` and `/benchmarks` — not a `/core` workspace member), path deps into
the real core crates. Cases today:

| Case | Claim it targets |
|---|---|
| Honest action accepted | control — the verifier isn't rejecting everything |
| Self-reported completion rejected | AIP §7 concedes self-reported completion (RESEARCH_VERIFICATION §1) |
| Omission rejected | DRP/EMILIA defer completeness to an external log (§2) |
| Equivocation rejected | forked log views need a shared witness (CLAUDE.md §4) |
| Scope widening rejected | monotonic attenuation (AIP/Biscuit/APS) |

Run it (exits non-zero if any case fails):

```bash
cargo run  --manifest-path conformance/Cargo.toml --bin conformance
cargo test --manifest-path conformance/Cargo.toml
```

**Honesty (CLAUDE.md §1.2, §4).** Each case encodes a claim we reproduced from a
primary source and tests **IndexOne's own verifier**, not the upstream SDKs. We
attack claimed or known-open properties, never a strawman.

**Next (⬜):** import each draft's own conformance fixtures (APS ships one) and
run them against our verifier; add cross-binding / receipt-splicing cases as the
verifier hardens.
