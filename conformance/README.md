# /conformance — cross-draft adversarial suite

The "SOC 2 for agent authorization" wedge. Owner: **shared** (Udaya leads the
attack cases, Satyam the rail-integration cases).

A conformance suite that is **cross-draft and adversarial** — not scoped to a
single spec (APS already ships an APS-scoped one; ours is the differentiator,
CLAUDE.md §14). For each draft (AIP, APS, DRP, EP) it encodes:

- the **claimed** verifier guarantees,
- the **admitted non-goals** (verbatim from each spec's limitations section),
- adversarial cases that probe the seam between the two — cross-binding,
  receipt-splicing, presenter-controlled sufficiency bar, inconsistent canonical
  action digest, log equivocation, and omission.

A verifier "passes conformance" when it rejects every adversarial case that
targets a property it *claims* to guarantee, and fails closed on every
unresolved step.

**Status: ⬜ not started.** Depends on the claim-to-attack matrix (`/docs`,
Days 1–2) and the hardened verifier (`core/verifier`, Days 11–16). See
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) for the work breakdown.
