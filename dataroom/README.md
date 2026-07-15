# /dataroom

Founding-brief and diligence artifacts for IndexOne — the material a human or
investor reads to understand the repo cold.

- [`INDEXONE_BRIEF.md`](INDEXONE_BRIEF.md) — technical ground truth (crypto,
  token structure, the `verify()` algorithm and its fail-closed gates), a
  real-vs-stubbed status matrix, reproduced test/benchmark numbers, design-partner
  inputs (product one-liner, integration surface, the "wound"), housekeeping
  blockers, and the open questions that need a human.
- [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md) — scope of work for the external
  cryptographic review (the founder-only gate before production / an external
  "it's safe" claim). Start this conversation now — it has a lead time.
- [`DESIGN_PARTNER_OUTREACH.md`](DESIGN_PARTNER_OUTREACH.md) — the discovery
  opener, a "how to run these" playbook, and five personalized message drafts.
- [`DECK_OUTLINE.md`](DECK_OUTLINE.md) — the seed-deck narrative, each slide
  grounded in a reproducible artifact, with the ⚠️ founder-only slides marked.

**These three are the highest-leverage next moves, and none is a code problem —
the build is no longer the bottleneck.** The audit and a live design partner are
what gate the raise; the deck is 80% assembled and blocked only on founder inputs
(bios, raise, ask).

**Read the PROVENANCE note at the top of the brief first.** It was generated
during a parallel `dataroom` implementation pass; `main` is the source of truth
and is a superset, so some metrics and file-line references should be re-run
against `main` before external use.

See also the canonical engineering docs at the repo root: [`../README.md`](../README.md),
[`../CLAUDE.md`](../CLAUDE.md), [`../VISION.md`](../VISION.md),
[`../ROADMAP.md`](../ROADMAP.md), [`../docs/SPEC.md`](../docs/SPEC.md),
[`../docs/REFERENCE.md`](../docs/REFERENCE.md), and [`../SECURITY.md`](../SECURITY.md).
