# Security Policy

IndexOne is a cryptographic verification layer for cross-organization AI-agent
delegation. Its correctness is the product, so we treat security reports as the
highest-priority class of issue.

## Scope

In scope: the Rust core (`core/` — `crypto`, `chain`, `witness`, `attestation`,
`verifier`, `revocation`), the SDK and rail integrations (`sdk/`,
`integrations/`), and the conformance/exploit harnesses (`conformance/`,
`exploits/`).

We are especially interested in reports where **the verifier accepts an
artifact it claims to reject** — a valid-looking chain, receipt, attestation, or
completion that passes `verify()` despite violating a property IndexOne claims
to guarantee (per-hop authenticity, monotonic attenuation, completeness/
non-omission, non-equivocation, independent attestation, outcome honesty,
cross-org attribution). That is precisely the class of bug this project exists
to eliminate.

Out of scope (these are documented non-goals, see `CLAUDE.md` §4): claims that a
recorded action digest matches physical ground truth, semantic-intent
verification, or any guarantee stronger than the weakest independent attester in
a chain. A "break" of a published non-goal is not a vulnerability.

## Reporting

Report privately — do **not** open a public issue for an unfixed vulnerability.
Email the maintainers (see repository owners) with:

- a description of the property violated and why,
- a minimal, deterministic reproduction (ideally a failing test or a harness in
  `exploits/`),
- affected crate/package and commit.

We aim to acknowledge within 3 business days and to ship or scope a fix before
any public disclosure. Coordinated disclosure is appreciated.

## Cryptographic posture

- Public-key primitives only in the trust path — no secret-based (HMAC) auth,
  which does not survive a trust boundary.
- Default-deny: every verifier path fails closed with a typed error naming the
  property that failed.
- Algorithm agility from v1 (per-block algorithm tags), so a weakened primitive
  can be rotated without a flag day.

This project has not yet had an external cryptographic audit; treat it as
pre-1.0 and do not rely on it for production value transfer without your own
review.
