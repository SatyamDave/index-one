# index-one — Design Reference

The verification layer for agent-to-agent communication that proves the
chain of permission behind every action.

This document is the shared map of prior art, standards, and design
invariants behind `/core`, `/integrations`, and `/sdk`. It doesn't
contain any implementation detail — see the crate/package docstrings and
`TODO`s in the code for that. When in doubt about *why* something is
built a certain way, it should be answerable from this file.

---

## 1. Papers to build from

### AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A
arXiv 2603.24775

**Why it matters to us:** our closest prior art, and the source of the
Invocation-Bound Capability Token (IBCT) block structure we're adapting —
Block 0 authority + Block N delegation is directly descended from AIP's
construction. Study the IBCT construction itself and its seven required
properties closely before diverging from it; every place we differ should
be a deliberate choice, not an oversight.

### AI Identity: Standards, Gaps, and Research Directions for AI Agents
arXiv 2604.23280 (April 2026)

**Why it matters to us:** this is our problem statement, almost verbatim —
no deployed protocol proves which human principal authorized which action
at the 3rd/4th hop across organizations, and no tool verifies intent
legitimacy. Cross-org attribution plus intent integrity is our zero-to-one;
this paper is the citation for why that gap exists and hasn't been closed.

### Authenticated Delegation and Authorized AI Agents
arXiv 2501.09674 (Tobin South et al., ICML 2025)

**Why it matters to us:** the foundational framing for what "delegation"
even means for AI agents (as distinct from human OAuth-style delegation) —
underpins the vocabulary the rest of this document and the codebase uses.

### Identity Management for Agentic AI
arXiv 2510.25819 (OpenID Foundation, Tobin South et al.)

**Why it matters to us:** explains concretely why SPIFFE/OAuth-style
identity breaks down across organization boundaries, and the specific
risks introduced by recursive delegation — the exact failure mode our
`chain` crate's hash-linked, scope-narrowing blocks are designed to close.

### AITH (post-quantum continuous delegation, ML-DSA-87)

**Why it matters to us:** the basis for our crypto-agility / hybrid-
signature design in `indexone-crypto` — informs the `Algorithm::MlDsa87`
and `Algorithm::Hybrid` variants and why every block carries its own
algorithm tag instead of the chain committing to one algorithm globally.

### Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud
Birgisson, Politz, Erlingsson et al., Google

**Why it matters to us:** the origin of offline attenuation as a concept —
the idea that a token can be narrowed by its holder without contacting the
issuer. Also the cautionary tale: Macaroons' shared-secret HMAC chaining
means anyone who can verify a caveat can also forge one, which is exactly
the flaw Biscuit (and, transitively, `indexone-chain`) fixes by moving to
public-key signatures per block.

### "Delegation Without Escalation"
mahasbini.org, May 2026

**Why it matters to us:** source of our revocation and attenuation
invariants — one-directional time attenuation (expiry only ever shortens
down a chain, never extends), and the requirement that revocation survive
partial-chain compromise. Directly informs `indexone-revocation`'s
short-TTL + transparency-log design.

---

## 2. Repos to build on / fork

### Eclipse Biscuit — [`biscuit-auth/biscuit`](https://github.com/biscuit-auth/biscuit) (biscuitsec.org)

**Why it matters to us:** our core primitive. Public-key (Ed25519)
capability tokens with offline attenuation, Datalog policies, built-in
revocation IDs, and sub-1ms verification — `indexone-chain` is built as an
extension of this model, not a reinvention of it. Authors: Geoffroy
Couprie, Clément Delafargue.

### `google-agentic-commerce/AP2`

**Why it matters to us:** the payment-mandate rail we integrate with *and*
attack (Intent/Cart/Payment mandates, W3C Verifiable Credentials, ECDSA
P-256). The seam we exploit and then close: AP2 binds a mandate to a
single user, not across an agent chain — see `integrations/attack` for a
runnable demonstration of exactly what that seam allows.

### `rescrv/libmacaroons`

**Why it matters to us:** the reference implementation for attenuation
mechanics — useful as a concrete read of how caveat-based narrowing is
actually implemented, separate from the Macaroons paper's theory.

### `google-a2a/a2a-x402`

**Why it matters to us:** the crypto-payment extension to A2A — relevant
prior art for how payment authorization gets threaded through an
agent-to-agent protocol, adjacent to what we do with AP2.

### AIP reference implementation (Python/Rust)

**Why it matters to us:** the closest comp to study line-by-line before we
diverge. Understand exactly what it does before deciding what we do
differently (cross-org attribution being the headline difference).

---

## 3. Standards to track

- **AP2** (Google) — payment-mandate rail; see §2 above.
- **Visa TAP** — Visa's agent payment/trust rail.
- **Mastercard Agent Pay / Verifiable Intent** — Mastercard's equivalent.
- **FIDO Agentic Authentication WG** — where agent authentication standards
  are being worked out at the FIDO Alliance.
- **IETF WIMSE** (`draft-ietf-wimse-arch`, §3.3.9) — Workload Identity in
  Multi-System Environments; §3.3.9 explicitly names multi-hop delegation
  as an unsolved failure mode. Watch this closely — it's the standards-body
  articulation of the exact problem index-one solves.
- **Web Bot Auth** — per-request Ed25519 header signing. This is our
  transport model for `integrations/mcp`: the capability chain travels
  as a header, signed per-request, alongside whatever payload it authorizes.

**Why it matters to us (collectively):** these are the rails and standards
bodies index-one has to interoperate with, not compete against — we're the
attribution layer sitting on top of all of them, so drift in any of these
is drift we need to track.

---

## 4. Key concepts

- **Authorization vs. authentication** — authentication proves *who you
  are*; authorization proves *what you're allowed to do*. index-one is
  fundamentally an authorization-chain problem: proving what authority was
  granted and how it moved, not just who's who at each hop.
- **Delegation** — one principal granting a subset of its own authority to
  another principal, without giving up that authority itself.
- **Attenuation** — narrowing a delegated capability, one-directionally:
  each hop can only reduce scope/budget/depth/expiry, never restore or
  widen what a previous hop removed.
- **Capability tokens** — authorization travels *in the token itself*
  (what you hold proves what you can do), as opposed to an ACL model where
  a central server looks up what you're allowed to do.
- **Datalog policies** — Biscuit's mechanism for expressing attenuation and
  authorization checks as logic facts/rules, evaluated locally at
  verification time rather than requiring a policy-server round trip.
- **Append-only signed chain** — each new delegation hop is a new signed
  block referencing the previous block's hash; nothing already in the
  chain can be edited or removed, only extended.
- **Local, stateless, per-request verification** — verifying a token
  requires no network call and no shared mutable state; every fact needed
  to check signatures and attenuation invariants travels inside the token.
  (Revocation freshness is the deliberate exception — see below.)
- **Crypto-agility / post-quantum** — the signature algorithm is a
  per-block, explicit tag, not a chain-wide assumption, so Ed25519 today
  and ML-DSA/hybrid tomorrow can coexist within the same chain's history.
- **Revocation + freshness at scale** — the hard problem with any offline,
  stateless-verification token: how do you invalidate one *before* its
  natural expiry without needing a live call on every verification. Solved
  here with short-TTL blocks (stale-by-default) plus an out-of-chain
  transparency log (checkable, but not required for every verification).

---

## 5. Design invariants we must honor

These are non-negotiable without an explicit, discussed exception — see
`CONTRIBUTING.md`.

1. **Proof lives in the token, not a central database.** No blockchain.
   Verification never requires a call back to an issuing authority or a
   shared ledger to check the chain's own well-formedness.
2. **Scope only narrows down a chain, never widens.** Every
   `DelegationBlock`'s permissions/budget must be a subset of what it
   inherited from the block before it.
3. **Time/expiry attenuates in one direction only.** A later block's
   expiry must be less than or equal to the one it inherited; delegation
   can shorten a token's remaining lifetime, never extend it.
4. **Revocation must survive partial-chain compromise.** A compromised key
   at one hop must not be able to suppress or hide the revocation of
   another hop — hence short-TTL (revocation-by-default over time) plus an
   out-of-chain transparency log (independent of any single hop's key).
5. **Signature algorithm must be swappable per block.** Agility isn't a
   chain-wide setting; each block declares its own algorithm, so migrating
   to post-quantum or hybrid signatures doesn't require invalidating or
   re-issuing an entire chain's history.

---

## 6. Team split

- **Rust crypto core** (`/core` — `chain`, `crypto`, `revocation` crates) —
  **Udaya**.
- **Python rail integration + attack POC** (`/integrations`, `/sdk`) —
  **Satyam**.

See `CONTRIBUTING.md` for how this split translates into review
responsibilities and PR expectations.
