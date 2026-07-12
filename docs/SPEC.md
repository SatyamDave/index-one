# IndexOne Delegation-Chain and Witnessed-Attestation Specification

    Internet Engineering Task Force (IETF-style draft)
    Intended status: Experimental
    Category: Standards Track (aspirational)
    Document: draft-indexone-delegation-witness-00

## Status of This Memo

This document is an internal, IETF-Internet-Draft-style specification of the
IndexOne delegation-chain, transparency-witness, and independent-attestation
formats and algorithms **as implemented** in the `core/` Rust crates of this
repository. It is not an IETF work product and has not been reviewed by any
standards body. It is written to be forkable into a real Internet-Draft once the
formats stabilize.

Where the running implementation and this specification differ, the difference
is called out explicitly (see the boxed **Implementation note** paragraphs).
Every normative claim in this document was checked against the source in
`core/chain`, `core/crypto`, `core/witness`, `core/attestation`,
`core/verifier`, and `core/revocation`. Citations to external work follow
`docs/RESEARCH_VERIFICATION.md`; no claim not reproduced there is asserted as
fact.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 / RFC 8174 when, and only when, they appear
in all capitals.

---

## Abstract

IndexOne specifies a capability-token format for recursive, cross-organization
AI-agent delegation, together with a transparency witness and an independent
completion-attestation mechanism. A delegation chain is an append-only sequence
of public-key-signed blocks: a root block naming a human principal and its
initial authority, followed by zero or more delegation blocks, each of which may
only *narrow* the authority it inherited and is hash-linked to its predecessor.

Signed chains prove per-hop authenticity and monotonic attenuation, but a signed
log proves nothing about what was silently left out of it, nor whether it was
shown consistently to every observer, nor whether a self-reported "done" is
honest. IndexOne closes those three gaps with (a) an append-only Merkle
transparency log ("the witness") providing RFC 6962 inclusion and consistency
proofs, so that omission and equivocation become detectable; and (b) an
independent completion attestation counter-signed by a party other than the
executing agent, optionally under a k-of-n threshold. A composed, fail-closed
`verify()` algorithm binds these together.

This specification is precise about scope. **A witness anchors what was
reported, not ground truth.** IndexOne proves a delegation chain is complete,
monotonic, cross-org-attributable, and non-equivocating, and that completion was
independently attested rather than self-reported — and the strength of that
attestation is exactly the strength of the attester's visibility into ground
truth. It does not, and cannot, prove that a recorded action digest corresponds
to what physically happened.

---

## 1. Terminology

- **Principal.** A party that can hold and exercise authority: a human, or an
  agent acting for an organization. Represented as an identifier plus a
  human-readable display name (`Principal` in `core/chain`).

- **Scope.** The permission envelope carried by a block: a set of opaque
  permission strings, an optional budget ceiling with a currency, a maximum
  remaining delegation depth, and an expiry timestamp (`Scope` in `core/chain`).

- **Delegation chain.** An append-only, cryptographically hash-linked sequence
  of signed blocks — one root block and zero or more delegation blocks — that
  together carry authority from a human principal down through one or more agent
  hops. The token *is* the proof: verification needs no callback and no shared
  database.

- **Attenuation.** The narrowing of authority at each hop: a child block's scope
  MUST be a subset of the scope it was delegated from — permissions narrow,
  budget shrinks, expiry moves no later, and depth strictly decreases.
  Attenuation never widens authority.

- **Witness.** An append-only Merkle transparency log over action receipts.
  Membership is provable (inclusion proof); append-only history is provable
  (consistency proof). An action absent from the witness has no inclusion proof
  against the current root and is therefore *provably missing*.

- **Inclusion proof.** An RFC 6962 §2.1.1 audit path demonstrating that a
  specific receipt is a leaf of a Merkle tree of a stated size rooted at a
  stated digest.

- **Consistency proof.** An RFC 6962 §2.1.2 proof that a smaller tree's root is
  a prefix of a larger tree's root — i.e. the log only *appended* between the
  two snapshots and never rewrote or reordered history.

- **Independent attestation.** A completion statement signed by a party other
  than the executing agent — either the immediate delegator (counter-signed) or
  an external third party — as opposed to a self-report by the executor.

- **Omission.** A real action that is absent from the record. It cannot be
  detected by reading a log that does not contain it; it is made detectable only
  by requiring an inclusion proof against a witnessed root.

- **Equivocation.** A log presenting different histories to different observers
  (a forked view). It is unsolvable without a shared witness; IndexOne detects
  it by comparing the attested root against a gossip-trusted root and by
  requiring consistency proofs.

- **Executor.** The agent at the tail of the chain — the party that performs the
  final action. A completion signed by the executor's key is *self-reported* and
  is rejected.

---

## 2. Delegation Token Format

A delegation token is a `Chain`: exactly one `RootBlock` (Block 0) followed by a
(possibly empty) ordered list of `DelegationBlock`s (Block 1, Block 2, …). Every
block embeds the public key(s) it is bound to, so a verifier holding only the
trusted root public key can check the entire chain hop-by-hop, offline.

### 2.1. Block 0 — RootBlock

The root block is the human root of authority. Every block in a chain traces
back to exactly one root block.

| Field           | Type        | Meaning                                                        |
| --------------- | ----------- | -------------------------------------------------------------- |
| `principal`     | Principal   | The human (or root) principal issuing all authority.           |
| `principal_key` | PublicKey   | The root principal's public key; the chain's **trust anchor**. |
| `scope`         | Scope       | The initial (widest) authority envelope.                       |
| `signature`     | Signature   | The root principal's signature over the block's signing payload. |

The `signature` covers the canonical encoding of `(principal, principal_key,
scope)` — every field except the signature itself. Because `principal_key` is
inside the signed payload and is also the key that verifies the signature, the
root block is self-authenticating against the trust anchor a verifier is given.

### 2.2. Block N — DelegationBlock (N ≥ 1)

Each delegation block records one agent delegating a narrowed authority to the
next.

| Field             | Type        | Meaning                                                                                          |
| ----------------- | ----------- | ------------------------------------------------------------------------------------------------ |
| `from`            | Principal   | The delegating principal. MUST equal the previous block's `to` (or the root `principal` for N=1). |
| `from_key`        | PublicKey   | Public key of `from`. MUST equal the previous block's `to_key` (or the root `principal_key` for N=1). |
| `to`              | Principal   | The principal authority is delegated to.                                                         |
| `to_key`          | PublicKey   | The key the delegatee MUST sign the *next* hop with.                                             |
| `scope`           | Scope       | The narrowed authority for this hop. MUST be a subset of the previous scope.                     |
| `purpose`         | String      | Why the delegation happened. MUST be non-empty (after trimming whitespace).                      |
| `prev_block_hash` | bytes       | blake3 hash linking this block to its predecessor (see §3).                                      |
| `signature`       | Signature   | Signature of `from_key` over the block's signing payload.                                        |

The `signature` covers the canonical encoding of `(from, from_key, to, to_key,
scope, purpose, prev_block_hash)` — every field except the signature itself.

### 2.3. Embedded keys and cross-org binding

Continuity is cryptographic, not nominal. Block N's `from_key` MUST equal the
key that Block N−1 designated as its delegatee (`to_key`), and for N=1 it MUST
equal the root's `principal_key`. This is what stops an unrelated key from
splicing itself into the chain: an appended block is only accepted if it is
signed by the key the current tail delegated to. Consequently a verifier that
trusts a single root public key can prove the *entire* chain of authority
hop-by-hop back to Block 0, across organization boundaries, with no callback and
no shared state.

The tail's `to_key` is also the **executor key** — the public key of the agent
that performs the final action. A completion attestation signed by this key is
self-reported and is rejected by the attestation layer (§6).

### 2.4. Per-block algorithm agility

Each signature and public key carries an explicit `Algorithm` tag, so the
signing algorithm is swappable **per block** — agility is not a chain-wide
assumption. Three schemes are implemented in `core/crypto`:

- **`Ed25519`** — classical EdDSA (RFC 8032), via `ed25519-dalek`.
- **`MlDsa87`** — post-quantum ML-DSA-87 (FIPS-204), via the pure-Rust `fips204`
  crate, signed with an **empty signing context** (`ctx = &[]`).
- **`Hybrid`** — a classical **and** a post-quantum signature over the same
  payload; verification requires **both** component signatures to pass. An
  attacker must forge both schemes at once.

Verification is a single dispatch function, `verify_signature(payload,
signature, public_key)`, that fails **closed**: it distinguishes "verification
ran and the signature is invalid" (`Ok(false)`) from "verification could not be
attempted" (`Err`) — the latter covering an algorithm-tag mismatch between
signature and key, malformed key/signature bytes, or malformed hybrid framing.
A relying party MUST treat `Err` as a rejection.

#### 2.4.1. Hybrid framing

`Algorithm::Hybrid` is a unit tag (so the enum stays `Copy`); the two component
`(algorithm, bytes)` pairs live inside the `bytes` of the hybrid `PublicKey` /
`Signature` under an explicit, self-describing layout of **exactly two**
concatenated components, each framed as:

    ┌──────────┬───────────────────────┬─────────────────┐
    │ tag: u8  │ len: u32 (big-endian) │ payload (len B) │
    └──────────┴───────────────────────┴─────────────────┘

`tag` is `0` for Ed25519 and `1` for ML-DSA-87. There is no tag for `Hybrid`, so
hybrids cannot nest — attempting to compose a hybrid as a component is a typed
error, not a silently accepted signature. Component order is positional and
identical between the signature and the public key: index 0 is the classical
signer, index 1 the post-quantum signer. Decoding rejects trailing bytes,
truncated headers, and truncated payloads. If either component's signature-tag
disagrees with its key-tag, verification is an `Err`; if either component
signature is well-framed but invalid, verification is `Ok(false)`.

---

## 3. Canonicalization and Hashing

### 3.1. Canonical bytes

All signatures and all hash links are computed over a **canonical byte
encoding** of the signed structure. The canonical-bytes target for the wire
format is **RFC 8785 JSON Canonicalization Scheme (JCS)**: a deterministic
serialization with sorted object keys and normalized number/string forms, so
that two independent implementations produce byte-identical inputs for the same
logical object.

> **Implementation note.** JCS is now **implemented**: all three signing/commitment
> sites — `root_signing_payload` / `delegation_signing_payload` (`core/chain`),
> `ActionReceipt::canonical_bytes` (`core/witness`), and `signing_payload`
> (`core/attestation`) — canonicalize with `serde_jcs` (RFC 8785), so independent
> encoders produce byte-identical inputs. Residual: the opaque `action_digest`
> (§5.1) is still *caller-defined*; how the caller canonicalizes the underlying
> action before it becomes `action_digest` is not yet specified normatively and
> is the remaining canonicalization gap to close.

### 3.2. Hash function

The hash function throughout is **blake3**, producing 32-byte digests.

### 3.3. Chain hash-linking

A `DelegationBlock.prev_block_hash` is `blake3` over the predecessor's **full**
canonical encoding, signature included. The predecessor is the root block (for
Block 1) or the previous delegation block (for Block N ≥ 2). Because the hash
covers the signature, any mutation of any earlier block — including re-signing —
changes the link and is detected at verification.

Two chain-level digests are defined:

- `Chain::digest()` — `blake3` over the whole chain's canonical bytes. This is
  the stable "authority this action ran under" identifier that witness receipts
  and completion attestations commit to.
- The executor key — `to_key` of the last delegation block, or `principal_key`
  if the chain has no delegations.

### 3.4. Domain-separated Merkle hashing (RFC 6962)

The witness Merkle tree domain-separates leaves from interior nodes exactly per
RFC 6962, so a leaf can never be reinterpreted as an interior node:

- **Leaf hash:** `blake3(0x00 || leaf_data)`.
- **Node hash:** `blake3(0x01 || left_digest || right_digest)`.
- **Empty tree:** `blake3(0x00 || "")` — the empty string hashed as a leaf, so
  it cannot collide with any node.

Tree shape follows the RFC 6962 split: for `n > 1` leaves, the left subtree
holds the largest power of two strictly less than `n`, and the right subtree
holds the remainder. Both the inclusion-path machinery and the consistency-proof
machinery use the same split function, so they never diverge on tree shape.

---

## 4. Attenuation Invariants

When a delegation block is appended, and again when a chain is verified, the
following invariants MUST hold between a block's `scope` and the scope it
inherited (the "parent" scope — the previous block's scope, or the root scope
for Block 1). Any violation is a typed, fail-closed rejection.

1. **Scope subset (permissions).** Every permission string in the child scope
   MUST also appear in the parent scope. A permission the parent never held
   cannot be granted downstream (`ScopeWidened`).

2. **Budget non-increasing.** If the parent has a budget ceiling, the child MUST
   also have one and it MUST be no larger. A child with *no* budget under a
   parent that *has* one is a widening and is rejected. When both budgets are
   set, the `currency` MUST match (`ScopeWidened`).

3. **Expiry non-increasing.** The child's `expires_at` MUST be less than or equal
   to the parent's. Delegation can shorten a token's remaining lifetime, never
   extend it (`ExpiryExtended`).

4. **Depth strictly decreasing, and bounded.** The parent scope's `max_depth`
   MUST be greater than zero for any further delegation to be authorized
   (`DepthExceeded`), and the child's `max_depth` MUST be **strictly** less than
   the parent's (`ScopeWidened` if not). Depth is checked separately from the
   subset test precisely because it must strictly decrease rather than merely
   not-increase.

5. **Mandatory non-empty purpose.** A delegation block's `purpose` MUST be
   non-empty after trimming whitespace (`MissingPurpose`). This is what makes
   the chain useful for *attribution* — why authority flowed — and not merely
   for authentication.

> **Note on terminology.** IndexOne's mandatory per-hop field is named
> `purpose`. The closest prior art, AIP, names the semantically-equivalent
> mandatory per-hop field `context` (see §8 and
> `docs/RESEARCH_VERIFICATION.md §1`); an empty value is rejected in both.

---

## 5. The Witness — Append-Only Merkle Transparency Log

The witness is the headline seam. A signed chain proves what it *contains* is
authentic; it says nothing about what was silently omitted. You cannot detect
the absence of an action by reading a log that does not contain it — a
theoretical boundary, not a bug. The witness is the shared log that makes the
absence provable.

### 5.1. Action receipts

Each action emits an `ActionReceipt` committing to:

- `chain_digest` — the delegation chain the action ran under (`Chain::digest`),
- `action_digest` — a digest of the action itself (request / params / outcome;
  caller-defined),
- `prev_root` — the Merkle root the receipt was appended on top of, chaining
  receipts so that a rewrite of history is detectable.

Callers SHOULD construct a receipt with `prev_root = witness.root()` *before*
appending it, so receipts chain to the prior head.

### 5.2. Append, root, inclusion

The witness is an append-only Merkle tree over receipt leaves. `append` returns
the new leaf's index; `root` returns the current Merkle root — the value
receipts and attestations commit to; appending always changes the root.

`inclusion_proof(index)` returns an `InclusionProof { leaf_index, tree_size,
path }`, where `path` is a leaf-up sequence of `PathStep { sibling,
sibling_is_left }` audit-path entries. `verify_inclusion(receipt, proof, root)`
recomputes the leaf hash and folds the siblings up the path, accepting only if
the result equals `root`. It is pure and stateless — a verifier checks inclusion
without touching the witness's storage — and returns `false` (fail closed) on any
mismatch.

**Omission detection.** An action that was never appended has no inclusion proof
that folds to the honest current root. Even reusing a real proof structure
borrowed from another leaf, an omitted receipt will not reconstruct the root.
This is what turns omission from a matter of trust into a detectable property.

### 5.3. Consistency proofs and equivocation detection

`consistency_proof(old_size, new_size)` produces an RFC 6962 §2.1.2 proof that
the size-`old_size` tree is a prefix of the current size-`new_size` tree, where
`new_size` MUST equal the current log length. The generator fails closed
(returns `None`) unless `old_size ≤ new_size == len`.

`verify_consistency(old_root, new_root, proof, old_size, new_size)` returns
`true` only if the proof reconstructs **both** roots. It fails closed on every
malformed, short, or over-long input, and it handles the boundary cases
explicitly: equal sizes require an empty proof and equal roots; `old_size == 0`
(the empty tree, a prefix of every tree) requires an empty proof; a non-empty
proof in either boundary case is rejected.

**Equivocation / no forked history.** A log that rewrote or reordered any leaf
below `old_size` cannot produce a proof that regenerates the genuine `old_root`.
So a forked log — one that showed one history to an early observer and a
different history later — cannot prove consistency against the honest earlier
root, and the fork is caught.

> **Implementation note.** The consistency- and inclusion-proof machinery is
> implemented and tested (all prefix pairs up to size 10; rewritten-history
> rejection). The **gossip transport** that distributes signed tree heads so
> that independent observers actually compare roots is a documented `TODO` in
> `core/witness` — it is the other half of equivocation detection and is not yet
> built. In `core/verifier`, non-equivocation is enforced by comparing the
> attested root to a caller-supplied `trusted_root` that stands in for the
> gossip-agreed value (§7).

---

## 6. Independent Completion Attestation

AIP's completion block is self-reported by default: the very agent whose work is
being judged signs "done." That is marking your own homework, and it is the
seam. IndexOne replaces it with a `CompletionAttestation` signed by *someone
other than the executing agent*.

### 6.1. Attestation contents

A `CompletionAttestation` binds:

- `chain_digest` — the delegation chain the action ran under,
- `requested_action_digest` — a digest of what was requested,
- `outcome_digest` — a digest of what the attester observed actually happened,
- `witnessed_root` — the witness Merkle root this attestation commits to,
- `inclusion` — a proof that the action's receipt is included under
  `witnessed_root`,
- `attester` / `attester_key` — who is attesting (MUST NOT be the executing
  agent),
- `role` — which independence flow this represents (signed, so it cannot be
  relabelled after the fact),
- `signature` — the attester's signature over all of the above.

### 6.2. Independence flows

`AttesterRole` records which of the two independence flows an attestation
represents:

- **`CounterSigned`** — the immediate delegator (one hop up the chain)
  counter-signs the executor's completion. Independent of the executor, though
  part of the delegation chain.
- **`ThirdParty`** — an external party not in the delegation chain (a notary /
  auditor) attests.

### 6.3. Verification and why self-report is rejected

`CompletionAttestation::verify(executor_key)` checks (a) that the attester key
is **not** the executor key — otherwise `NotIndependent` — and (b) that the
signature is genuinely the named attester's over the bound payload — otherwise
`SignatureInvalid`. It fails closed. Cross-checks of the outcome and inclusion
against the chain and the witnessed root are the composed verifier's
responsibility (§7), not this method's.

Self-report is rejected because a signature by the executor over its own "done"
adds no independent evidence: the party with the incentive to misreport is the
same party vouching. The independence check is the crypto-enforceable core of
"honestly reported" — it proves *who* signed and *that it was not the executor*.
It does **not** prove the outcome is physically true (see §8.1).

### 6.4. Threshold (k-of-n) attestation

`ThresholdAttestation { attestations, threshold }` raises the bar past a single
counter-signer: completion holds only if at least `threshold` **distinct,
independent** attesters each vouch for the **same** action. `verify(executor_key)`
enforces, failing closed on the first violation:

1. **Consistent binding.** Every attestation MUST bind the same `(chain_digest,
   requested_action_digest, outcome_digest, witnessed_root)` tuple — otherwise
   they are not about one action (`InconsistentBinding`).
2. **Distinct attesters.** No two attestations may share an attester key; a
   duplicate is rejected outright, never silently deduplicated
   (`DuplicateAttester`).
3. **Enough independent, valid signatures.** At least `threshold` attestations
   MUST individually verify — each independent of the executor and correctly
   signed. An executor self-report or a bad signature simply does not count
   toward the threshold (`NotEnoughIndependentAttestations { have, need }`).

This means no lone attester's word decides completion, and a single compromised
attester cannot fabricate it.

---

## 7. The `verify()` Algorithm

`core/verifier` composes the layers into a single fail-closed `verify(action,
root_key, trusted_root, policy)` over a `VerifiableAction { chain,
action_receipt, completion }`. The `policy` (`VerifyPolicy`) is **verifier-set**,
not presenter-derived: it names which attester identities count as independent
(so the presenter cannot pick the weakest bar or pass off a throwaway key). It
returns the effective (narrowest) `Scope` the final hop is authorized for, or a
typed `VerifyError` naming the exact property that failed.

The seven conceptual steps (numbered per CLAUDE.md §6; the executor's evaluation
order is noted where it differs, chosen so a forged-root proof cannot slip
through against its own private root):

1. **Verify every delegation-block signature.** Delegated to
   `Chain::verify(root_key)`: the root key must match the trust anchor, the root
   signature must verify, and every block's signature must verify under its
   `from_key`.

2. **Confirm monotonic attenuation.** Also inside `Chain::verify`: cryptographic
   hop-to-hop continuity (`from_key` = predecessor's `to_key`; `from` =
   predecessor's `to`), intact hash links, non-empty purpose, and all four
   attenuation invariants of §4. A failure here surfaces as `VerifyError::Chain`
   wrapping the specific `ChainError`.

3. **Bind the action to the chain.** The `action_receipt.chain_digest` and the
   `completion.chain_digest` MUST both equal `chain.digest()` — otherwise
   `ChainBindingMismatch`. This ties the receipt and the attestation to *this*
   authority, not some other chain.

4. **Verify an inclusion proof against a witnessed root (completeness).** The
   receipt MUST be provably included under the witnessed root via
   `verify_inclusion`. No inclusion proof ⇒ `Omission` — the headline property.
   `verify_inclusion` rejects a malformed or oversized proof (`leaf_index >=
   tree_size`, or `path.len() > MAX_PROOF_PATH`) *before* folding, so an
   attacker-padded proof cannot burn CPU/memory. The receipt carries a
   per-invocation `nonce`, so two byte-identical actions do not share a leaf.

5. **Verify independent completion, anchored identity, and digest match.** The
   completion MUST: (a) verify against the executor key (not self-reported +
   valid signature); (b) be **anchored to an identity the verifier trusts** for
   its role — a `ThirdParty` attester's key MUST be in `policy.trusted_attesters`,
   a `CounterSigned` attester's key MUST be a real delegator in the chain —
   otherwise `AttesterNotAnchored`; and (c) have both `requested_action_digest`
   and `outcome_digest` equal the receipt's `action_digest` — otherwise
   `RequestedActionMismatch` / `OutcomeMismatch`. Part (b) is what makes
   "independent" mean *a trusted party*, not merely *a key that isn't the
   executor* (a throwaway key would otherwise attest the executor's own work).

6. **Cross-check the root against the gossip-trusted root (non-equivocation).**
   The `completion.witnessed_root` MUST equal the caller-supplied
   `trusted_root` — otherwise `Equivocation`. *Executed before step 4* so that an
   inclusion proof cannot be validated against a forged private root.

7. **Fail closed on any unresolved step.** There is no default-accept path; every
   branch either advances to the next check or returns a typed `VerifyError`. On
   success, the effective narrowest scope is returned.

The Day-12 kill test (CLAUDE.md §9) is mechanized in this crate's tests: an
all-valid-signatures chain whose action was **omitted** from the witness, or
whose completion was **self-reported**, returns INVALID here even though the
chain alone verifies.

---

## 8. Security Considerations

### 8.1. Scope boundary (read this twice)

This is the most important section. IndexOne **can** cryptographically prove:

- every delegation block is authentic and signed;
- authority narrowed monotonically across hops (never widened);
- the chain is **complete** — no hop silently omitted — *provided the action was
  committed to a witnessed transparency root*;
- the log is **non-equivocating** — no forked views — *via consistency proofs and
  gossip*;
- completion was **independently attested** rather than self-reported — *as
  strong as the attester's visibility*;
- which principals are in the chain and their delegation relationships.

IndexOne **cannot** prove, and this document does not claim:

- **That a recorded action digest corresponds to what physically happened.** A
  witness anchors *what was reported, not ground truth.* If an agent controls its
  own execution environment and commits a truthful digest of a *fabricated*
  action, the log faithfully anchors a lie. Independent attestation raises the
  bar to "as strong as the attester's visibility into ground truth" — it does not
  reach certainty.
- **Semantic intent match** ("the agent's purpose was legitimate") as a pure
  cryptographic guarantee. A *subset* of intent violations is reduced to
  detectable omissions; semantic intent is not solved.
- **Anything stronger than the weakest independent attester in the chain.**

The honest one-sentence scope: *IndexOne proves the delegation chain is complete,
monotonic, cross-org-attributable, and non-equivocating, and that completion was
independently attested rather than self-reported — and the strength of the
attestation is exactly the strength of the attester's visibility into ground
truth.* Sourcing cheap, high-visibility independent attestation is the core
research risk, not a solved problem.

### 8.2. Algorithm agility and post-quantum posture

Because each block carries its own `Algorithm` tag (§2.4), a chain can mix
classical and post-quantum blocks and migrate to ML-DSA-87 or hybrid signatures
without a flag day or re-issuing history. The `Hybrid` scheme is a deliberate
hedge: a hybrid block stays safe both the day a large quantum computer arrives
*and* the day a lattice break is announced, because forging it requires breaking
both schemes simultaneously. Verification fails closed on any structural
ambiguity (§2.4.1), so downgrade-by-malformation is a rejection, not a bypass.

### 8.3. Revocation (short-TTL + transparency log)

Chain verification is local, stateless, and per-request; "has this been revoked
since issuance" is inherently a *freshness* question and is the one check that
cannot be purely local. `core/revocation` isolates it with two complementary
mechanisms so that revocation survives partial-chain compromise:

- **Short-TTL** (`ShortTtlChecker`). Every block is valid only within a short
  freshness window, so a stale-but-unrevoked token stops working on its own with
  no lookup. Fail-closed by default: a block whose issuance the checker never saw
  cannot be vouched fresh and is treated as stale.
- **Out-of-chain transparency log** (`TransparencyLogChecker`). A published
  revocation is checkable via an append-only set keyed by a **keyless,
  deterministic** `RevocationId = blake3(DOMAIN || signature.bytes)`. Because the
  id derives from the block's *signature bytes* — which already travel in the
  token — anyone can compute it without the signing key, and revoking one hop
  cannot be suppressed by compromising another hop's key. The log is append-only
  by construction: there is deliberately no removal API, because "un-revoking" by
  dropping an entry is exactly the suppression a partial-compromise attacker
  would attempt.

A `CompositeChecker` consults both: a definite revocation from *any* checker is
authoritative and is never masked by another checker that could not answer; only
if no checker reports a revocation and at least one could not determine status
does the composite fail closed with the undeterminable error. `RevocationError`
keeps "definitely revoked / stale" strictly distinct from "couldn't determine"
(`LogUnreachable`), and callers fail closed on both.

> **Implementation note.** The in-memory cores of both checkers are implemented
> and tested. The **remote** transparency-log fetch and the inclusion /
> non-inclusion proof machinery over a remote log are documented `TODO`s; a
> checker pointed at a remote URL it has not synced fails closed with
> `LogUnreachable` rather than silently reporting "live."

### 8.4. Fail-closed discipline

Every verification path in every crate fails closed with a typed error naming
the violated property: `ChainError`, `CryptoError`, `VerifyError`,
`AttestationError` / `ThresholdError`, and `RevocationError`. The crypto layer's
`Err` vs `Ok(false)` distinction is load-bearing — "could not attempt
verification" is never silently treated as "valid." Implementations MUST NOT add
a default-accept branch to any of these paths.

---

## 9. Relationship to Prior Work

Citations here follow `docs/RESEARCH_VERIFICATION.md`; corrections found in that
primary-source pass are applied, and fabrications it identifies are not repeated.

- **AIP (Agent Identity Protocol / IBCT), arXiv 2603.24775** — the closest prior
  art and the source of the block structure IndexOne adapts (Block 0 authority +
  Block N delegation). It is a **single-author, non-peer-reviewed preprint plus an
  individual, non-adopted Internet-Draft**; all its benchmarks are self-reported
  and should be cited as such. AIP's mandatory per-hop field is named **`context`**
  (IndexOne calls the semantically-equivalent field `purpose`). AIP's **only**
  explicitly admitted completion gap is **self-reported completion** — it names
  counter-signing / third-party attestation as unbuilt in v1, which is exactly the
  gap `core/attestation` closes. The words "omission," "completeness," and
  "equivocation" do **not** appear in the AIP paper; those are IndexOne's threat
  labels, presented as gaps we identify, not as AIP's admitted non-goals.

- **Biscuit** — the public-key (Ed25519) capability-token primitive with offline
  attenuation and signature-derived revocation ids. IndexOne's chain is built in
  this model (append-only, blocks only narrow) rather than reinventing it.
  Biscuit's "sub-1 ms verification" is the creator's figure (originally stated in
  a 2022 podcast), not an independently reproduced spec guarantee.

- **Macaroons (NDSS'14)** — the origin of offline attenuation. Its cautionary
  lesson is the shared-secret HMAC chaining flaw: verification needs the symmetric
  root key, so verify-capability equals forge-capability. IndexOne (via the
  Biscuit model) uses per-block public-key signatures precisely to avoid that
  flaw. The Macaroons paper itself proposes the public-key variant.

- **RFC 6962 (Certificate Transparency)** — the discipline `core/witness`
  implements directly: §2.1.1 inclusion proofs and §2.1.2 consistency proofs, with
  domain-separated leaf (`0x00`) and node (`0x01`) hashing. Gossip is named in
  RFC 6962 but deferred to a separate document; IndexOne's gossip transport is
  likewise not yet built (§5.3).

- **SCITT (`draft-ietf-scitt-architecture`)** — the transparency-service model
  (Transparency Service / Signed Statement / Receipt / Registration Policy) that
  IndexOne's witness is designed to fit. The agent-delegation drafts that address
  completeness (DRP; the EMILIA / cross-org-mapping line) defer it to an external,
  still-unbuilt SCITT-style cross-org transparency log — the layer IndexOne
  builds. (Not "every draft punts to a log": APS mostly self-solves via internal
  cascade records, and HDP leaves completeness to application-layer audit.)

- **IETF WIMSE (`draft-ietf-wimse-arch`), §3.3.8** — recognizes the multi-hop
  cross-org risk in a credible body's own words: "a chain of AI-to-AI
  interactions could unintentionally extend authority far beyond what was
  originally granted … each hop … MUST explicitly scope and re-bind the security
  context." WIMSE specifies only **per-hop re-binding**, leaving verifiable
  end-to-end provenance to implementations — which is what IndexOne provides.
  (There is no WIMSE "§3.3.9" and no "R1–R9 problem statement"; those were
  fabrications corrected in `docs/RESEARCH_VERIFICATION.md` and are not repeated
  here. The related material is §3.3.8 with §3.3.4 "Delegation and
  Impersonation.")

### 9.1. Relationship to the payment rails (AP2)

IndexOne sits **on top of** the agent-payment rails, not against them. AP2
**does** support delegation and multi-step delegation chains (SD-JWT `cnf`
key-binding, a "Trusted Agent Provider" model) — the earlier "binds to a single
user, not a chain" framing was wrong and is not asserted here. AP2 produces an
audit trail but has **no cross-org transparency mechanism to make omission
detectable and no independent completion attestation**; IndexOne's seam is to
make AP2-style chains' attribution tamper-evident and dispute-defensible over the
top.

---

## 10. IANA Considerations

This document has no IANA actions.

## 11. References

Informative references, as reproduced in `docs/RESEARCH_VERIFICATION.md`:

- RFC 2119 / RFC 8174 — Requirement key words.
- RFC 6962 — Certificate Transparency (inclusion §2.1.1, consistency §2.1.2).
- RFC 8032 — EdDSA (Ed25519).
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Standard).
- `draft-ietf-scitt-architecture` — SCITT Architecture.
- `draft-ietf-wimse-arch` — WIMSE Architecture (§3.3.8, §3.3.4).
- arXiv 2603.24775 — AIP: Agent Identity Protocol (single-author preprint).
- Birgisson et al., NDSS 2014 — Macaroons.
- Eclipse Biscuit — `biscuit-auth/biscuit`.
</content>
</invoke>
