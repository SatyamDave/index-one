# Verifier Hardening — Adversarial Audit

An adversarial pass (one web/literature agent + one read-only code auditor at
HEAD) against the composed `verify()` (chain + witness + attestation). Each
finding is a concrete break or a cited immunity. This is the "attack a claimed
property" bar from CLAUDE.md §1.2 turned on our own verifier.

Status legend: 🔴 open · 🟢 fixed (with the commit that closed it) · ✅ already immune.

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Sockpuppet key defeats "independent" attestation (Sybil defeats threshold too) | **CRITICAL** | 🟢 |
| 2 | `requested_action_digest` never checked; no action↔purpose binding | HIGH | 🟢 |
| 3 | Presenter-controlled sufficiency; threshold never invoked by `verify()` | MEDIUM | 🟢 (policy) |
| 4 | Unbounded inclusion-/consistency-proof length → DoS | LOW | 🟢 |
| 5 | Cross-binding / receipt-splicing / crypto panics | — | ✅ immune (cited) |
| 6 | Invocation replay: byte-identical actions share a leaf | MEDIUM | 🟢 (nonce) |

## 1 — CRITICAL: sockpuppet attestation

The product thesis is *"completion is independently attested, not self-reported."*
The **only** enforcement was a key inequality: `CompletionAttestation::verify`
returned `NotIndependent` iff `attester_key == executor_key`. The executing agent
generates a fresh keypair `K2`, signs its own completion as some "notary"
principal, and `verify()` accepts it (`K2 ≠ executor_key`, signature valid,
`outcome_digest == receipt.action_digest`, chain + inclusion + root all bind). C
has "independently" attested its own work. The k-of-n path is equally broken: one
actor mints `k` fresh keys and meets any threshold. The kill-test only caught the
naive same-key case.

**Fix:** `verify()` anchors attester *identity*, not just inequality, via a
verifier-set policy: a `ThirdParty` attestation is accepted only if its
`attester_key` is in the caller's trusted-attester set; a `CounterSigned`
attestation only if its key is a real delegator present in the chain (and ≠
executor). Identity is now required, so a throwaway key is rejected.

## 2 — HIGH: `requested_action_digest` unchecked, no action↔purpose binding

CLAUDE.md §6 step 3 promises the action digest is bound to the declared purpose +
chain; the code only bound the chain. `requested_action_digest` was signed but
read nowhere in `verify()`. **Fix:** step 3 now requires
`completion.requested_action_digest == action_receipt.action_digest` (the attested
request must equal the logged action). **Full purpose↔digest binding is now
built:** `indexone_witness::bind_action(purpose, params_digest)` defines
`action_digest` as a domain-separated `blake3(DOMAIN ‖ len(purpose) ‖ purpose ‖
params_digest)`, and `indexone_verifier::verify_action_purpose_binding` /
`verify_with_purpose` require the witnessed digest to equal the binding for the
**final hop's** purpose and the declared params. An action witnessed under a
different purpose (or params) now fails closed with `VerifyError::PurposeMismatch`
— the `action_bound_to_a_different_purpose_is_rejected` test shows base `verify()`
accepting the opaque digest while the binding gate rejects it. Honest scope
(CLAUDE.md §4): binds the digest to the *declared* purpose, not to ground truth.

## 3 — MEDIUM: presenter-controlled sufficiency

`verify()` accepted whatever single `CompletionAttestation` the presenter
supplied; `ThresholdAttestation` was never invoked. **Fix:** the sufficiency bar
is now a `VerifyPolicy` the *verifier* sets (required role + trusted set), not an
artifact-derived value. (Threshold-in-`verify()` as a first-class path remains a
follow-up; the identity anchor already blocks the Sybil route.)

## 4 — LOW: unbounded proof length DoS

`verify_inclusion` folded `proof.path` with no cap. **Fix:** reject before folding
when `leaf_index >= tree_size` or `path.len()` exceeds `⌈log2(tree_size)⌉` (capped
at 64); consistency-proof node count is likewise bounded.

## 5 — IMMUNE (verified, keep the invariants)

Cross-binding (receipt/attestation from another chain), receipt-splicing, and
crypto panics on attacker bytes are all already blocked: `chain_digest` binds
receipt+attestation to `chain.digest()`; inclusion proofs are leaf-specific
(fold-and-compare); `witnessed_root == trusted_root` is checked before inclusion;
signature verification uses guarded `try_into`/`checked_add`, never a slice panic.

## 6 — MEDIUM: invocation replay

Two byte-identical actions on the same chain (e.g. two identical $40 charges)
produce identical receipts → the same leaf, so an attestation for one is
replayable for the other. **Fix:** `ActionReceipt` carries an invocation `nonce`,
making each invocation's leaf unique; an attestation (bound to a specific leaf via
its signed inclusion proof) then covers exactly one invocation.
