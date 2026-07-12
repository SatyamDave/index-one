# Remote revocation transparency

An append-only Merkle log (the witness) proves **inclusion** and **consistency**
but never **absence**. Yet the verifier's hot path is the *negative* query —
"prove this hop is **not** revoked". This note records how we answer that, from
a primary-source survey (see the four mechanisms below), and what we ship.

## The four mechanisms (surveyed)

| Mechanism | Proves non-inclusion? | Trust model | Cost |
|---|---|---|---|
| **Sparse / indexed Merkle tree** (Laurie–Kasper *Revocation Transparency*; Trillian Verifiable Map) | ✅ audit path to an *empty* leaf under a signed root | cryptographic for a given root; **no** consistency (equivocation possible) | a map + per-query proof |
| **Log-backed map** (Trillian VLDM; RFC 9162) | ✅ | cryptographic end-to-end vs. a misbehaving operator (map non-inclusion + log consistency) | most machinery |
| **CRLite / CRLSets / Let's-Revoke** | local absence-check against a signed *complete* snapshot (Bloom cascade / bitvector) | signature + freshness + completeness | ship the whole set |
| **SCITT receipts** | ❌ inclusion-only (revocation is explicitly out of scope) | signature, offline-verifiable | — |

## What we ship

**v1: a signed, epoched, complete revocation snapshot** (`SignedRevocationSnapshot`
in `core/revocation`). The operator signs the whole revoked `BTreeSet<RevocationId>`
with a monotonic `epoch` and a `published_at` timestamp; a client checks
membership locally and offline. This is the CRLSet / Let's-Revoke / SCITT trust
template, and it fits IndexOne unusually well:

- The query we need is exactly "prove NOT revoked" → a complete signed set
  answers it by local absence-check, no per-request proof fetch.
- Its trust axis is **signature + freshness**, and freshness is already
  first-class here (the `Clock` trait + `ShortTtlChecker`). The snapshot's
  max-staleness reuses that machinery.
- Our revocation volume is tiny (revoked capability hops, not billions of certs),
  so we ship the exact set — no Bloom/ribbon cascade needed yet.
- `SnapshotChecker` fails closed on: a bad operator signature, an `epoch` older
  than the newest seen (**anti-rollback** — an operator can't quietly un-revoke),
  or a snapshot past the staleness window — each surfaces as `LogUnreachable`
  ("couldn't determine"), distinct from a definite `Revoked`.

**Residual weakness (stated honestly):** a malicious operator *omitting* an entry
is bounded, not eliminated — but the snapshot is signed and gossipable, and
because `RevocationId` is keyless (`blake3(sig)`), any party can recompute ids and
cross-check, so equivocation is **detectable**.

The transport (fetching the snapshot over the network) is injected via the
`SnapshotSource` trait, so `core/revocation` stays synchronous and dependency-light;
the concrete HTTP source lives in a separate crate.

## v2 — sparse Merkle map (built) + log-backing (next)

When the threat model demands defending against a *misbehaving* operator
per-request (not just an unreliable one), the upgrade is a **log-backed sparse
Merkle map**. Two composable pieces, both grounded in the survey below.
**Piece (a) is now built** in `core/revmap`; piece (b) is the remaining step.

**(a) Sparse Merkle map keyed by the 32-byte `RevocationId`** — *implemented in
`core/revmap` (`RevocationMap`, `verify_non_inclusion`): blake3-only, no C deps,
8 adversarial tests incl. forged-proof cross-over and malformed-proof
fail-closed.* blake3 already
gives a uniform 256-bit path, so the id *is* the root-to-leaf direction vector
over a notional 2²⁵⁶-leaf tree. A revoked key's leaf holds a present-value; every
other leaf holds the empty-leaf constant. A **non-revocation proof** is an audit
path terminating in the empty leaf (or, in the compact variant, in a *different*
key `k'≠k` at the slot), against a signed root. The 2²⁵⁶ tree is tractable via
the default-subtree trick — one precomputed empty-hash per level, `Dᵢ =
H(Dᵢ₋₁‖Dᵢ₋₁)` — so only the ~`log₂ n` non-default siblings plus a level bitmap
travel in the proof: **~0.5–0.8 KB** for 10⁴–10⁶ entries (vs. 8 KB uncompressed).

*Reuse evaluated, then built (no-bloat).* The survey shortlisted three maintained
crates with native non-inclusion proofs — `sparse-merkle-tree` (nervosnetwork/jjyr),
`jmt` (Penumbra), `monotree`. We probed the top pick: its non-inclusion/forged-proof
API is exactly right and Namada-hardened, **but `blake2b-rs` is a non-optional
dependency** (not feature-gated), so reusing it forces a C-compiled blake2b lib
into our deliberately lean, blake3-only, C-dep-free core even though we never call
it. One-line reason to build instead: *the only suitable crate hard-depends on a
C hasher that violates the core's blake3-only / audit-minimal invariant, and this
is load-bearing crypto we must own per the Day-12 gate.* `core/revmap` is ~1 file,
depends only on blake3 + serde, and passes the same adversarial forged-proof test
the crate does. (`ct-merkle`/`rs_merkle` were the wrong tool regardless —
append-only/plain trees, no absence proofs.)

**(b) Log-back it (Trillian VLDM pattern).** A bare signed map has no native
append-only check, so it can silently **equivocate** (different root to different
observers) or **roll back** (un-revoke by omitting an entry) — the exact holes v1
mitigates only by monotonic epoch + gossip. The fix: commit each epoch's map root
as **one leaf in the RFC 6962 log we already run** (`core/witness` +
`services/witness`), with the leaf payload `{epoch, map_root, log_STH_it_was_built_over}`.
A client then verifies **three** proofs, reusing the log's existing APIs
unchanged: (1) map (non-)inclusion of the id against `map_root`; (2) log inclusion
that the `map_root` leaf is in the log; (3) log consistency from its last-seen STH
→ current STH. Proof (2) kills equivocation (a contradictory root is a second,
detectable leaf); proof (3) kills silent rollback (the epoch sequence can only
grow). Added surface is small: one map + the "root → log leaf" rule; no new log
proof types.

**Honest boundary (unchanged from v1's spirit).** Log-backing buys
*detectability* of root-equivocation and rollback — **not completeness**. An
operator that simply never inserts a revocation produces a perfectly valid,
consistent map; catching that still needs an out-of-band monitor comparing the
map against revocation intent (as CT needs domain monitors). And detection, not
prevention, is the CT-style guarantee: it relies on STH gossip / the witness
quorum we already run, plus a client freshness policy (insist on a recent,
consistency-checked epoch).

**v2 crypto pitfalls to encode (from the survey).** Leaf-vs-internal domain
separation (RFC 6962's `0x00`/`0x01` prefixing, or blake3 `derive_key` per node
type) to stop second-preimage leaf/node confusion; the empty-leaf constant must
be a signed parameter both sides agree on and no real leaf can collide with; in
the compact variant the verifier **must** check `k'≠k`; and the default-sibling
bitmap must be authenticated by reconstructing `Dᵢ` locally, never trusting
attacker-supplied "default" positions.

## Sources

Laurie & Kasper, *Revocation Transparency* (2²⁵⁶-leaf SMT, empty-hash absence
proofs); Dahlberg/Pulls/Peeters, *Efficient Sparse Merkle Trees* (ePrint
2016/683 — compressed (non-)membership proofs, <4 ms); Haider, *Compact Sparse
Merkle Trees* (ePrint 2018/955); iden3/Baylina & Bellés, *Sparse Merkle Trees*
(leaf = `H(1‖k‖v)` domain separation); Google Trillian *Verifiable Data
Structures* (log-derived map, "signed map checkpoint incorporates a log
checkpoint"); RFC 9162 (CT v2 — log-only, no map/revocation); Larisch et al.,
*CRLite* (IEEE S&P 2017) + Mozilla Clubcard (2025); Smith et al., *Let's Revoke*
(NDSS 2020); `draft-ietf-scitt-architecture-22` (revocation & non-inclusion
explicitly out of scope). Rust SMT crates surveyed: `sparse-merkle-tree`
(nervosnetwork), `jmt` (Penumbra), `monotree`.
