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

## v2 (documented destination, not built)

When the threat model demands defending against a *misbehaving* operator
per-request (not just an unreliable one): a **sparse Merkle tree keyed directly by
the 32-byte `RevocationId`** (blake3 already gives a uniform 256-bit path) — leaf =
`H(metadata)` if revoked, else the empty-leaf constant; non-revocation proof =
audit path to the empty leaf against a signed root (~few hundred bytes after
default-sibling compression). Then **log-back it** (Trillian VLDM): publish
successive signed roots as entries in the **RFC 6962 log we already run**
(`core/witness` + `services/witness`), so consistency/append-only — the one thing
a bare map lacks — comes free, and rollback/equivocation becomes cryptographically
detectable.

## Sources

Laurie & Kasper, *Revocation Transparency*; Dahlberg/Pulls, *Efficient Sparse
Merkle Trees* (ePrint 2016/683); Haider, *Compact Sparse Merkle Trees* (ePrint
2018/955); Google Trillian *Verifiable Data Structures*; RFC 9162 (CT v2);
Larisch et al., *CRLite* (IEEE S&P 2017) + Mozilla Clubcard (2025); Smith et al.,
*Let's Revoke* (NDSS 2020); `draft-ietf-scitt-architecture-22`.
