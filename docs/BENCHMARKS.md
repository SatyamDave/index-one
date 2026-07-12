# Benchmarks — real `verify()`

> **Directive 5 (reproduce-before-quote).** Every number here was produced by the
> committed benches in `/benchmarks` against the real code — `Chain::verify`, the
> composed `indexone_verifier::verify()`, and the `indexone-witness` log
> operations — not placeholders. Re-run them yourself before quoting; they are
> **machine-specific and thermal-state-specific** and will differ on your
> hardware (see the note under "Composed `verify()` latency").

## Reproduce

```bash
cargo bench --manifest-path benchmarks/Cargo.toml
```

- `benches/verify_latency.rs` — full `Chain::verify(&root_key)` over chains of
  1/3/5/10 real hops (Ed25519 signature check + blake3 hash-link check + the
  attenuation invariants, per hop).
- `benches/hop_size.rs` — serialized size of one real, signed `DelegationBlock`.
- `benches/composed_verify.rs` — the full composed `indexone_verifier::verify()`
  (chain + witness inclusion proof + non-equivocation + independent completion
  attestation + outcome/action-digest gates), and `verify_threshold` (k-of-n),
  over 1/3/5/10 hops and k = 1/2/3.
- `benches/witness_ops.rs` — the `indexone-witness` hot paths (append, inclusion
  and consistency proof generation + verification, signed tree heads) over log
  sizes S = 100 / 1,000 / 10,000.

## Environment (this run)

| | |
|---|---|
| CPU | Apple M4 Pro (`arm64` / `aarch64-apple-darwin`) |
| Build | `cargo bench` release profile, criterion 0.5 |
| Crypto | real Ed25519 (`ed25519-dalek` 2), blake3, deterministic keys from seed |
| Date | 2026-07-12 |

## Results

**Verification latency** (criterion median; `[low  median  high]`):

| Hops | `verify()` latency | Marginal / hop |
|---:|---|---|
| 1  | **47.6 µs**  `[47.1  47.6  48.3]` | — |
| 3  | **95.5 µs**  `[95.4  95.5  95.6]` | ~24 µs |
| 5  | **142.6 µs** `[142.5 142.6 142.7]` | ~24 µs |
| 10 | **263.1 µs** `[262.8 263.1 263.4]` | ~24 µs |

**Per-hop wire size** (current encoding):

| Metric | Value |
|---|---|
| Serialized `DelegationBlock` | **999 bytes** (JSON) |
| Serialize time | ~842 ns |

### Composed `verify()` latency (chain + witness inclusion + independent attestation)

`benches/composed_verify.rs` times the full `indexone_verifier::verify()` — every
gate: chain signatures + attenuation, witness inclusion proof, non-equivocation,
independent completion attestation, and outcome/action-digest consistency.

> **Thermal note (read before quoting absolutes).** This section was measured in
> a later, sustained-load session that ran **~2× hotter** than the table above:
> its same-run `Chain::verify` baseline reads ~89 µs/1-hop vs the ~48 µs table
> above — **same code, more machine load/heat.** So quote the **composed − chain
> delta** (load-independent), not the raw composed µs, unless you re-measure on a
> cool machine.

| Hops | `Chain::verify` (same run) | composed `verify()` | composed overhead |
|---:|---|---|---|
| 1  | 89.3 µs  | **160.0 µs** | +70.7 µs (+79%) |
| 3  | 189.7 µs | **294.1 µs** | +104 µs (+55%) |
| 5  | 292.4 µs | **431.3 µs** | +139 µs (+48%) |
| 10 | 549.0 µs | **776.5 µs** | +228 µs (+41%) |

The overhead is a **~70 µs floor** — one independent-attestation signature
verification plus the inclusion-proof fold — that grows slowly with hops; as a
*fraction* it shrinks (79% → 41%) because per-hop chain-signature work dominates
at depth. Still sub-millisecond through 10 hops, still no network call.

**k-of-n threshold verify** (`verify_threshold`, 3-hop chain, k distinct
independent attesters):

| k | latency | per additional attester |
|---:|---|---|
| 1 | 298.0 µs | — |
| 2 | 342.8 µs | +44.9 µs |
| 3 | 386.5 µs | +43.6 µs |

Each additional independent attester is a clean **~+44 µs** (one more Ed25519
signature-verify + inclusion check) — linear, no surprises.

### Witness operations (`indexone-witness`)

`benches/witness_ops.rs`, criterion medians across log size S — **after** the
interior-node memoization (see below):

| op | S=100 | S=1,000 | S=10,000 |
|---|---|---|---|
| `append` (one more leaf) | 8.5 µs | 9.2 µs | 13.0 µs |
| `inclusion_proof` (generate) | 278 ns | 777 ns | 720 ns |
| `verify_inclusion` | 8.88 µs | 9.35 µs | 9.98 µs |
| `consistency_proof` (generate) | 267 ns | 758 ns | 721 ns |
| `verify_consistency` | 957 ns | 1.56 µs | 1.80 µs |
| `signed_head` (STH) | 11.7 µs | 12.0 µs | 11.8 µs |
| `verify_signed_head` | 23.4 µs | 23.3 µs | 23.4 µs |

**Scaling — now O(log n), was O(n).** Both the *verify* and *prove* paths are now
flat in log size. Earlier, proof/STH *generation* scaled ~O(S) because the tree
recomputed subtree roots (and re-hashed the ~1 KB receipts) on every call —
~3.9 ms to generate a proof at 10k leaves. The witness now **memoizes the roots
of perfect, aligned subtrees** (immutable in an append-only log, so the cache
needs no invalidation) and caches leaf hashes, so generation is O(log n):

| generate @ 10k leaves | before | after | speedup |
|---|---|---|---|
| `inclusion_proof` | 3.92 ms | 720 ns | **~5,400×** |
| `consistency_proof` | 3.85 ms | 721 ns | **~5,300×** |
| `signed_head` | 3.87 ms | 11.8 µs | **~330×** |
| `append` | 144 µs | 13.0 µs | **~11×** |

The output is **byte-identical** to the naive RFC 6962 recomputation — proven by
an exhaustive differential oracle in the crate's tests (every root for sizes
0–300, every inclusion path for all sizes/indices to 200, every consistency proof
for all prefix pairs to 150). So a witness server can now generate proofs in
sub-microsecond time at 10k+ leaves with no change to any root, proof, or signed
tree head a relying party verifies.

## Reading the numbers honestly

- **"Microseconds, local, no callback" holds.** A full cross-org chain verifies
  in **tens to a couple hundred microseconds** — 3 hops in ~95 µs, and even 10
  hops stays sub-millisecond (~263 µs). Verification is a pure function of the
  token's bytes: **no network call, no registry lookup, no chain/gas.** That is
  the marketable contrast with on-chain registries — but quote it as "~95 µs for
  a 3-hop chain on an M4 Pro," not a bare "microseconds."
- **Latency scales linearly** at ~24 µs/hop — dominated by one Ed25519
  verification per block. Expected and healthy.
- **The 999-byte hop size is JSON, not the target.** It is larger than AIP's
  self-reported ~340–380 B/hop because (a) we serialize to JSON (the canonical
  bytes we sign over today — RFC 8785 JCS / a compact binary encoding is the
  target, see `core/*` TODOs) and (b) every block embeds the signer's public key
  (Ed25519 pubkey 32 B + signature 64 B + field names). A compact binary
  encoding will shrink this substantially; until it lands, do **not** quote a
  hop-size number as competitive.
- **Composed `verify()` is what a relying party actually runs**, and it stays
  sub-millisecond through 10 hops — the witness-inclusion + independent-attestation
  layer adds a ~70 µs floor over `Chain::verify` (see the composed table). Quote
  the composed delta, not the raw thermal-loaded absolutes.
- **Witness proof generation and verification are both O(log n) and flat** —
  interior-node memoization landed, so proof/STH generation is sub-microsecond to
  low-µs even at 10k+ leaves (was ~3.9 ms), byte-identical to the naive
  recomputation. The witness server is no longer a scaling bottleneck for proof
  serving.

## What this does *not* claim

These are single-machine microbenchmarks of the happy-path verify. They are not
a throughput/latency SLO, not measured under load, and not independently
reproduced. Treat them as "the primitive is fast and local," not as a
production performance guarantee.
