# Benchmarks — real `verify()`

> **Directive 5 (reproduce-before-quote).** Every number here was produced by the
> committed benches in `/benchmarks` against the real `indexone-chain::Chain::verify`
> — not a placeholder. Re-run them yourself before quoting; they are
> **machine-specific** and will differ on your hardware.

## Reproduce

```bash
cargo bench --manifest-path benchmarks/Cargo.toml
```

- `benches/verify_latency.rs` — full `Chain::verify(&root_key)` over chains of
  1/3/5/10 real hops (Ed25519 signature check + blake3 hash-link check + the
  attenuation invariants, per hop).
- `benches/hop_size.rs` — serialized size of one real, signed `DelegationBlock`.

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
| Serialized `DelegationBlock` | **997 bytes** (JSON) |
| Serialize time | ~854 ns |

## Reading the numbers honestly

- **"Microseconds, local, no callback" holds.** A full cross-org chain verifies
  in **tens to a couple hundred microseconds** — 3 hops in ~95 µs, and even 10
  hops stays sub-millisecond (~263 µs). Verification is a pure function of the
  token's bytes: **no network call, no registry lookup, no chain/gas.** That is
  the marketable contrast with on-chain registries — but quote it as "~95 µs for
  a 3-hop chain on an M4 Pro," not a bare "microseconds."
- **Latency scales linearly** at ~24 µs/hop — dominated by one Ed25519
  verification per block. Expected and healthy.
- **The 997-byte hop size is JSON, not the target.** It is larger than AIP's
  self-reported ~340–380 B/hop because (a) we serialize to JSON (the canonical
  bytes we sign over today — RFC 8785 JCS / a compact binary encoding is the
  target, see `core/*` TODOs) and (b) every block embeds the signer's public key
  (Ed25519 pubkey 32 B + signature 64 B + field names). A compact binary
  encoding will shrink this substantially; until it lands, do **not** quote a
  hop-size number as competitive.
- **Not yet measured:** witness inclusion/consistency-proof verification and the
  full composed `verifier::verify` (chain + witness + attestation). Add benches
  for those before quoting an end-to-end "verify one action" latency.

## What this does *not* claim

These are single-machine microbenchmarks of the happy-path verify. They are not
a throughput/latency SLO, not measured under load, and not independently
reproduced. Treat them as "the primitive is fast and local," not as a
production performance guarantee.
