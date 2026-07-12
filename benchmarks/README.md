# benchmarks

Verification-latency and per-hop-size benchmarks for index-one, run via
[criterion](https://github.com/bheisler/criterion.rs).

```
cargo bench --manifest-path benchmarks/Cargo.toml
```

## Targets

Matching AIP's published numbers (our closest prior art -- see
`/docs/REFERENCE.md`):

- **Verification latency**: sub-millisecond, per chain, regardless of hop
  count in the ranges we expect (single digits to low tens of hops).
- **Per-hop size**: ~340-380 bytes per delegation block on the wire.

## Status

These benches currently measure **placeholders**, not real logic:

- `benches/verify_latency.rs` benchmarks a placeholder walk over a chain's
  blocks, not `indexone_chain::Chain::verify` (which is an unimplemented
  stub, see `/core/chain/src/lib.rs`).
- `benches/hop_size.rs` measures a JSON-encoded `DelegationBlock` with a
  zeroed placeholder signature. JSON is not the intended wire encoding, and
  the signature isn't real yet, so treat the printed byte count as a
  structural placeholder, not a real measurement against the 340-380 byte
  target.

Both are wired up (via path dependencies) against the real `indexone-chain`
/ `indexone-crypto` types, so once those crates have real implementations,
swap the placeholder calls for real ones and the harness shape/targets
above stay valid.
