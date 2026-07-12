# /fuzz — libFuzzer campaign

The **CI-gated** invariant coverage lives in each core crate's
`tests/proptest_soundness.rs` (property tests, run by `cargo test`). This
directory is the **deeper, on-demand campaign** over the raw
serde-deserialize-then-verify surface a remote peer actually feeds — the paths
where a malformed byte stream could panic (a DoS) or, worse, verify.

Targets:

- `fuzz_chain_verify` — arbitrary bytes → `Chain` → `verify()`
- `fuzz_receipt` — arbitrary bytes → `ActionReceipt` → `canonical_bytes()`
- `fuzz_attestation_verify` — arbitrary bytes → `CompletionAttestation` → `verify()`
- `fuzz_inclusion_proof` — arbitrary bytes → `InclusionProof` → `verify_inclusion()`

## Run

```bash
rustup toolchain install nightly && cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_chain_verify --fuzz-dir fuzz -- -max_total_time=300
```

Any crash is written to `fuzz/artifacts/<target>/` and reproduces with
`cargo +nightly fuzz run <target> --fuzz-dir fuzz <artifact>`. CI (`rust-ci.yml`
`fuzz-build`) only *builds* the targets each PR so they can't rot; run the
campaign on a schedule or before a release. The generated corpus/artifacts are
git-ignored.
