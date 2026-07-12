# indexone-verifier-wasm

The IndexOne composed `verify()`, compiled to **WebAssembly** — the real Rust
verifier running in a browser or at the edge. This is the concrete form of a
marketable wedge (CLAUDE.md §8): the proof lives in the token and is checked
**locally, offline, in microseconds — no chain, no registry lookup, no callback**.
A browser, a Cloudflare Worker, or an edge function can reject an omitted or
self-reported cross-org action without talking to us at all.

`verify_action(inputJson)` takes the same JSON an SDK builds for the
`indexone-cli` `composed_verify` command and returns
`{"ok":true,"effective_scope":…}` or `{"ok":false,"error":…}` — fail closed.

## Build

```bash
wasm-pack build --target web    --release   # browser (ESM)  -> pkg/
wasm-pack build --target nodejs --release   # Node           -> pkg-node/
cargo build --target wasm32-unknown-unknown --release   # raw .wasm, no bindgen
```

(Or `make wasm` from the repo root.) The verifier itself uses no randomness;
`getrandom`'s browser backend is selected only so the crypto crate's keygen
symbols link on `wasm32-unknown-unknown`.

## Browser demo

After `wasm-pack build --target web`, serve this directory and open
`demo/index.html` — paste a `composed_verify` request and verify it entirely in
the page. (Any static server, e.g. `python3 -m http.server`.)

## Proven end to end

`cargo test` covers the fail-closed JSON boundary natively. The full Day-12
before/after has been run **through the wasm** under Node: a real cross-org
chain → witnessed action → independent attestation → `verify_action` returns
`ok:true` for the honest action and `ok:false` (`omission`) for an action the
witness never recorded — the same verdicts the native verifier gives, now in a
JS engine.

## Honesty (CLAUDE.md §4)

A witness anchors what was reported, not ground truth; local verification proves
the token's properties (completeness, independent attestation, non-equivocation),
not that the world matched. The `.wasm` is a pure function of its input — no
network, no side channel.
