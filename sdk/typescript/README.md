# IndexOne TypeScript SDK

Thin bindings over the IndexOne Rust core — **no crypto is reimplemented in
TypeScript**. Every `issue` / `attenuate` / `verify` call shells out to the
`indexone-cli` sidecar (built from `core/cli`), which runs the real
`indexone-chain` + `indexone-crypto` code. This mirrors the Python SDK and uses
the identical sidecar JSON contract.

## Setup

```bash
cargo build -p indexone-cli            # build the sidecar (from repo root: core/)
export INDEXONE_CLI="$(pwd)/core/target/debug/indexone-cli"   # or put it on PATH

cd sdk/typescript
npm install
npm run typecheck   # tsc --noEmit
npm test            # tsc + node --test (real round-trip runs when INDEXONE_CLI is set)
```

## Usage

```ts
import { wrap, verify, type Principal, type Scope } from "indexone";

const alice: Principal = { id: "human:alice", display_name: "Alice" };
const client = wrap("00".repeat(32), alice); // 32-byte hex seed

const scope: Scope = {
  permissions: ["payments.charge"],
  max_depth: 2,
  expires_at: 4_102_444_800,
  budget: 10_000,
  currency: "USD",
};
const issued = client.issue(scope);
const step = client.attenuate(
  issued.chain,
  { id: "agent:a@org1", display_name: "A" },
  "11".repeat(32),
  { permissions: ["payments.charge"], max_depth: 1, expires_at: 4_102_444_800, budget: 5_000 },
  "book travel",
);

// Throws IndexOneError (fail closed) if the chain is invalid:
const effective = verify(step.chain, issued.root_key);
```

If `indexone-cli` is not found (neither `INDEXONE_CLI` nor on `PATH`), calls throw
`IndexOneError` with a build hint — the SDK fails closed, never silently.
