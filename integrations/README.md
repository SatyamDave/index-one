# integrations

Rail integrations and the cross-org attribution attack POC for index-one.

- `ap2/` — adapters between AP2 (Google's agentic-commerce mandate rail) and
  index-one capability-chain blocks.
- `mcp/` — MCP request-header signing/verification hooks (Web Bot Auth style
  per-request Ed25519 header signing).
- `attack/` — a runnable harness demonstrating the gap this project exists to
  close: a single-hop AP2 mandate cannot attribute authority across a 3-agent,
  cross-org delegation chain.

No real cryptography lives here — signing/verification stubs call into the
`indexone-chain` / `indexone-crypto` Rust core (not yet wired up). The
`attack/` harness uses clearly-marked placeholder "signatures" purely to
demonstrate the structural attribution gap, not to perform real
cryptographic operations.

See `/docs/REFERENCE.md` for the design invariants and prior art this
package is built against.
