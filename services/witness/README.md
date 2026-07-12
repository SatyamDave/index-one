# IndexOne Witness Service — "run the anchor"

The hosted cross-organization **witness / transparency log** — the product the
vision calls for (VISION.md: *"the anchor every receipt log needs and no one
runs"*). A thin, standards-aligned HTTP shell over the `indexone-witness` crate:
every cryptographic operation (Merkle append, inclusion + consistency proofs,
signed tree heads, equivocation reconciliation) already lives in the crate; this
service only parses requests, encodes digests/signatures as base64url, and holds
the log behind a mutex.

Standalone package (like `/exploits`, `/conformance`) — **not** a member of the
`/core` workspace, so axum/tokio never touch the async-free core. `cargo audit`
clean (99 deps); TLS is deliberately not handled here (terminate at a proxy) to
stay off the `ring` advisory.

## Run

```bash
# fixed operator key (stable signed tree heads) + address + durable log:
INDEXONE_WITNESS_SEED=$(python3 -c "print('07'*32)") \
INDEXONE_WITNESS_ADDR=127.0.0.1:8791 \
INDEXONE_WITNESS_DB=./witness.log \
cargo run --manifest-path services/witness/Cargo.toml --bin indexone-witness-service
# (omit the seed to generate a fresh key each start; omit the DB for an
#  in-memory, ephemeral log)
```

`INDEXONE_WITNESS_DB` points at a durable append-only log file. When set, every
submitted receipt is persisted and **`fsync`'d to the physical device** before it
is acked, so an acked entry survives power loss / kernel panic, not just a clean
exit. The whole tree — root, size, and all inclusion proofs — is replayed from
the file on restart, so a restart does not lose or fork the log; a **torn
trailing frame** from a crash mid-append (never acked) is truncated and recovered
on open, rather than refusing to start.

## API (RFC 6962 §4 / SCITT SCRAPI aligned)

Digests and signatures are **base64url (no padding)**; sizes/indices are decimal
integers; bodies are JSON. Every failure is a typed, fail-closed error.

| Method & path | Mirrors | Does |
|---|---|---|
| `POST /witness/v1/entries` | SCITT Registration → Receipt; RFC 6962 `add-chain` | append a receipt → `{leaf_index, inclusion_proof, sth}` |
| `GET /witness/v1/sth` | RFC 6962 `get-sth` | current signed tree head `{tree_size, root, signature}` |
| `GET /witness/v1/proof?leaf_index=N` | RFC 6962 `get-proof-by-hash`/`get-entry-and-proof` | inclusion proof for leaf `N` |
| `GET /witness/v1/consistency?first=M&second=N` | RFC 6962 `get-sth-consistency` | append-only proof M→N (`second` must be current size) |
| `POST /witness/v1/gossip` | RFC 6962 §3 gossip / SCITT Auditor | reconcile a peer STH → `consistent` or a `409` **equivocation proof** |
| `GET /.well-known/witness-keys` | SCRAPI `/.well-known/scitt-keys` | the operator's Ed25519 key, so anyone verifies offline |

**Submitter contract.** `POST /entries` requires `prev_root` to equal the log's
current root at submission (`GET /sth` first) — the crate's receipt-chaining
invariant. A stale `prev_root` is rejected `409`.

**Equivocation is portable proof.** `POST /gossip` returns `409` with *both*
operator-signed heads when they can't be reconciled (`reason`:
`forked_root` | `inconsistent` | `invalid_signed_head`). Because both STHs carry
the log's own signature, that response is non-repudiable evidence the log forked.

## Tested

In-process (`tower::ServiceExt::oneshot`, no socket bound — deterministic, CI-safe):
submit → the returned proof verifies against the signed root; stale `prev_root`
rejected; STH + consistency track appends; gossip catches a forked root; keys
served. Plus a live end-to-end run over a bound port.

## Not yet (documented TODOs)
- **Proof by leaf hash** (`?hash=`) needs a service-side `leaf_hash → index` map;
  v1 is by `leaf_index` only.
- **Persistence backends** — a durable append-only file log ships now
  (`INDEXONE_WITNESS_DB`); a compacting/indexed store (or an object-store backend)
  for very large logs is a later step.
- **`get-entries`** bulk replay for auditors (a policy decision, since leaves may
  reference private action digests).
- A signed **timestamp** in the STH (would require extending `sth_signing_bytes`
  in the crate so the signature covers it).
