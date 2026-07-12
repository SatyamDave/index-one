# indexone-revocation-log-service

The hosted IndexOne **revocation log** — the *publisher* side of remote
revocation. It holds the revoked set, signs a `SignedRevocationSnapshot` over it
(`indexone-revocation`), and serves that snapshot over HTTP for the *client*
side — `indexone-revocation-http`'s `HttpSnapshotSource` → `SnapshotChecker` — to
fetch and check. Publisher → transport → checker is exercised end-to-end in one
integration test over a real socket.

Every cryptographic operation lives in `indexone-revocation`; this is a thin
HTTP shell. Standalone package (not a `/core` workspace member) so axum/tokio
never enter the async-free core. TLS is not handled here — terminate at a proxy
(keeps `cargo audit` off the `ring` advisory).

## API

| Method + path | Purpose |
|---|---|
| `GET  /revocations/v1/snapshot` | The current `SignedRevocationSnapshot`, re-signed at read time so `published_at` is always fresh. Native serde form → wire-compatible with `HttpSnapshotSource` by construction. |
| `POST /revocations/v1/revoke` | `{ "revocation_id": <hex>, "reason": <str> }` → revoke, raise the epoch, return the new snapshot. |
| `GET  /revocations/v1/entries` | Audit list `{ epoch, entries: [{ revocation_id, reason }] }`. |
| `GET  /.well-known/revocation-keys` | The operator's Ed25519 public key — pin it as `operator_key` in a `SnapshotChecker`. |

`revocation_id` is the 32-byte keyless `RevocationId` (`blake3(DOMAIN || block_signature)`)
as lowercase hex — derivable by any token holder, so a revoker never needs the
signing key.

## Trust model (what this service does and doesn't guarantee)

- **Monotonic epoch.** A revocation only ever *raises* the epoch; the client's
  `SnapshotChecker` rejects any snapshot with an epoch below the newest it has
  seen, so an operator can't quietly un-revoke by serving an older set.
- **Signed + fresh.** The checker rejects a bad signature or a snapshot past its
  staleness window (fail closed as `LogUnreachable`, distinct from `Revoked`).
- **Append-only.** No un-revoke API — dropping an entry is exactly the
  suppression the design forbids.
- **Residual weakness (honest):** a malicious operator *omitting* an entry is
  bounded, not eliminated. Because `RevocationId` is keyless, any party can
  recompute ids and cross-check, so equivocation is *detectable*. The strict
  upgrade — a log-backed sparse Merkle map, whose roots are committed as leaves
  in the RFC 6962 witness we already run, making root-equivocation and rollback
  cryptographically detectable — is documented in
  `docs/REVOCATION_TRANSPARENCY.md` (v2).

## Run

```
INDEXONE_REVLOG_SEED=<64 hex chars>  # optional; else a fresh key is generated
INDEXONE_REVLOG_ADDR=127.0.0.1:8788  # optional
cargo run -p indexone-revocation-log-service
```
