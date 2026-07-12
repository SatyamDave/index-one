/**
 * IndexOne TypeScript SDK — thin bindings over the Rust core.
 *
 * This SDK does NOT reimplement chain or crypto logic in TypeScript. Every
 * signing/verification call shells out to the `indexone-cli` binary built from
 * `core/cli` (`cargo build -p indexone-cli`), which runs the real
 * `indexone-chain` + `indexone-crypto` code. Locate the binary via the
 * `INDEXONE_CLI` environment variable or by having it on `PATH`.
 *
 * The sidecar JSON contract matches the Python SDK exactly:
 *   {cmd:"issue", seed, principal, scope}         -> {ok, chain, root_key}
 *   {cmd:"attenuate", chain, signer_seed, to, to_seed, scope, purpose}
 *                                                 -> {ok, chain, to_key}
 *   {cmd:"verify", chain, root_key}               -> {ok, effective_scope} | {ok:false, error}
 *
 * Key material is a 32-byte hex seed the client manages.
 */

import { spawnSync } from "node:child_process";

/** A typed constraint that bounds where or how much a `Permission` applies. */
export type Constraint = { amount_max: number } | { resource_in: string[] };

/**
 * A permission is either a bare action string, or a structured object with
 * typed constraints. Constraints only tighten down a chain; the Rust core
 * enforces the narrowing.
 */
export type Permission = string | { action: string; constraints: Constraint[] };

/** Mirrors `indexone_chain::Scope`. */
export interface Scope {
  permissions: Permission[];
  max_depth: number;
  expires_at: number;
  budget?: number | null;
  currency?: string | null;
}

/** Mirrors `indexone_chain::Principal`. */
export interface Principal {
  id: string;
  display_name: string;
}

/** Opaque JSON forms of the core's serde types. */
export type Chain = Record<string, unknown>;
export type PublicKey = Record<string, unknown>;

/** A verification failure or a sidecar/transport error. Thrown (fail closed)
 *  rather than returning a bare `false`. */
export class IndexOneError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IndexOneError";
  }
}

function cliPath(): string {
  const env = process.env["INDEXONE_CLI"];
  if (env && env.length > 0) {
    return env;
  }
  // Fall back to PATH; spawnSync throws ENOENT (caught below) if absent.
  return "indexone-cli";
}

function invoke(request: Record<string, unknown>): Record<string, unknown> {
  const result = spawnSync(cliPath(), {
    input: JSON.stringify(request),
    encoding: "utf8",
  });
  if (result.error) {
    throw new IndexOneError(
      `could not run indexone-cli (${result.error.message}). Build it with ` +
        "`cargo build -p indexone-cli` and set INDEXONE_CLI or put it on PATH.",
    );
  }
  const stdout = (result.stdout ?? "").trim();
  if (stdout.length === 0) {
    throw new IndexOneError(`indexone-cli produced no output (stderr: ${result.stderr ?? ""})`);
  }
  const response = JSON.parse(stdout) as Record<string, unknown>;
  if (response["ok"] !== true) {
    throw new IndexOneError(String(response["error"] ?? "unknown error from indexone-cli"));
  }
  return response;
}

/** Issue a fresh capability chain from a human root authority. Returns the
 *  chain and its `root_key` (the trust anchor). */
export function issue(
  seedHex: string,
  principal: Principal,
  scope: Scope,
): { chain: Chain; root_key: PublicKey } {
  const resp = invoke({ cmd: "issue", seed: seedHex, principal, scope });
  return { chain: resp["chain"] as Chain, root_key: resp["root_key"] as PublicKey };
}

/** Append a scope-narrowing delegation hop, signed by the current tail key. */
export function attenuate(
  chain: Chain,
  signerSeedHex: string,
  to: Principal,
  toSeedHex: string,
  scope: Scope,
  purpose: string,
): { chain: Chain; to_key: PublicKey } {
  const resp = invoke({
    cmd: "attenuate",
    chain,
    signer_seed: signerSeedHex,
    to,
    to_seed: toSeedHex,
    scope,
    purpose,
  });
  return { chain: resp["chain"] as Chain, to_key: resp["to_key"] as PublicKey };
}

/** Verify a chain against a trusted root key; return its effective (narrowest)
 *  scope. Throws {@link IndexOneError} (fail closed) on any invalid chain. */
export function verify(chain: Chain, rootKey: PublicKey): Scope {
  const resp = invoke({ cmd: "verify", chain, root_key: rootKey });
  return resp["effective_scope"] as Scope;
}

// ── Witness · attestation · composed verify — the full §6 product surface ────
//
// These reach past the delegation chain to the three deliverables the competing
// drafts punt: a witnessed action (completeness/omission), an independent
// completion attestation (not self-reported), and the composed fail-closed
// verify(). Receipts / proofs / attestations are opaque JSON threaded between
// calls; digests are lowercase hex.

/** Opaque JSON forms of the witness/attestation serde types. */
export type Receipt = Record<string, unknown>;
export type InclusionProof = Record<string, unknown>;
export type Completion = Record<string, unknown>;

/** Derive a public key from a 32-byte hex seed — e.g. to name a trusted attester
 *  in a {@link composedVerify} policy without issuing a chain. */
export function pubkey(seedHex: string): PublicKey {
  return invoke({ cmd: "pubkey", seed: seedHex })["public_key"] as PublicKey;
}

/** The content digest of a chain (hex) — what receipts and attestations bind to. */
export function chainDigest(chain: Chain): string {
  return invoke({ cmd: "chain_digest", chain })["digest"] as string;
}

/** The purpose-bound action digest (hex) for `(purpose, paramsDigest)`. Use it as
 *  the `action_digest` you witness, then enforce it via
 *  {@link composedVerify} `paramsDigestHex` — closes the opaque-digest gap. */
export function bindAction(purpose: string, paramsDigestHex: string): string {
  return invoke({ cmd: "bind_action", purpose, params_digest: paramsDigestHex })["digest"] as string;
}

/** Append an action receipt to the transparency witness. Returns the receipt, the
 *  updated `log`, the new Merkle `root` (hex), and an `inclusion_proof`. The
 *  witness is stateless: thread `log` back on each call. An action with no
 *  inclusion proof against `root` is *provably omitted*. */
export function witnessAppend(
  chainDigestHex: string,
  actionDigestHex: string,
  nonceHex: string,
  opts: { prevRootHex?: string; log?: Receipt[] } = {},
): { receipt: Receipt; log: Receipt[]; leaf_index: number; root: string; inclusion_proof: InclusionProof } {
  const resp = invoke({
    cmd: "witness_append",
    log: opts.log ?? [],
    chain_digest: chainDigestHex,
    action_digest: actionDigestHex,
    nonce: nonceHex,
    prev_root: opts.prevRootHex ?? "00".repeat(32),
  });
  return resp as {
    receipt: Receipt;
    log: Receipt[];
    leaf_index: number;
    root: string;
    inclusion_proof: InclusionProof;
  };
}

/** Produce an **independent** completion attestation (not self-reported). `role`
 *  is "third_party" or "counter_signed". */
export function attest(
  seedHex: string,
  attester: Principal,
  chainDigestHex: string,
  requestedActionHex: string,
  outcomeHex: string,
  witnessedRootHex: string,
  inclusionProof: InclusionProof,
  role: "third_party" | "counter_signed" = "third_party",
): Completion {
  return invoke({
    cmd: "attest",
    seed: seedHex,
    attester,
    chain_digest: chainDigestHex,
    requested_action: requestedActionHex,
    outcome: outcomeHex,
    witnessed_root: witnessedRootHex,
    inclusion_proof: inclusionProof,
    role,
  })["completion"] as Completion;
}

/** The full §6 `verify()`: chain + witness completeness (**omission**) +
 *  independent attestation + non-equivocation, fail closed. Throws
 *  {@link IndexOneError} naming the unresolved step. */
export function composedVerify(
  chain: Chain,
  rootKey: PublicKey,
  trustedRootHex: string,
  actionReceipt: Receipt,
  completion: Completion,
  opts: { trustedAttesters?: PublicKey[]; allowCounterSigned?: boolean; paramsDigestHex?: string } = {},
): Scope {
  const request: Record<string, unknown> = {
    cmd: "composed_verify",
    chain,
    root_key: rootKey,
    trusted_root: trustedRootHex,
    action_receipt: actionReceipt,
    completion,
    policy: {
      trusted_attesters: opts.trustedAttesters ?? [],
      allow_counter_signed: opts.allowCounterSigned ?? false,
    },
  };
  // Pass params_digest to also enforce the purpose<->digest binding.
  if (opts.paramsDigestHex !== undefined) request["params_digest"] = opts.paramsDigestHex;
  return invoke(request)["effective_scope"] as Scope;
}

/** Wraps one agent's identity (a 32-byte hex seed + principal). */
export class Client {
  constructor(
    readonly seedHex: string,
    readonly principal: Principal,
  ) {}

  issue(scope: Scope): { chain: Chain; root_key: PublicKey } {
    return issue(this.seedHex, this.principal, scope);
  }

  attenuate(
    chain: Chain,
    to: Principal,
    toSeedHex: string,
    scope: Scope,
    purpose: string,
  ): { chain: Chain; to_key: PublicKey } {
    return attenuate(chain, this.seedHex, to, toSeedHex, scope, purpose);
  }
}

/** The one-liner entry point: wrap an identity as a {@link Client}. */
export function wrap(seedHex: string, principal: Principal): Client {
  return new Client(seedHex, principal);
}
