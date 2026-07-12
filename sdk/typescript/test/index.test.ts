import assert from "node:assert/strict";
import { test } from "node:test";

import { createHash } from "node:crypto";

import {
  Client,
  IndexOneError,
  attenuate,
  attest,
  chainDigest,
  composedVerify,
  issue,
  pubkey,
  verify,
  witnessAppend,
  wrap,
  type Chain,
  type Principal,
  type PublicKey,
  type Scope,
} from "../src/index.js";

const FAR_FUTURE = 4_102_444_800;

function cliAvailable(): boolean {
  return Boolean(process.env["INDEXONE_CLI"]);
}

test("wrap returns a Client carrying its identity", () => {
  const client = wrap("00".repeat(32), { id: "human:alice", display_name: "Alice" });
  assert.ok(client instanceof Client);
  assert.equal(client.principal.id, "human:alice");
});

test("scope and principal shapes construct", () => {
  const scope: Scope = {
    permissions: ["payments.charge"],
    max_depth: 2,
    expires_at: FAR_FUTURE,
    budget: 10_000,
    currency: "USD",
  };
  const principal: Principal = { id: "human:alice", display_name: "Alice" };
  assert.equal(scope.budget, 10_000);
  assert.equal(principal.id, "human:alice");
});

test("missing sidecar fails closed with IndexOneError", () => {
  const saved = process.env["INDEXONE_CLI"];
  process.env["INDEXONE_CLI"] = "/nonexistent/indexone-cli-xyz";
  try {
    assert.throws(
      () => verify({}, { algorithm: "Ed25519", bytes: [] }),
      IndexOneError,
    );
  } finally {
    if (saved === undefined) delete process.env["INDEXONE_CLI"];
    else process.env["INDEXONE_CLI"] = saved;
  }
});

test(
  "real issue -> attenuate -> verify round-trip through the sidecar",
  { skip: cliAvailable() ? false : "indexone-cli not built (set INDEXONE_CLI)" },
  () => {
    const rootSeed = "01".repeat(32);
    const aSeed = "02".repeat(32);
    const issued = issue(
      rootSeed,
      { id: "human:alice", display_name: "Alice" },
      { permissions: ["payments.charge"], max_depth: 2, expires_at: FAR_FUTURE, budget: 10_000, currency: "USD" },
    );
    const client = new Client(rootSeed, { id: "human:alice", display_name: "Alice" });
    const step = client.attenuate(
      issued.chain,
      { id: "agent:a@org1", display_name: "A" },
      aSeed,
      { permissions: ["payments.charge"], max_depth: 1, expires_at: FAR_FUTURE, budget: 5_000, currency: "USD" },
      "book travel",
    );
    const effective = verify(step.chain, issued.root_key);
    assert.equal(effective.budget, 5_000);
    assert.equal(effective.max_depth, 1);
  },
);

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const seedByte = (b: number): string => b.toString(16).padStart(2, "0").repeat(32);

/** Human -> A@org1 -> B@org2 -> C@org3 (executor). */
function threeHopChain(): { chain: Chain; rootKey: PublicKey; cd: string } {
  const issued = issue(
    seedByte(1),
    { id: "human:alice", display_name: "Alice" },
    { permissions: ["payments.charge"], max_depth: 3, expires_at: FAR_FUTURE, budget: 10_000, currency: "USD" },
  );
  let chain = issued.chain;
  for (const [s, t, id, depth] of [
    [1, 2, "agent:a@org1", 2],
    [2, 3, "agent:b@org2", 1],
    [3, 4, "agent:c@org3", 0],
  ] as const) {
    chain = attenuate(
      chain,
      seedByte(s),
      { id, display_name: id },
      seedByte(t),
      { permissions: ["payments.charge"], max_depth: depth, expires_at: FAR_FUTURE, budget: 4_000, currency: "USD" },
      `hop to ${id}`,
    ).chain;
  }
  return { chain, rootKey: issued.root_key, cd: chainDigest(chain) };
}

test(
  "full surface: witnessed + independently attested action verifies",
  { skip: cliAvailable() ? false : "indexone-cli not built (set INDEXONE_CLI)" },
  () => {
    const { chain, rootKey, cd } = threeHopChain();
    const action = sha("charge $40");
    const nonce = sha("nonce-1");
    const notaryKey = pubkey(seedByte(9));

    const w = witnessAppend(cd, action, nonce);
    const completion = attest(
      seedByte(9), { id: "attester:notary", display_name: "Notary" }, cd, action, action, w.root, w.inclusion_proof,
    );
    const effective = composedVerify(chain, rootKey, w.root, w.receipt, completion, {
      trustedAttesters: [notaryKey],
    });
    assert.equal(effective.budget, 4_000);
  },
);

test(
  "omitted action fails closed through the SDK (the Day-12 lead case)",
  { skip: cliAvailable() ? false : "indexone-cli not built (set INDEXONE_CLI)" },
  () => {
    const { chain, rootKey, cd } = threeHopChain();
    const honest = sha("charge $40");
    const nonce = sha("nonce-1");
    const notaryKey = pubkey(seedByte(9));

    const w = witnessAppend(cd, honest, nonce); // only the honest action is witnessed
    const omitted = sha("secret $9000");
    const omittedReceipt = witnessAppend(cd, omitted, nonce).receipt; // throwaway log
    const completion = attest(
      seedByte(9), { id: "attester:notary", display_name: "Notary" }, cd, omitted, omitted, w.root, w.inclusion_proof,
    );
    assert.throws(
      () => composedVerify(chain, rootKey, w.root, omittedReceipt, completion, { trustedAttesters: [notaryKey] }),
      IndexOneError,
    );
  },
);
