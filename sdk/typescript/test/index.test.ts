import assert from "node:assert/strict";
import { test } from "node:test";

import { Client, IndexOneError, issue, verify, wrap, type Principal, type Scope } from "../src/index.js";

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
