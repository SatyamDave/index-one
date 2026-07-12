# INDEXONE FOUNDING BRIEF

> **⚠️ PROVENANCE & ACCURACY — read before quoting.** This brief was generated
> during a **parallel `dataroom` implementation pass**, then compared against
> `main`. `main` was found to be a **superset**: it independently implemented the
> same features and additionally has RFC 8785 (JCS) canonicalization, a
> TypeScript SDK, a protocol spec (`docs/SPEC.md`), module-split crypto, and a
> second exploit binary. **`main` is the source of truth.** Consequently:
> - Section 1 (crypto primitives, token structure, `verify()` algorithm) is
>   accurate for `main` as well — `main`'s versions are equal or better.
> - Sections 3 (metrics) and 5–6 were measured/observed on the `dataroom` tree.
>   The **numbers and per-file line references may differ on `main`** (e.g. crypto
>   is split into `core/crypto/src/{ed25519,hybrid,mldsa}.rs`; the exploit bin is
>   `exploits/src/bin/omission_3hop.rs`). **Re-run the benchmarks and re-grep line
>   numbers against `main`** before putting anything in a deck or spec.
> - Items in §5/§6 flagged as "missing on this branch" (JCS, TS SDK, spec doc,
>   witness gossip, remote-revocation transport) are **already present on `main`**.
>
> Original generation note: 2026-07-11 from the `dataroom` working tree, Apple M4
> Pro / macOS 26.5.1 / rustc 1.96.0; every claim grounded in a file path, test
> name, or reproduced command output (CLAUDE.md Directive 5).

---

## 1. TECHNICAL GROUND TRUTH (for the spec + deck)

### 1.1 Crypto primitives actually in use (exact crate + version)

Versions from `core/Cargo.toml` `[workspace.dependencies]`, `core/crypto/Cargo.toml`, and `core/Cargo.lock`:

| Crate | Primitive | Library + version | Where |
|---|---|---|---|
| `indexone-crypto` | Ed25519 (RFC 8032) | `ed25519-dalek 2.2.0` | `core/crypto/src/lib.rs:104-170` |
| `indexone-crypto` | **ML-DSA-87 (FIPS 204), post-quantum** | `ml-dsa =0.1.1` (RustCrypto, pinned exact, `default-features=false`, `alloc`) | `core/crypto/Cargo.toml:18`, `core/crypto/src/lib.rs:172-242` |
| `indexone-crypto` | **Hybrid Ed25519 + ML-DSA-87** (both must verify) | composition of the two above | `core/crypto/src/lib.rs:244-350` |
| `indexone-chain` | blake3 hash links + chain digest | `blake3 1.8.5` | `core/chain/src/lib.rs:198-207,390-392` |
| `indexone-witness` | blake3 Merkle tree, RFC 6962 discipline | `blake3 1.8.5` | `core/witness/src/lib.rs:29-45` |
| `indexone-revocation` | blake3 revocation ids | `blake3 1.8.5` | `core/revocation/src/lib.rs:47-52` |
| all signed payloads | canonical bytes = deterministic `serde_json 1.0.150` | `serde 1.0.228` | **not** RFC 8785 JCS yet — TODO at `core/chain/src/lib.rs:174`, `core/witness/src/lib.rs:64`, `core/attestation/src/lib.rs:111` |

**PQ / hybrid: real, not aspirational.** `Algorithm` is `{ Ed25519, MlDsa87, Hybrid }` (`core/crypto/src/lib.rs:20-31`) and `verify_signature` dispatches all three arms (lines 87-100). Every key/signature carries its algorithm tag, so schemes coexist per-block. Hybrid byte layout is fixed-offset and unambiguous (documented at `lib.rs:251-254`): **public key = 32 (Ed25519) + 2592 (ML-DSA-87) = 2624 bytes; signature = 64 + 4627 = 4691 bytes.** Verification is a fail-closed AND of both halves; forging or truncating either half is rejected (tests `hybrid_forged_ed25519_half_is_invalid_not_error`, `hybrid_forged_mldsa_half_is_invalid_not_error`, `hybrid_truncated_signature_is_an_error_not_a_false`, `hybrid_truncated_key_is_an_error_not_a_false`).

### 1.2 Capability-token structure (actual struct fields)

**Block 0 — `RootBlock`** (`core/chain/src/lib.rs:94-101`): `principal: Principal`, `principal_key: PublicKey` (the trust anchor), `scope: Scope`, `signature`.

**Block N — `DelegationBlock`** (`core/chain/src/lib.rs:110-130`): `from: Principal`, `from_key: PublicKey`, `to: Principal`, `to_key: PublicKey` (the key the *next* hop must sign with), `scope: Scope`, `purpose: String` (mandatory; empty ⇒ `MissingPurpose`), `prev_block_hash: Vec<u8>` (blake3 of the previous block's full bytes), `signature`.

**`Scope`** (`lib.rs:35-49`): `permissions: Vec<String>`, `budget: Option<u64>`, `currency: Option<String>`, `max_depth: u32`, `expires_at: u64`.

**Signed fields:** everything but the signature. Root signs `(principal, principal_key, scope)` (`root_signing_payload`, `lib.rs:176`); each delegation signs `(from, from_key, to, to_key, scope, purpose, prev_block_hash)` (`delegation_signing_payload`, `lib.rs:183`).

**What binds hop N to N−1 (three locks, all enforced in `Chain::verify`, `lib.rs:340-352`):** (1) `prev_block_hash` = blake3 of block N−1's full canonical bytes; (2) `from_key` must equal block N−1's `to_key` — the block must be signed by the exact key the previous hop delegated to (`WrongSigner`); (3) `from` must equal block N−1's `to` (`PrincipalMismatch`). Attenuation invariants (`Scope::is_narrowing_of`, `lib.rs:56-77`): permissions ⊆ parent, budget ≤ parent, currency match, `expires_at` never later, `max_depth` strictly decreasing and > 0.

### 1.3 `verify()` — what it composes, what it rejects, fail-closed

`indexone_verifier::verify(action, root_key, trusted_root) -> Result<Scope, VerifyError>` (`core/verifier/src/lib.rs:88-140`), eight ordered gates, each a typed error naming the violated claimed property:

1. **Chain** — signatures + hash links + hop continuity + monotonic attenuation (`Chain::verify`) → `VerifyError::Chain(_)`.
2. **Chain binding** — receipt *and* attestation must commit to this chain's digest → `ChainBindingMismatch` (anti-splicing).
3. **Non-equivocation** — attestation's `witnessed_root` must equal the gossip-trusted root, checked *before* inclusion → `Equivocation`.
4. **Completeness / omission** — receipt must have a valid Merkle inclusion proof under the trusted root → `Omission`.
5. **Independent attestation** — attester key ≠ executor key, signature valid → `Attestation(NotIndependent | SignatureInvalid | …)`.
6. **Outcome honesty** — attested `outcome_digest` == witnessed `action_digest` → `OutcomeMismatch`.
7. **Canonical action-digest consistency** — `requested_action_digest` == witnessed digest → `ActionDigestInconsistent` (an in-scope-but-different-from-requested action still fails).
8. Accept, returning the effective scope.

There is also **`verify_threshold(...)`** (`lib.rs:154-…`) taking a k-of-n `ThresholdAttestation`, which additionally enforces a **presenter-cannot-dilute sufficiency bar**: a bundle whose declared `threshold` is below the verifier's `required_threshold` is rejected with `InsufficientAttestation { required, declared }` before signatures are examined.

**Fails closed — confirmed:** `verify` has no `Ok` path except the final line after all gates. Tests in `core/verifier/src/lib.rs` (all passing): `honest_action_verifies`, `omitted_action_is_invalid_even_with_valid_signatures`, `self_reported_completion_is_invalid`, `equivocated_root_is_invalid`, `dishonest_outcome_is_invalid`. ⚠️ Coverage gap: **`verify_threshold` and the `ActionDigestInconsistent` gate have no dedicated test in the verifier crate** (the k-of-n rule itself is tested in `attestation`; the conformance bin exercises the single-attestation path). Add verifier-level tests for both before the spec claims them.

### 1.4 The Day-12 / cross-org kill test, in plain English

Mechanized as `omitted_action_is_invalid_even_with_valid_signatures` (`core/verifier/src/lib.rs`) and shipped as a standalone binary `exploits/src/omission_3hop.rs`. Build the chain **Human (alice) → A (org1) → B (org2) → C (org3)** with every signature valid and every scope properly narrowed ($100→$50→$50→$40, depth 3→0). The executing agent then claims an action digest that was **never appended to the witness**, presenting a real chain, a real-looking receipt, and a recycled inclusion proof. A **chain-only / signature-only** verifier (`Chain::verify`) returns VALID — correct, because omission is outside what a signature can prove. The composed `verify()` returns `Omission` for the same artifact, because no inclusion proof for an unlogged action can fold to the witnessed Merkle root. Supporting cases: executor self-signing completion → `Attestation(NotIndependent)`; attested root gossip rejects → `Equivocation`; witness says X, attestation says Y → `OutcomeMismatch`.

**What IndexOne catches that a single-hop mandate misses:** a single-hop mandate proves only internal consistency of one credential. It cannot see whether intermediate hops actually delegated, whether the action set is complete, or whether "done" was reported by anyone but the doer. The runnable POC (`python -m integrations.attack.poc_cross_org_chain`) shows a compromised org-2 agent minting a full-budget mandate in the human's name that passes single-hop verification, while the real core rejects the same forgery with `wrong signer`.

**⚠️ Honesty caveat (unchanged and important):** the "before" side is a *chain-only / signature-only* verifier standing in for AIP's non-goals — **no real AIP reference verifier is vendored** in this branch. `exploits/README.md` and `exploits/src/omission_3hop.rs:23-27` say so explicitly. Do not tell an investor "AIP's verifier says VALID" until a real AIP verifier is run side-by-side.

---

## 2. STATUS MATRIX (real vs stubbed)

Detected via `grep -rniE 'todo|unimplemented!|todo!|stub|mock|illustrative|not real crypto|placeholder|NotImplementedError'` over source (excluding `target/`).

| Crate / module | Status | Evidence |
|---|---|---|
| `core/crypto` | **REAL** | Ed25519 + ML-DSA-87 + hybrid; 17 tests incl. forged-half / truncation rejection. |
| `core/chain` | **REAL** | Signatures, blake3 links, all attenuation invariants; 6 tests. |
| `core/witness` | **REAL** | Merkle append/root/inclusion **+ RFC 6962 consistency proofs + signed checkpoints + `audit_checkpoints` (fork vs extension)**; 12 tests. In-memory only (no persistence/network service). |
| `core/attestation` | **REAL** | Independent + `AttesterRole` (CounterSigner/ThirdParty) + k-of-n `ThresholdAttestation`; 16 tests. |
| `core/verifier` | **REAL** (test gap) | 8-gate `verify` + `verify_threshold`; 5 tests. `verify_threshold`/`ActionDigestInconsistent` untested at this layer (§1.3). |
| `core/revocation` | **REAL** | `RevocationId`=blake3(sig); `ShortTtlChecker`, `TransparencyLogChecker` (verifies snapshot vs a trusted commitment), `check_chain_revocation` fails closed on indeterminate; 9 tests. Transport is in-memory data, not HTTP/gossip (commented). |
| `core/cli` | **REAL** (no unit tests) | `keygen/issue/attenuate/sign/verify-sig/verify` JSON sidecar; **0 unit tests** — exercised only indirectly via the Python SDK tests. |
| `sdk/python` | **REAL** | `Client`/`wrap`/`issue`/`attenuate`/`verify` bind to core via the sidecar; 4 behavioral tests (skip if sidecar unbuilt). |
| `integrations/ap2` | **REAL** | `mandate_to_scope` / `mandate_to_delegation_block` + shape check; 5 tests. Not a full W3C VC/ECDSA-P256 verification (explicitly scoped). |
| `integrations/mcp` | **REAL** | Canonical base + Ed25519 sign/verify via core; 3 tests. |
| `integrations/attack` | **REAL (mixed, labeled)** | Real-core defense half (`wrong signer`); AP2 half is a deliberately-labeled single-hop stand-in (`harness.py:44` `fake_signature … NOT real crypto`). |
| `exploits/` | **REAL** (assertion bin) | `omission_3hop` runs, all cases reproduce, exit 0; 0 unit tests (it *is* the assertion). |
| `conformance/` | **REAL** (assertion bin) | 8/8 properties PASS, exit 0; 0 unit tests. |
| `benchmarks/` | **REAL** | Drives real `Chain::verify` + real Ed25519 block; numbers in §3. |

**Direct answers:** revocation (short-TTL + transparency log) — **REAL**, fails closed, 9 tests (transport is in-memory, not networked). Python SDK — **REAL**, binds to core via sidecar. AP2 integration — **REAL** field mapping (not full VC verification). Attack POC — **real crypto on the defense side** (drives the Rust core), AP2 side intentionally a labeled stand-in.

**No `unimplemented!()`, `todo!()`, or `NotImplementedError` remain in source** (verified). Remaining `TODO`s are design notes, not stubs (§5).

---

## 3. PROOF & METRICS (for deck + data room)

### 3.1 Tests (run 2026-07-11)

```
cargo test --manifest-path core/Cargo.toml --workspace
```
**65 passed, 0 failed** — crypto 17, chain 6, witness 12, attestation 16, verifier 5, revocation 9 (cli: 0 tests).

```
INDEXONE_CLI=<built> pytest   (integrations)  → 11 passed
INDEXONE_CLI=<built> pytest   (sdk/python)    →  4 passed
```
Total **80 automated tests green** (65 Rust + 15 Python). Plus two runnable assertion binaries, both exit 0:
```
cargo run --manifest-path exploits/Cargo.toml --bin omission_3hop   # all 3 cases REPRODUCED
cargo run --manifest-path conformance/Cargo.toml                    # 8/8 properties PASS
```

### 3.2 Benchmarks (real crypto, Apple M4 Pro, release; `cargo bench --manifest-path benchmarks/Cargo.toml`)

| Benchmark | Median |
|---|---|
| `verify/1_hops` | **45.3 µs** |
| `verify/3_hops` | **93.3 µs** |
| `verify/5_hops` | **141.2 µs** |
| `verify/10_hops` | **261.2 µs** |
| `serialize_delegation_block_json` | 808 ns |
| **Per-hop token size (JSON, real Ed25519 sig + embedded keys)** | **997 bytes** |

Raw:
```
verify/1_hops    time: [45.149 µs 45.311 µs 45.493 µs]
verify/3_hops    time: [92.959 µs 93.346 µs 93.741 µs]
verify/5_hops    time: [140.82 µs 141.24 µs 141.75 µs]
verify/10_hops   time: [260.67 µs 261.16 µs 261.68 µs]
current JSON-encoded DelegationBlock size: 997 bytes (real Ed25519 sig + embedded keys; target: compact binary encoding)
```
**Slide-ready (honest):** "3-hop cross-org chain verifies in **~93 µs**, ~0.26 ms at 10 hops (real Ed25519, M4 Pro)." Per-hop **997 bytes** in JSON — ~2.6× the 340–380-byte target in `benchmarks/README.md`; the gap is JSON + two embedded 32-byte keys, closed by a binary encoding. ⚠️ These benches measure `Chain::verify` only — **not** the composed `verify()` (witness + attestation). No composed-verify bench exists; don't quote "full verify() latency" yet.

### 3.3 LOC, crates, contributors

**LOC (`wc -l`, excl. `target/`):** Rust **4,570** · Python **989**. Per-crate Rust: crypto 508, chain 563, witness 761, attestation 674, verifier 458, revocation 516, cli 271 (+ exploits/conformance/benchmarks).

**Crates (7 in the `core` workspace):** `indexone-crypto`, `-chain`, `-revocation`, `-witness`, `-attestation`, `-verifier`, `-cli`; plus standalone `indexone-exploits`, `indexone-conformance`, `indexone-benchmarks`. Python: `indexone` (SDK), `index-one-integrations`.

**Contributor split (git authorship):** `Satyam Dave: +2,259 / −0` (the initial scaffold), `Udaya Tejas: +13,232 / −1,198` (the project charter + all subsequent implementation). ⚠️ Caveat for a data room: the large `Udaya` figure includes this session's automated implementation work, authored under the configured git user `Udaya Tejas` with `Co-Authored-By: Claude`. It is **not** a hand-written-by-one-founder line count — represent it honestly.

---

## 4. DESIGN-PARTNER INPUTS (for the one-pager)

### 4.1 One-sentence product (grounded)

> **IndexOne proves, in ~0.1 ms and with no callback, that a cross-organization AI-agent action ran under an unbroken, monotonically-narrowing chain of signed human authority — and that the action was actually logged to a witnessed transparency root and its completion attested by someone other than the agent that did it.**

Every clause maps to shipped, tested code: chain (`indexone-chain`), latency (§3.2), no-callback (`Chain::verify` is pure over the token bytes), completeness/non-equivocation (`indexone-witness`), independent/threshold attestation (`indexone-attestation`), composed fail-closed (`indexone-verifier`).

### 4.2 Integration surface

Two entry points today. **Rust** (native, fastest): `Chain::issue` → `Chain::attenuate` per hop → `indexone_verifier::verify(...)` (see the flow in `core/verifier/src/lib.rs` tests). **Python** (`pip install indexone`, binds to the core via the `indexone-cli` sidecar — no crypto reimplemented):

```python
import indexone
human   = indexone.Client("human:alice")
agent_a = indexone.wrap(my_agent, agent_id="agent:a@org1")

root = indexone.Scope(["payments.charge"], budget=10_000, currency="USD", max_depth=2)
hop  = indexone.Scope(["payments.charge"], budget=5_000,  currency="USD", max_depth=1)

token = human.issue(root)
token = human.attenuate(token, agent_a, hop, "book travel")
scope = indexone.verify(token)     # -> effective narrowed Scope, or raises IndexOneError
```
Build the sidecar first: `cargo build --manifest-path core/Cargo.toml -p indexone-cli` (`sdk/python/src/indexone/client.py`). MCP transport (chain-in-a-header, Ed25519 per request) is real in `integrations/src/integrations/mcp/hooks.py`.

### 4.3 The "wound" (demo-ready)

Your customer's agent (org 1) is authorized by a human for $100 of travel spend. Downstream, an over-permissioned agent at org 2 — which org 1 **never delegated to** — mints its own payment mandate in the human's name, at the **full $100** (no narrowing), and hands it to the settlement agent at org 3. Single-hop, AP2-style verification **passes**: the mandate is internally consistent and the format cannot even express "the chain of agents that led here." `python -m integrations.attack.poc_cross_org_chain` reproduces it (`ap2_verification_passed: True`, `actually_authorized: False`), then shows the real IndexOne core rejecting the same forgery with `wrong signer` — org 2 was never delegated the tail key, so it cannot extend the hash-linked, scope-narrowing chain. (The AP2 side of the POC is a deliberately-labeled single-hop stand-in, not a real AP2 verifier.)

---

## 5. HOUSEKEEPING (blockers to clear before outreach)

### 5.1 License — RESOLVED on this branch
Apache-2.0 across `LICENSE`, `core/Cargo.toml:35`, `integrations/pyproject.toml:11`, `sdk/python/pyproject.toml:11`. No TODO remains in any of them. (⚠️ On `origin/main` the license state may differ — reconcile, §6.)

### 5.2 Remaining "TODO/stub/placeholder/not-real" lines (`file:line`)
- `core/chain/src/lib.rs:37` — structured/Datalog scope type (design TODO).
- `core/chain/src/lib.rs:84` — pin identity format for AP2/MCP composition (design TODO).
- `core/chain/src/lib.rs:174`, `core/witness/src/lib.rs:64`, `core/attestation/src/lib.rs:111` — **RFC 8785 (JCS) canonicalization** before wire format (design TODO; note `origin/main` reportedly already did this).
- `integrations/src/integrations/__init__.py:6` — **stale**: still calls the attack module a "runnable placeholder"; it now drives real crypto. Scrub.
- `integrations/src/integrations/attack/harness.py:44` — `fake_signature … NOT real crypto`: **correct and intentional** (labels the AP2 stand-in); keep.
- Test docstrings in `sdk/python/tests/test_client.py:3` and `integrations/tests/test_ap2_adapter.py:1` mention "stub/no stubs" descriptively — harmless.

### 5.3 CI, security, spec
- **CI is not run on this branch.** There is no `origin/dataroom`; `dataroom` is local-only. CI is green on `origin/main` historically, but none of this branch's code has been through CI. Pushing will be its first CI run.
- Python CI (`.github/workflows/python-ci.yml`) was updated on this branch to build the sidecar and install both packages; Rust CI / Security (`cargo audit`, green locally) unchanged. `cargo audit` passed locally (0 vulnerabilities, incl. the new `ml-dsa`).
- `SECURITY.md` **present** on this branch.
- **No protocol/wire spec doc on this branch** (`docs/` has only `REFERENCE.md`, prior-art notes). ⚠️ `origin/main`'s commit log mentions a spec doc — see §6.
- **⚠️ Committed build artifacts on `origin/main`:** the diff against `origin/main` shows thousands of `*/target/debug/**` files tracked in git (a `.gitignore` miss on the `closed-nightshade` merges). This branch does **not** track `target/`. Flag for whoever owns `main`.

### 5.4 Unverified citations (unchanged)
The arXiv IDs, "AITH", and `mahasbini.org` refs in `docs/REFERENCE.md` remain unverified against primary sources (CLAUDE.md Directive 5 / §16). Verify before any deck/spec.

---

## 6. ⚠️ HUMAN INPUT NEEDED

1. **⚠️ THE PUSH DECISION (highest priority).** `origin/main` already has a parallel implementation of this branch's work (via `closed-nightshade`, PRs #2 & #3) **plus** JCS canonicalization, a TypeScript SDK, and witness gossip + a real remote-revocation transport that `dataroom` lacks. Options: (a) **abandon `dataroom`** and adopt `main` (likely the superset — but it carries committed `target/` bloat to clean); (b) **cherry-pick** only what `dataroom` has that `main` lacks (little, if `main` is a true superset); (c) reconcile into one branch. Someone must diff the two implementations and choose — do **not** merge blindly (5,294 files differ, mostly `target/` noise). ⚠️ NEEDS HUMAN INPUT: which branch is the source of truth?
2. ⚠️ NEEDS HUMAN INPUT: **Real AIP reference verifier** — is there a runnable AIP implementation to vendor for a true side-by-side kill-test? Until then the demo says "a signature-only verifier accepts it," not "AIP accepts it."
3. ⚠️ NEEDS HUMAN INPUT: **Raise parameters** — amount, valuation/instrument (SAFE?), use of funds. Nothing in the repo speaks to this.
4. ⚠️ NEEDS HUMAN INPUT: **Founder bios** — repo gives only names, the role split, an OSCP mention (Udaya), a Purdue email (Satyam). Deck needs real bios.
5. ⚠️ NEEDS HUMAN INPUT: **Design-partner shortlist + warm intros** — CLAUDE.md §13 lists candidates (Nevermined, Crossmint, Skyfire, Payman, Catena Labs, Fewsats…); no contacts recorded. Who do you actually know?
6. ⚠️ NEEDS HUMAN INPUT: **Timeline** — CLAUDE.md §10 targets a YC Fall app (Jul 27). Still the plan?
7. ⚠️ NEEDS HUMAN INPUT: **Public spec** — `origin/main`'s log references a spec doc; this branch has none. Which spec is canonical, and is it published?
8. ⚠️ NEEDS HUMAN INPUT: **Crypto dual-review** — CONTRIBUTING.md requires both founders to review crypto before it lands. This session's crypto (ML-DSA/hybrid, threshold, consistency proofs, revocation) has not had a human security review.

---

## STATE OF READINESS

1. **Demo-ready on this branch:** the full stack — Ed25519 + ML-DSA-87 + hybrid crypto, scope-narrowing chain, Merkle witness with inclusion + consistency proofs + checkpoints, independent + k-of-n threshold attestation, 8-gate fail-closed `verify()`, real revocation, a one-command before/after flag-plant, and an 8/8 conformance suite. **80 tests green** (65 Rust + 15 Python); ~93 µs 3-hop verify (M4 Pro).
2. **The single biggest thing before any push:** reconcile with `origin/main`, which independently built the same features **plus** JCS, a TS SDK, and gossip/remote-revocation. This is not a merge — it's a "pick the source of truth" decision. Blind-pushing `dataroom` duplicates and conflicts.
3. **Still genuinely open (both branches, unless `main` closed them):** a vendored real AIP verifier for the headline demo; the hosted witness *network* as a service; a composed-`verify()` benchmark; verifier-level tests for `verify_threshold` / `ActionDigestInconsistent`; and human crypto review.
4. **Cleared on this branch:** Apache-2.0 finalized, IndexOne naming consistent, `SECURITY.md`, real ROADMAP, stale labels scrubbed (one line left at `integrations/__init__.py:6`). `origin/main` still carries committed `target/` artifacts to clean.
5. **Single highest-priority gap:** the branch reconciliation in item 2 — until that's decided, nothing should be pushed, because the strongest version of this work may already be on `main` and pushing `dataroom` on top would set it back.
