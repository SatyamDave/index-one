# Research Verification — primary-source pass

> Directive 5 / §16: nothing in a deck, paper, or design-partner conversation
> until reproduced from the primary source. This file is that reproduction pass
> for the reading list in `REFERENCE.md`. Verified 2026-07-11-→12 by parallel
> research agents; every row traces to a primary source. **Where our own docs
> were wrong, this file says so** — see §7.

Legend: ✅ confirmed · ✳️ confirmed with correction/nuance · ❌ not reproducible / likely fabricated.

---

## 1. AIP / IBCT — our closest comp

**Real.** arXiv **2603.24775**, "AIP: Agent Identity Protocol for Verifiable
Delegation Across MCP and A2A," **single author Sunil Prakash**, 25 Mar 2026
(cs.CR/cs.AI), plus an individual Internet-Draft `draft-prakash-aip-00`.
**Caveat: non-peer-reviewed preprint + non-adopted I-D by one author; every
number is self-reported.**

- ✅ IBCT block structure (Block 0 Authority / Delegation / Completion) matches ours.
- ✳️ The mandatory per-hop field is named **`context`**, not `purpose` (semantics = purpose; empty context is rejected). Our code/docs call it `purpose` — fine internally, but say "context" when describing AIP.
- ✅ "Seven required properties" of agent identity; ✅ `X-AIP-Token` header; ✅ sub-ms verification (0.049 ms Rust, self-reported); ✅ "100% rejection" over the author's **own** 600-case/6-category harness (not an external red-team).
- ✳️ **Its only explicitly admitted completion gap is self-reported completion** — §7 says completion is self-reported and "counter-signing / third-party attestation … are not enforced in v1." **The words "omission," "completeness," and "equivocation" do NOT appear in the paper.** Those are *our* threat-model labels. Also admitted in §7: no revocation infra, DNS trust-anchor risk, no post-quantum.

**Use:** AIP genuinely concedes the honest-self-report gap and names counter-signing as the unbuilt fix — that maps cleanly to our attestation layer. Do **not** attribute "omission/equivocation" to AIP as its admitted non-goals; frame them as gaps we identify, not ones AIP names.

## 2. Competing drafts — APS / DRP / EP / HDP / SPICE

- ✅ **APS** `draft-pidlisnyi-aps-02` — 7-dimension product-lattice scope, content-addressed receipts, imported cross-org roots, ships a conformance suite. For general receipt-chain completeness it concedes deployments "MUST specify an external mechanism … append-only log with inclusion proofs" (unnamed, unbuilt) — but its primary mechanism is internal cascade-completion records, so it is the *least* supportive of the "punts to a log" framing.
- ✅ **DRP** `draft-nelson-agent-delegation-receipts-10` — **strongest support for our thesis:** implementations "SHOULD submit action log roots to an independently monitored transparency log following the SCITT architecture … to detect truncation and log fork attacks." That log is emerging/unbuilt.
- ✳️ **EP / EMILIA** — real via `draft-rampalli-cross-org-delegation-mapping-03` (cites Schrock EP drafts). Offloads authority documents to a transparency log ("log consistency is worth what the log operator is worth"). **Corrections:** the doc is **EP-AEG** (Action Evidence *Graph*), not "EP-AEC"; and a **named "cross-binding attack" is NOT found in any primary source** — do not quote it as a reproduced EP result.
- ✳️ **HDP** `draft-helixar-hdp-agentic-delegation-00` — fully offline multi-hop chain, but specifies **no** transparency log and simply **does not address omission/completeness** (leaves it to application-layer audit). It ignores the gap rather than punting to a log.
- ❌ **SPICE** — real IETF WG, but it's a **verifiable-credentials** WG, **not** an agent recursive-delegation draft. Our docs miscategorize it. Treat as adjacent, not a competitor.

**Defensible thesis (corrected):** *the agent-delegation drafts that address completeness (DRP, the EMILIA/cross-org-mapping line) defer it to an external, still-unbuilt SCITT-style cross-org transparency log; the rest (HDP, APS's general-chain case) leave omission/completeness unsolved.* Not "every draft punts to a log" — drop the "every."

## 3. Substrate — Biscuit + Macaroons

- ✅ **Biscuit** (Eclipse Biscuit, orig. Clever Cloud; Couprie & Delafargue): Ed25519 chain of block signatures, offline holder-side attenuation (append-only, blocks only narrow, can't be removed without breaking the chain), local Datalog-*variant* authorization needing only the issuer pubkey, spec-defined revocation IDs (a block's signature).
- ✳️ "Sub-1ms verification" — real, if anything conservative (creator states <0.5 ms full round-trip), but the citation is a **2022 podcast**, not a published benchmark. Cite as the creator's figure, not a spec guarantee.
- ✅ **Macaroons** (NDSS'14): origin of offline attenuation; the HMAC flaw is real and primary-source documented — "verifiable only by the target service" because verification needs the symmetric root key, so verify-capability = forge-capability. The paper itself proposes the public-key variant Biscuit implements. `rescrv/libmacaroons` exists.

**Use:** "Biscuit is the public-key successor that fixes the Macaroons shared-secret weakness" is accurate and echoed in Biscuit's own Eclipse proposal. Our substrate framing holds.

## 4. Rails — AP2 / Web Bot Auth / x402

- ✅ **AP2** `google-agentic-commerce/AP2` (ap2-protocol.org). ✳️ **Corrections:** the **v0.2 spec** renamed mandates to **Checkout Mandate + Payment Mandate** (Intent → an *open mandate*); the v0.1 SDK still ships Intent/Cart/Payment. Uses **SD-JWT VC / VDC over OpenID4VP** (not bare W3C VC). Crypto is **non-deterministic ECDSA, P-256/ES256 as the canonical example** (not a hard P-256-only mandate; not Ed25519).
- ❌ **AP2 does NOT bind to a single user only** — delegation and multi-step delegation chains (SD-JWT `cnf` key-binding, "Trusted Agent Provider") are a **first-class, tested** feature. Our "single-user, not a chain" seam claim is **wrong** — correct it before any pitch.
- ❌ **"Delegated Trust" / "Temporal Gaps" as AP2's own open problems** — not reproduced. "Temporal Gaps" comes from a **third-party** paper (arXiv 2602.06345), not AP2's spec. Do not attribute to Google/AP2.
- ✅ **Web Bot Auth** — per-request Ed25519 via **RFC 9421**; headers `Signature` / `Signature-Input` / `Signature-Agent`; keys at `/.well-known/http-message-signatures-directory`. This is a real transport model for our MCP integration.
- ✳️ **x402** — correct repo is **`google-agentic-commerce/a2a-x402`** (not `google-a2a`); an A2A extension reviving HTTP 402 for on-chain (USDC) agent-to-agent payments.

**For the AP2 adapter (Satyam):** build against the JSON Schemas in `code/sdk/schemas/ap2/*` (source of truth). Mandate field structures captured in the agent transcript; watch the v0.1-SDK vs v0.2-spec split. Because AP2 already supports chains, our wedge is **cross-org completeness/attestation over AP2 chains**, not "AP2 can't chain."

## 5. Standards — WIMSE / FIDO / SCITT / RFC 6962 / Visa TAP / MC Agent Pay

- ✳️ **WIMSE** `draft-ietf-wimse-arch` (real WG). **Corrections:** there is **no §3.3.9** and **no R1–R9 requirements list** — both appear fabricated in our docs (the real R2/R4 requirements live in `draft-rampalli-cross-org-delegation-mapping-05`, not WIMSE). Multi-hop is real but, in **`draft-ietf-wimse-arch-08` (07 Jul 2026)**, lives in **§3.4.11 "AI and ML-Based Intermediaries"** (+ §3.4.7 Delegation and Impersonation) — these were §3.3.x in earlier revs and **move between revisions, so pin the version every time you cite**. It is framed **prescriptively** (MUST re-bind per hop), not as an admitted-unsolved gap. Real, citable quote (§3.4.11): "a chain of AI-to-AI interactions could unintentionally extend authority far beyond what was originally granted … each hop … MUST explicitly scope and re-bind the security context."
- ✅ **FIDO Agentic Authentication** TWG (announced 2026-04-28; seeded by AP2 + MC Verifiable Intent). ✅ **SCITT** `draft-ietf-scitt-architecture` — Transparency Service / Signed Statement / Receipt / Registration Policy; a legitimate model to build a witness on. ✅ **RFC 6962** — §2.1.1 inclusion proofs, §2.1.2 consistency proofs (exactly what our `witness` crate implements); gossip discipline stated but deferred to a separate doc.
- ✅ **Visa TAP** (2025-10-14, with Cloudflare; `github.com/visa/trusted-agent-protocol`) and **Mastercard Agent Pay / Verifiable Intent** (2025-04-29) are real announced rails.

**Opening slide fix:** reframe from "WIMSE names multi-hop cross-org delegation as unsolved (§3.3.9, R1–R9)" to "WIMSE (§3.4.11/§3.4.7, draft-08) recognizes multi-hop cross-org delegation as a first-order risk and specifies only per-hop re-binding, leaving verifiable end-to-end provenance to implementations" — true, and it motivates a witness layer.

## 6. Surveys & delegation papers

- ✅ **2501.09674** South et al., **ICML 2025 Position oral** ("AI Agents Need Authenticated Delegation") — **strongest, safest citation**; the anchor for the delegation framing.
- ✅ **2510.25819** OpenID Foundation / South et al. — authoritative for the **SPIFFE/OAuth cross-org-boundary breakdown**; use this for that point.
- ✳️ **2604.23280** — real five-gap survey, but by **Otsuka/Toyoda/Leung**, *not* the OpenID/South group. Don't conflate authorship. Gap #4 is "Governance Opacity and Enforcement Paradox."
- ✳️ **AITH** (2604.07695) — real single-author student preprint; ML-DSA-87 continuous delegation. Cite as an existence proof only; don't lean on its numbers.
- ✳️ **"Delegation Without Escalation"** (mahasbini.org) — real self-published essay; on-point but grey literature. For a formal paper back its claims with peer-reviewed capability/macaroons sources.

## 7. Corrections to our own docs (action items)

These are places `REFERENCE.md` / `CLAUDE.md` / positioning are wrong or overstated and **must** be fixed before external use:

1. **AP2 "single-user, not a chain"** → false; AP2 supports tested delegation chains. Reposition the wedge to cross-org completeness/attestation over AP2 chains.
2. **AP2 "Delegated Trust / Temporal Gaps" as AP2's open problems** → not AP2's; "Temporal Gaps" is third-party (arXiv 2602.06345).
3. **WIMSE "§3.3.9" and "R1–R9 problem statement"** → do not exist (the real R2/R4 are in `draft-rampalli-cross-org-delegation-mapping-05`, not WIMSE). Cite **§3.4.11 / §3.4.7 of `draft-ietf-wimse-arch-08`** with the real quote; reframe as "recognized risk, prescriptive-only," not "named as unsolved." These section numbers moved from §3.3.x — re-pin on every revision.
4. **"Every competing draft punts completeness to an external log"** → overstated. True for DRP + EMILIA line; APS mostly self-solves; HDP ignores it; SPICE is unrelated. Drop "every."
5. **AIP admitted non-goals = "omission/equivocation"** → AIP only concedes self-reported completion. Present omission/equivocation as gaps *we* identify.
6. **"EP-AEC"** → **EP-AEG** (Action Evidence Graph). The named "cross-binding attack" is unverified — don't quote it.
7. **SPICE** listed as a recursive-delegation competitor → it's a verifiable-credentials WG; recategorize as adjacent.
8. **AIP field `purpose`** → AIP calls it `context`. **Biscuit "sub-1ms"** and **AIP benchmarks** → cite as self-reported, not independent.

## What we can safely claim (net)

- The **substrate framing is sound** (Biscuit = public-key successor to Macaroons; RFC 6962 gives us inclusion + consistency proofs; SCITT is a real witness architecture to build on).
- The **gap is real** and articulated by credible bodies — but in **prescriptive/deferred** terms (WIMSE re-binding; DRP/EMILIA deferring to an unbuilt SCITT log; AIP conceding self-report). Our honest one-liner: *the drafts recognize cross-org completeness/honest-completion and either defer it to a transparency log nobody runs cross-org, or leave it to implementations — we build that layer.*
- **Lead with what is defensible:** self-reported-completion (AIP's own admission) + omission/completeness (our identified gap, grounded in the CT/SCITT model). Avoid attributing our threat labels to specs that don't use them.

---

## 8. AIP reference implementation — for the real side-by-side

Three agents verified (and one **installed and ran**) the actual AIP reference impl,
so `exploits/` can run the genuine AIP verifier next to `IndexOne::verify`, not a
stand-in.

**It exists, and it's the author's own.** `github.com/sunilp/aip` (Sunil Prakash —
same author as arXiv 2603.24775 / `draft-prakash-aip-00`), **Apache-2.0**. Python
on PyPI: **`agent-identity-protocol` v0.3.0** (`pip install`); Rust crates live
in-repo (`rust/aip-core|aip-token|aip-mcp`, **not** on crates.io — build from
source). *Do not confuse* the DID-based namesakes (`openagentidentityprotocol`,
`The-Nexus-Guard/aip`, crates.io `aip`, PyPI `aip-sdk`) — none are Prakash's.

**Safe to run headless (verdict A, reproduced).** `CompactToken.verify(token, pubkey)`
and the chained/Biscuit path are pure offline Ed25519 — no network, server,
secrets, or filesystem writes (the `httpx` dep is only the optional `aip-proxy`
server). Install pulled prebuilt wheels only; the repo's own `pytest` (compact +
chained + policy) passed 18/18 offline.

**Verifier entry points:** Python `CompactToken.verify(token_str, public_key_bytes)`
(`aip_token/compact.py`), `ChainedToken.authorize(scope, root_public_key_bytes)`;
CLI `aip-proxy` (verifies `X-AIP-Token`). Rust `CompactToken::verify(&str, &[u8;32])`.

**What AIP's verifier checks** (draft §4.1, 5 steps): (1) extract token, (2) verify
Ed25519 signatures against the issuer identity doc, (3) requested tool ∈ `scope`,
(4) chain constraints — child scope ⊆ parent, child budget ≤ parent, depth <
`max_depth`, **non-empty `context`**, expiry — (5) inject identity. Compact mode =
JWT (`alg:EdDSA`, `typ:aip+jwt`, claims `iss/sub/scope/budget_usd/max_depth/iat/exp`,
< 1h). Identity docs canonicalized with **RFC 8785 (JCS)**.

**Honesty for the side-by-side (do not overclaim):**
- **Self-report → VALID is a verbatim non-goal.** §3.3 / §7: *"Completion blocks
  are self-reported… Counter-signing and third-party attestation exist as trust
  escalation options but are not enforced in v1. A dishonest agent can
  misrepresent its result hash or cost without detection."* AIP validates the
  completion block's *signature* only, never its truth → returns VALID. Quote this.
- **Omission → VALID is an *implication*, not a printed §7 sentence.** AIP's verifier
  never inspects work performed and has no completeness/witness mechanism, so an
  omitted action passes. Frame it as a consequence of the self-reported/attenuation-
  only model (§3.3/§7), **not** as a quoted non-goal.
- The AIP token and the IndexOne chain are the **same delegation scenario in each
  system's native format**, not identical bytes — say so.
