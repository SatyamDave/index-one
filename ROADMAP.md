# CLAUDE.md — Warrant

> **Codename: Warrant** *(provisional — a warrant is delegated authority that is accountable and on the record; swap the name freely).*
> **One-liner:** The witness and independent-attestation layer for cross-organization AI agent delegation — we prove an agent action chain is complete, attributed, and honestly reported, not just signed.

This file is the single source of truth for the project. It is both (a) the repo context file for any Claude Code / agent session and (b) the master briefing for a human or model picking this up cold. Read it fully before writing code, drafting a deck, or talking to a design partner.

---

## 0. HOW TO USE THIS FILE

- **As a Claude Code context file:** keep it at repo root. It defines the prime directives, the architecture, what to build, what NOT to build, and the coding conventions. Obey Section 1 above all else.
- **As a briefing:** Sections 2–9 are the thesis and the technical bottom. Sections 10–18 are execution.
- **When in doubt, re-read Section 1 (Prime Directives) and Section 4 (Scope Boundary).** Those two sections are what keep this a company instead of a blog post.

---

## 1. PRIME DIRECTIVES (non-negotiable)

1. **Build ON the delegation primitive; do not rebuild it.** Biscuit (public-key, offline-attenuating capability tokens) and AIP's Invocation-Bound Capability Token (IBCT) chain already exist, are open-source, sub-millisecond, and reject 100% of *known structural* attacks. Reimplementing them is not the company. Use their SDKs directly.
2. **Only ever attack a CLAIMED property.** An exploit that breaks a system's *published non-goal* ("of course a signature doesn't prove ground truth") is a blog post. An exploit where a verifier **accepts what it should reject against a property it claims to guarantee** is a company. Every demo must pass this bar.
3. **Lead with omission / equivocation, not semantic intent.** The completeness/equivocation gap is a *theoretical boundary* (you cannot detect the absence of X by reading a log that doesn't contain X; forked log views are unsolvable without a shared witness). That makes it undismissible. "Intent verification" is partly non-crypto and gets waved away. Lead the first exploit and the first product with the witness/omission problem.
4. **Do not pitch "we verify intent" semantically.** Pitch "we prove the action set is complete, attributed across orgs, and independently attested." That is the crypto-enforceable version. Overclaiming intent verification kills credibility with any serious cryptographer.
5. **Never quote a number, repo, arXiv ID, or spec claim you have not personally reproduced from the primary source.** Much of the research in this doc came from a fast synthesis pass (see Section 16). Treat every citation as *unverified until reproduced*. Re-derive benchmarks yourself; confirm repo/spec facts against the actual files before they enter a deck or a conversation with an investor.
6. **Fail closed.** The verifier rejects on any unresolved step. Security posture is default-deny.
7. **The Day-12 honesty gate is real (Section 9).** If by Day 12 no verifier accepts what it should reject against a claimed property, STOP and re-scope. Do not rationalize a non-goal exploit into a company.

---

## 2. MISSION & CONTEXT

**What's happening in the world:** AI agents are becoming economic actors that delegate tasks to *other* companies' agents and pay each other autonomously. The identity/authorization rails for this are being poured right now (Google AP2, Mastercard Verifiable Intent, FIDO Agentic Auth WG, Cloudflare Web Bot Auth, Visa Trusted Agent Protocol). These rails solve the **single hop**: one human authorizes one agent for one action.

**The gap:** the moment a task crosses three or more agents across organizational trust boundaries — the actual future — no deployed mechanism can prove, locally and without a callback, *which human principal is accountable at hop 3–4*, *that the reported action set is complete*, or *that self-reported completion is honest*. This is stated plainly in the WIMSE cross-org delegation problem statement and the AI-identity survey (Section 15).

**What we build:** the layer above the delegation chain — a shared-witness/transparency anchor for **completeness and non-equivocation**, an **independent completion-attestation** mechanism (the fix AIP names but doesn't build), and an **adversarial conformance suite + hardened verifier** across the competing drafts.

**Why us:** the intersection of offensive security (attack the drafts), agent systems (wrap MCP/A2A/HTTP), and cryptography (build the witness/anchor + completeness/attribution proofs). That intersection is rare. See Section 12 for the role split and the gate.

---

## 3. THE THESIS / THE SECRET / WHY NOW

**The contrarian truth:** everyone assumes agent trust is "solved" by the rails being poured. It is not — it is solved for the single hop and wide open for recursive, cross-org delegation, which is where the money, the liability, and the disputes concentrate.

**Why now (the forcing functions):**
- Agent-to-agent commerce rails are being standardized *this year* — you cannot start a rails-adjacent trust company after the rails set.
- Regulatory teeth: EU AI Act auditability obligations create a forced compliance budget.
- Payment-network economics: chargeback / dispute adjudication for agent commerce needs court-survivable evidence.
- The competing IETF drafts (AIP, APS, DRP, EP, SPICE, HDP) all **explicitly punt** the same hard problems to "an external transparency log" that nobody has built cross-org.

**Why it's a company and not a feature:** the delegation token is commoditizing (good — it's our substrate). The **witness network** that anchors completeness across organizations has network effects a standard cannot absorb: a spec can define a log format, but someone still has to *run the cross-org anchor*, and it gets more valuable as more agents emit receipts to it.

---

## 4. SCOPE BOUNDARY — WHAT WE CAN AND CANNOT PROVE (read this twice)

This is the most important section. Overclaiming here is the fastest way to lose credibility.

**We CAN cryptographically prove:**
- Every delegation block is authentic and signed (Biscuit/AIP already do this — we reuse it).
- Authority narrowed monotonically across hops (never widened) — attenuation (reused).
- The delegation chain is **complete** — no hop was silently omitted — *provided the action was committed to a witnessed transparency root* (our layer).
- The log is **non-equivocating** — no forked views to different observers — *via consistency proofs + gossip* (our layer, CT discipline).
- Completion was **independently attested** rather than self-reported — *as strong as the attester's visibility* (our layer).
- Which principals are in the chain and their delegation relationships (attribution of the *chain*).

**We CANNOT prove (do not claim these):**
- That a recorded action digest corresponds to what physically happened in the world. **A witness anchors what was reported, not ground truth.** If an agent controls its own execution environment and commits a truthful digest of a *fabricated* "right" action, the log faithfully anchors a lie.
- Semantic intent match ("the agent's purpose was legitimate") as a pure cryptographic guarantee. We reduce a *subset* of intent violations to detectable *omissions*; we do not solve semantic intent.
- Anything stronger than the weakest independent attester in the chain.

**The honest company scope, in one sentence:** *We prove the delegation chain is complete, monotonic, cross-org-attributable, and non-equivocating, and that completion was independently attested rather than self-reported — and the strength of the attestation is exactly the strength of the attester's visibility into ground truth.* Sourcing cheap, high-visibility independent attestation is the core research risk and belongs on every risk slide.

---

## 5. PROBLEM DECOMPOSITION — SOLVED / CROWDED / OPEN

| Sub-problem | Status | Our seam? |
|---|---|---|
| Per-hop authenticity & integrity | Solved (Ed25519/ECDSA + content-addressing) | No |
| Recursive multi-hop chaining | Crowded (AIP, APS, DRP, HDP, SPICE) | No |
| Monotonic attenuation (narrow-only) | Crowded (AIP/Biscuit, APS lattice, DRP subset) | No |
| Cross-org offline verification (no callback) | Mostly solved (APS imported roots, HDP, EP) | No |
| **Omission / completeness** | **Open** (all punt to "external log"; theoretical limit) | **YES — lead here** |
| **Equivocation (forked log views)** | **Open** (needs shared witness; unsolvable without one) | **YES — lead here** |
| **Self-reported completion honesty** | **Open** (AIP explicit non-goal; names counter-signing as unbuilt fix) | **YES** |
| **Multi-principal legal attribution across orgs** | **Open** (AIP partial; APS punts attribution; survey gap #2) | **YES** |
| **Malicious-within-scope / intent integrity** | **Open, partly non-crypto** (reduce a subset to omission) | Partial — do NOT overclaim |
| **Collusion detection** | **Open** (needs cross-org audit correlation) | Adjacent |
| Revocation (offline, bounded staleness) | Partial (AIP v1 none; APS cascade) | Adjacent |
| Adversarial conformance / attack suite (cross-draft) | **Does not exist** | **YES — the fundraise artifact** |

---

## 6. ARCHITECTURE — SUBSTRATE vs OUR LAYER

### Substrate (integrate, do not reinvent)
- **Biscuit** (`biscuit-auth/biscuit`, Eclipse Foundation): public-key (Ed25519) capability tokens, offline attenuation, Datalog policy, revocation ids. This is the per-hop primitive. Learn Datalog in an afternoon.
- **AIP / IBCT** (closest prior art): append-only token, one signed block per hop.
  - Block 0 (Authority): root identity, initial scopes, budget ceiling, max depth, expiry.
  - Block N (Delegation): delegator→delegatee, attenuated scope, **mandatory purpose/context field**.
  - Block N+1 (Completion): result hash, verification status, cost — **self-reported by default** (this is the seam).
  - Transport: a token in an HTTP header on every tool call (mirror AIP's `X-AIP-Token`).
- **Rails we sit ON (never against):** AP2 (agent payment mandates), MCP (agent→tool), A2A (agent→agent), Web Bot Auth (per-request Ed25519 header signing). AP2 binds a mandate to a *user, not a chain* — its own spec names "Delegated Trust" and "Temporal Gaps" as open. That seam is ours.

### Our layer (the three deliverables)
1. **Shared-witness / completeness anchor** — a cross-org transparency log (SCITT-architecture) publishing signed Merkle roots over agent-action events, with **consistency proofs + gossip** (Certificate Transparency discipline) so a forked/rewritten log is caught. Each action emits a receipt committing to (a) the delegation chain it acted under, (b) the action digest, (c) the previous root. An action with no inclusion proof against the current root is **provably missing** → omission becomes detectable.
2. **Independent completion attestation** — replace AIP's self-reported completion block with a **counter-signed** (delegator verifies) or **third-party-attested** block. Binds: requested action digest + delegation chain + observed outcome digest + witness inclusion proof. This is the exact fix AIP names and does not build.
3. **Adversarial conformance suite + hardened verifier** — a claim-to-attack matrix across AIP/APS/DRP/EP; a verifier that catches cross-binding/receipt-splicing, presenter-controlled sufficiency bar, inconsistent canonical action digest, log equivocation, and omission; and a conformance certification ("SOC 2 for agent authorization").

### The `verify()` algorithm we ship
1. Resolve + verify every delegation-block signature. *(reuse AIP/Biscuit)*
2. Confirm monotonic attenuation across the chain. *(reuse)*
3. **[OURS]** Verify the action digest is bound to the declared purpose + the delegation chain.
4. **[OURS]** Verify an inclusion proof of the action against a witnessed transparency root (completeness).
5. **[OURS]** Verify the completion attestation is independently signed (not self-reported) and its outcome digest matches the observed action.
6. **[OURS]** Cross-check the root against gossip/consistency proofs (non-equivocation).
7. Fail closed on any unresolved step.

---

## 7. BUSINESS FORM (decide before Day 3 — it sets the first exploit)

Four candidate forms; standards absorption is the existential risk, so choose the form a standard **cannot** absorb:

- **★ Hosted witness / transparency network (RECOMMENDED).** The shared cross-org anchor every receipt log needs but nobody runs. Network effects; a spec can define the format but someone must run the anchor. **This is the default choice.** → It means the *first exploit is equivocation/omission* and the *first product is the witness*.
- Conformance certification ("SOC 2 for agent authorization") — mandatable by regulators/payment networks, but commoditizable (APS already ships a scoped conformance suite).
- Enforcement gateway / verifier API — called at authorization time; strong but closer to a feature.
- Regulated audit-trail / dispute-evidence product — court-survivable evidence for agent commerce.

**Decision:** default to the **hosted witness network**, with the conformance suite as the wedge/credibility artifact and the verifier API as the near-term integration surface. Revisit only if a design partner pulls hard toward certification.

---

## 8. POSITIONING — WHAT WE SAY / DON'T SAY

**Say:**
- "We're the witness and independent-attestation layer for cross-org agent delegation."
- "Everyone can prove the token narrowed; nobody can prove the chain was complete, honestly reported, and attributable across companies. We do that."
- "We build on AIP and Biscuit. We ship what they explicitly punt."
- Urgency stat (verify first): a large share of scanned MCP servers reportedly lacked authentication — the house is already delegating money with no lock. *(Reproduce before quoting.)*

**Don't say:**
- "We verify agent intent." (Partly non-crypto; you'll get torn apart.)
- "We invented the delegation protocol." (You didn't; you build above it.)
- "The city/world/judiciary of AI agents." (Grandiosity trap. Investors fund a purchase order, not a vibe. Adjudication is a *later* feature you earn by first being the trusted record.)
- Any number you haven't reproduced (Directive 5).

**Deck arc:** open on the urgency stat → the single-hop rails everyone's building → the multi-hop gap (WIMSE/survey, in credible bodies' words) → the omission/equivocation exploit against a real verifier → our hardened verifier + witness catching it → the network business → why this team.

---

## 9. FALSIFIABILITY — THE DAY-12 KILL TEST

**The test:** build a 3-hop cross-org chain using AIP's own SDKs (Human → Agent A → Agent B → Agent C's tool, with a self-reported completion). Produce **all-valid signatures** in a scenario where one of:
- (a) in-scope action for a *different* declared purpose,
- (b) an *omitted* action not represented in the chain,  **← lead with this**
- (c) dishonest self-reported completion.

Show AIP's verifier returns **VALID** (correct — these are its non-goals). Show **our** hardened verifier + witness returns **INVALID** for the *same artifact* (catches omission via missing inclusion proof; catches dishonest completion via absent independent attestation). That before/after is the demo, the paper, and the raise.

**Why (b) leads:** omission/equivocation is a theoretical boundary, so no reviewer can dismiss it as "of course signatures don't prove ground truth." (a) and (c) are vulnerable to "your witness only anchors what the agent chose to report" — true, per Section 4 — so they are supporting demos, not the headline.

**The honesty gate:** if by Day 12 every "break" is really an in-scope action AIP's attenuation already rejects, you've hit the trap. Stop, re-scope, or fall back (Section 12). The 7/10 fundability only materializes when a real verifier accepts what it should reject against a *claimed* property.

---

## 10. 30-DAY ROADMAP

**Day 0 (before code):** decide business form (Section 7 → hosted witness network). Write the one-paragraph thesis. No further idea search — the research phase is closed.

**Days 1–2 — Claim-to-attack matrix.** Clone the AIP, APS, and Biscuit repos. For each: list claimed verifier guarantees, admitted non-goals (use AIP's limitations section verbatim), and the suspected exploit class. Pick the one exploit where valid artifacts cause wrong acceptance. Reproduce each system's headline benchmark yourself (Directive 5).

**Days 3–10 — One concrete exploit (the flag-plant).** Build the 3-hop chain. Land the **omission** exploit first (then optionally dishonest-completion). All-valid signatures; AIP verifier says VALID; our check says INVALID.

**Days 11–16 — Minimal mitigation.** Hardened verifier + witness inclusion-proof check (and/or independent completion attestation) that catches the exploit. Clean, reproducible before/after.

**Days 10–14 (parallel) — Standards presence.** Join WIMSE, FIDO Agentic Auth, and SCITT mailing lists. After the exploit is reproducible, post the residual-risk gap analysis as **conformance guidance**, never as "your draft is broken." Authority compounds and is free.

**Days 17–22 — Five design-partner conversations.** Agent-payment infra builders whose agents already transact across companies (candidates in Section 13). Opener: *"When your agent's spend goes wrong across a vendor chain, can you prove whose authority produced it — and prove nothing was omitted?"* Discovery, not pitch.

**Days 23–30 — Fundraise artifact.** Publish the attack paper + OSS hardened verifier + a demo video. YC Fall application (deadline Jul 27) leads with the exploit + mitigation, not the vision. Pitch: *"We are the adversarial conformance and witness layer for agent authorization — we break the drafts, then ship the hardened reference and run the anchor."*

---

## 11. TECH STACK, REPO STRUCTURE, CONVENTIONS

**Languages:** Rust for the witness/anchor core and verifier (performance + it matches Biscuit's core); Python + TypeScript SDKs for integration (matches AIP/APS ecosystems and design-partner reach). WASM build of the verifier for in-browser/edge.

**Crypto:** Ed25519 for signatures (match the ecosystem); design for **algorithm agility from v1** — AIP defers post-quantum, which is an easy differentiator and matches our long-term thesis. Canonicalize with RFC 8785 (JCS); content-address everything.

**Transparency log:** SCITT-architecture; Merkle tree with CT-style consistency proofs (RFC 6962 discipline) + gossip; pluggable root anchor.

**Suggested repo layout:**
```
/warrant
  /crates
    /witness        # Rust: transparency log, Merkle roots, consistency proofs, gossip
    /verifier       # Rust: the verify() algorithm; fail-closed
    /attestation    # Rust: counter-sign / third-party attestation blocks
  /sdk
    /python         # thin bindings + integration helpers
    /typescript     # thin bindings + integration helpers
  /conformance      # cross-draft adversarial suite (AIP/APS/DRP/EP)
  /exploits         # reproducible attack harness (the flag-plant); deterministic
  /integrations     # MCP / A2A / AP2 / Web Bot Auth wrappers
  /docs             # spec notes, threat model, verification methodology
  CLAUDE.md         # this file
```

**Conventions:**
- Default-deny; every verifier path fails closed with a typed error naming the failed property.
- Every exploit in `/exploits` ships with a deterministic harness that regenerates the attack against pinned upstream versions.
- No secret-based auth anywhere in the trust path (HMAC dies at trust boundaries — that's why we're on public-key primitives).
- Tests assert against *claimed* properties of upstream systems; comment each test with the exact claim it targets.
- Reproduce-before-quote: any benchmark committed to `/docs` must include the script that produced it.

---

## 12. TEAM ROLES & THE GATE

- **Cryptography (Udaya):** owns the witness/anchor construction, completeness + attribution proofs, attestation binding, algorithm agility. **This is the load-bearing half.**
- **Agent systems (Satyam):** owns MCP/A2A/AP2 integration, wrapping AIP/Biscuit, the runtime path.
- **Offensive security (Udaya, OSCP):** owns the attack harness and the claim-to-attack matrix.

**The gate (decide by Day 12):** the entire company reduces to the witness/anchor crypto. If that gets genuinely built (not "SDKs wrapped"), the thesis is ~7.5/10 fundable. **If the crypto half is not truly owned, this collapses to ~4/10 — ship the attack paper as research and fall back to the agent-native inference runtime.** Be honest at the gate; do not narrate progress you don't have.

---

## 13. DESIGN-PARTNER TARGETS (verify current status before outreach)

Agent-payment / cross-org infra builders who feel the "prove it, don't trust the vendor log" pain today (transaction volume is still early — sell to the *builders*, not the volume):
- Agent-payment infra: Nevermined, Crossmint, Cobo, Circle, Skyfire, Payman, Catena Labs, Fewsats.
- x402 / AP2 ecosystem: services listed on x402 Bazaar; per-inference/per-crawl monetizers (e.g., per-inference billers, Cloudflare pay-per-crawl-style providers).
- Standards contributors: WIMSE, FIDO Agentic Auth WG, SCITT, IETF Web Bot Auth WG participants (design partners *and* your credibility panel).

Reach via public LinkedIn/X/Discord with the Section 10 opener. Do not fabricate contacts.

---

## 14. RISK REGISTER

| Risk | Likelihood | Mitigation |
|---|---|---|
| POC dismissed as attacking a non-goal | High | Only attack claimed properties; **lead with omission/equivocation** (a theoretical boundary, not a non-goal) |
| Standards bodies absorb the fix | Med-High | Be the **hosted witness network**, not a spec; ship the reference impl and run the anchor |
| Witness only anchors reported data, not ground truth | **Real (core)** | State the scope boundary (Section 4) openly; source high-visibility independent attestation; never overclaim |
| "Intent" is non-crypto | Real | Pitch "complete + independently attested," not "intent verified" |
| APS already ships a conformance suite | Medium | Ours is **cross-draft + adversarial**, not APS-scoped conformance |
| Premature market / low agent-txn volume | Medium | Sell to funded infra builders now; EU AI Act + payment-network dispute economics create forced budget |
| Team can't own witness crypto | Real | Day-12 gate; fall back to attack-paper-as-research or inference runtime |
| Unverified research entering the deck | Med-High | Directive 5 — reproduce before quoting; verify every repo/arXiv/number/spec claim |

---

## 15. READING LIST (prioritized — verify each before quoting)

1. **AIP** (Agent Identity Protocol / IBCT) — closest prior art; read its **limitations section hardest**, it names your seams. ★★★
2. **AI-identity survey** (five gaps: semantic intent, recursive delegation accountability, agent identity integrity, governance enforcement, operational sustainability) — your opening slide. ★★★
3. **WIMSE cross-org delegation problem statement** — enumerates the requirements (R1–R9); proposes no mechanism. Your spec. ★★★
4. **APS** (Agent Passport System) — most complete competitor; understand its lattice + receipts + its conformance suite. ★★
5. **Biscuit** — your substrate; Clever Cloud tutorial + biscuitsec.org spec; learn Datalog. ★★
6. **Macaroons** — foundational attenuation paper (why offline narrowing works). ★
7. **DRP** / **EP-AEC** drafts — the transparency-log punt and the composition layer's "cross-binding attack." ★
8. **South et al.** (Authenticated Delegation) + **OpenID** whitepaper — credible voices; cite for *accountability*, not *intent*. ★
9. **AP2** repo — confirm the mandate format from the actual spec files before quoting. ★
10. **SCITT** + **Certificate Transparency (RFC 6962)** — the witness/gossip discipline you build on. ★

*(All arXiv IDs, draft names, and repos in this project came from a synthesis pass and MUST be re-verified against primary sources — see Section 16.)*

---

## 16. VERIFICATION DISCIPLINE

The research underlying this project was assembled fast from mixed sources (papers, IETF drafts, repos, third-party analyses, and two AI research passes). **None of it is trusted until reproduced.** Before any claim reaches an investor, a design partner, or a published paper:
- Confirm the paper/draft/repo exists and says what we think it says — from the primary source, not a summary.
- Re-run any benchmark yourself; commit the script.
- For AP2's mandate format and any "100% rejection / sub-ms / N-byte" figures, reproduce or drop them.
- Where a claim can't be verified, say "unconfirmed" out loud rather than laundering it into fact.

This is not bureaucracy — a single fabricated stat in a security pitch ends the meeting.

---

## 17. GLOSSARY

- **Attenuation** — narrowing a token's authority (never widening), offline, without the issuer.
- **Delegation chain** — append-only sequence of signed blocks, one per hop, each attenuating from its parent.
- **IBCT** — Invocation-Bound Capability Token (AIP's per-hop object).
- **Witness / transparency log** — append-only Merkle-rooted log with consistency proofs + gossip; catches omission and equivocation.
- **Equivocation** — a log presenting different histories to different observers; unsolvable without a shared witness.
- **Omission** — a real action absent from the record; undetectable by reading a log that doesn't contain it → requires inclusion-proof-against-witnessed-root.
- **Independent attestation** — a completion signed by a party other than the executing agent (counter-signed or third-party).
- **Cross-org attribution** — resolving which human principal is accountable when the chain crosses trust boundaries.

---

## 18. DEV WORKFLOW (fill in as the repo grows)

```
# build
cargo build --workspace
# run the verifier tests (each asserts a claimed upstream property)
cargo test -p verifier
# regenerate the flag-plant exploit against pinned upstream versions
cargo run -p exploits --bin omission_3hop
# run the cross-draft adversarial conformance suite
cargo run -p conformance
```

**Standing instruction to any agent working this repo:** obey Section 1. Build on the substrate, attack only claimed properties, lead with omission/equivocation, never overclaim intent, verify before quoting, and fail closed.
