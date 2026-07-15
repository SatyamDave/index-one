# IndexOne — Seed Deck Narrative

Slide-by-slide arc (CLAUDE.md §8), each grounded in a real, reproducible
artifact. Lead with the exploit and the mitigation, not the vision (CLAUDE.md
§10, YC-style). Every number must be reproduced before it goes on a slide
(Directive 5). ⚠️ marks the slides only a human can fill.

---

**1 — Title / one-liner.**
"IndexOne — the witness and independent-attestation layer for cross-org AI-agent
delegation. We prove an agent action chain is complete, attributed, and honestly
reported — not just signed."

**2 — Urgency.** The rails for agent-to-agent commerce are being poured *this
year* (AP2, Visa TAP, Mastercard Agent Pay, FIDO Agentic Auth, Web Bot Auth).
Trust is becoming the product.
- ⚠️ Optional urgency stat (e.g., the "large share of MCP servers lack auth"
  figure) — **reproduce from primary source before using, or drop it** (§8).

**3 — The gap everyone's building past.** Every rail solves the **single hop**:
one human authorizes one agent for one action. The moment a task crosses 3–4
agents across organizations — the real shape of the agent economy — three
questions have no answer: *whose authority produced this? is the record complete?
was the report honest?*
- Grounded: WIMSE and the AI-identity survey name this gap (cite the *corrected*
  framing from `docs/RESEARCH_VERIFICATION.md` — §3.3.8/§3.3.4, not the fabricated
  §3.3.9/R1–R9).

**4 — The exploit (the flag-plant).** On a real 3-hop cross-org chain with
all-valid signatures, the **real AIP reference verifier** returns VALID — while
an action was never witnessed (omission) and a completion was self-reported.
- Grounded: `make require-real` runs the *actual* `agent-identity-protocol` SDK.
  AIP's own §7 concedes completion is self-reported and counter-signing is "not
  enforced in v1." (Frame omission as a gap *we* identify, not AIP's printed
  non-goal — the honest framing that survives a cryptographer.)

**5 — Our verifier + witness catches it.** The *same* artifact: IndexOne's
composed `verify()` returns INVALID — omission caught via a missing witness
inclusion proof, self-report caught via absent independent attestation. Fail
closed, offline, no callback.
- Grounded: `make demo` (one command: chain → witness → verify, accepts the
  honest action, rejects omission + self-report, against a live witness service).
  `docs/BENCHMARKS.md`: 3-hop verify in the hundreds of microseconds; the
  independent-attestation layer costs ~+120 µs — **lead with what we catch, not
  speed** (we claim no speed advantage; AIP's verifier is right there with us).

**6 — Why it's a company, not a feature.** The delegation token is commoditizing
(good — it's our substrate: Biscuit/AIP). The **cross-org witness network** that
anchors completeness has network effects a standard can't absorb: a spec defines
a format; someone still has to *run the anchor*, and it gets more valuable as more
agents emit receipts to it.
- Grounded: a real hosted witness service ships today (`services/witness`:
  persistent, crash-safe, RFC 6962 proofs, gossip/equivocation detection).

**7 — Honest scope (put this IN the deck — it earns credibility).** We prove the
chain is complete, monotonic, cross-org-attributable, non-equivocating, and
independently attested. We do **not** claim ground truth or semantic intent — a
witness anchors what was *reported*, and an attestation is only as strong as the
attester's visibility. Sourcing cheap high-visibility attestation is our core
research risk, and it's on this slide.

**8 — Traction / design partners. ⚠️ NEEDS HUMAN INPUT.**
- ⚠️ Design partners in conversation / piloting (the single biggest thing to fill
  — see `DESIGN_PARTNER_OUTREACH.md`).
- Grounded assets you *do* have: open-source hardened verifier + witness, a real
  AIP side-by-side, a one-command demo, machine-verification (125 core tests, 18
  property tests, ~12M fuzz executions), and an external crypto review in progress
  (see `AUDIT_SCOPE.md`).

**9 — Why this team.** The intersection of **offensive security** (break the
drafts), **agent systems** (wrap the real protocols), and **cryptography** (build
the witness + attestation). Few teams span all three.
- ⚠️ NEEDS HUMAN INPUT: founder bios (education, prior work, the OSCP + crypto
  evidence that makes "this team" credible, not a slogan).

**10 — The ask. ⚠️ NEEDS HUMAN INPUT.**
- ⚠️ Raise amount, instrument (SAFE?), target valuation.
- ⚠️ Use of funds (suggest: the external audit, the hosted witness network as a
  service, and design-partner integration engineering).
- ⚠️ Timeline / milestones (e.g., audit sign-off, first design partner live).

---

## Say / don't-say (CLAUDE.md §8)

**Say:** "the witness and independent-attestation layer for cross-org agent
delegation"; "everyone can prove the token narrowed; nobody can prove the chain
was complete, honestly reported, and attributable across companies — we do";
"we build on AIP and Biscuit; we ship what they explicitly punt."

**Don't say:** "we verify agent intent" (partly non-crypto); "we invented the
delegation protocol" (you didn't); "the city/judiciary of AI agents"
(grandiosity — investors fund a purchase order, not a vibe); any number you
haven't reproduced.

## Before this deck goes out — checklist

- [ ] Every stat reproduced from primary source (Directive 5 / `RESEARCH_VERIFICATION.md`).
- [ ] Scope-boundary slide (7) present and unhedged.
- [ ] ⚠️ Team, traction, and ask slides filled by the founders.
- [ ] The `make demo` / `make require-real` artifacts run clean on the demo machine.
- [ ] External audit at least *scheduled* (its existence de-risks the crypto slide).
