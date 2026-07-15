# IndexOne — Design-Partner Outreach

Five discovery conversations with agent-payment / cross-org infra builders who
feel the "prove it, don't trust the vendor log" pain today. **This is discovery,
not a pitch.** The goal is to learn whether the pain is real and urgent for them,
not to sell. Transaction volume in agent commerce is still early — you are
selling to the *builders* who will need this, not to today's volume.

## The opener (CLAUDE.md §10)

> *When your agent's spend goes wrong across a vendor chain, can you prove whose
> authority produced it — and prove nothing was omitted?*

That one question is the whole wedge. It is a question they cannot answer today,
and it is not a feature request — it's a liability they already carry.

## How to run these

- **Listen for the pain, don't present the product.** Ask: "When an agent you
  don't control acts across a vendor chain and money moves wrong, how do you
  reconstruct whose authority produced it today? What's your dispute story?"
- **The demo is the artifact, not the deck.** If it goes well, `make demo` shows
  the whole thing in one command: a cross-org chain witnessed and verified, with
  an omitted action and a self-reported completion both caught, against a live
  witness service. Real crypto, real AIP side-by-side (`make require-real`).
- **Stay inside the scope boundary (CLAUDE.md §4).** Say "we prove the chain is
  complete, attributed, non-equivocating, and independently attested." Do **not**
  say "we verify intent" or "we prove ground truth" — a witness anchors what was
  *reported*. Overclaiming here loses the credible ones fastest.
- **Ask for the design-partner relationship, not a sale:** "Would you pilot the
  witness against your real agent-to-agent flows and tell us where it breaks?"
- **Success = one company that will emit receipts to a witness against real
  flows.** That is the single most important thing missing from the raise.

## Message drafts

Each is short, specific, discovery-framed. **⚠️ Verify each company's current
focus and find the warm-intro path before sending — do not send cold if a warm
intro exists.**

### 1. Skyfire
> Hi [name] — you're building the payment + identity rails for AI agents. The
> piece I keep hitting: once an agent hands a task to *another company's* agent
> and money moves, no one can prove locally which human principal is accountable
> at hop 3, or that nothing was silently left out. We built the witness +
> independent-attestation layer that sits on top of rails like yours and closes
> exactly that. Not selling — I'd love 20 minutes to learn how you handle
> cross-vendor attribution and disputes today, and whether this is real pain for
> you.

### 2. Payman
> Hi [name] — Payman is making agents pay across boundaries, which is precisely
> where the "whose authority produced this spend" question gets hard. When a
> payment flows through a chain of agents you don't all control, can you today
> prove the chain was complete and honestly reported, not just signed? We built
> that proof layer (on top of AP2/x402-style rails, not against them). Would you
> be open to a discovery call — I want to understand your dispute/attribution
> story before I show anything.

### 3. Catena Labs
> Hi [name] — an AI-native financial institution is the sharpest version of this:
> agents transacting across orgs, with real liability at each hop. The gap we
> work on is proving, offline and without a callback, which human principal is
> accountable at hop 3–4 and that the action set is complete — the thing every
> delegation spec punts to "an external transparency log" nobody runs cross-org.
> We run that anchor. I'd value 20 minutes to hear how you're thinking about
> cross-org agent accountability and where you'd want this to plug in.

### 4. Nevermined
> Hi [name] — you're building agent-to-agent payments and monetization. Our
> question for you: when an agent pays another agent for compute/data across a
> vendor chain, and it later needs adjudication, can you reconstruct whose
> authority produced it and prove nothing was omitted? We built the
> witness/completeness + independent-attestation layer for exactly that. Purely
> to learn — how do you handle cross-agent attribution today, and is it a pain
> worth solving now?

### 5. Fewsats
> Hi [name] — per-request agent payments (x402/L402) are where "one agent, one
> action" meets "but who authorized the chain behind it." When a paid request is
> the tail of a multi-agent, cross-org delegation, the single-hop mandate can't
> prove the chain that led there — we demonstrate exactly that gap and close it.
> I'd love a short discovery call to understand whether cross-org attribution is
> a real problem in your flows yet, or still over the horizon.

## ⚠️ NEEDS HUMAN INPUT

- ⚠️ Warm-intro paths for each (LinkedIn/X/Discord/mutuals) — do not cold-send if a warm intro exists.
- ⚠️ Verify each company's current focus and the right person to reach (these drafts assume general positioning).
- ⚠️ Any additional targets from CLAUDE.md §13 (Crossmint, Cobo, Circle, Catena, x402 Bazaar services).
- ⚠️ Your calendar link / scheduling.
- ⚠️ Do **not** fabricate contacts or claims; keep every message inside the scope boundary.
