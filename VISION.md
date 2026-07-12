# VISION — Warrant

> *Codename provisional. A warrant is delegated authority that stays accountable and on the record — which is the whole company.*

**The one-liner:** Warrant is the witness and independent-attestation layer for cross-organization AI agent delegation. When agents act and pay on behalf of humans across company lines, Warrant proves the chain of authority was complete, attributable, and honestly reported — not just signed.

---

## The world we're building for

Software is stopping being something people operate and starting to be something that acts. AI agents already research, decide, transact, and — increasingly — hand work to *other companies'* agents to finish. An agent hires an agent, which pays a third agent for compute or data, and real money and real consequences move with no human watching each hop.

The identity and payment rails for this are being poured right now — Google's AP2, Mastercard's Verifiable Intent, the FIDO Agentic Authentication working group, Cloudflare's Web Bot Auth, Visa's Trusted Agent Protocol. Trust, as Mastercard put it, is becoming the product.

But every one of those rails solves the **single hop**: one human, authorizing one agent, for one action. That is the easy 10%.

## The problem no one owns

The moment a task crosses three or four agents across organizations that don't share infrastructure — the actual shape of the agent economy — three questions have no answer:

1. **Whose authority produced this?** When a chain of agents spans companies, no deployed mechanism can prove, locally and without phoning home, which human principal is accountable at the third or fourth hop.
2. **Is the record complete?** An append-only log proves what it contains can't be changed. It says nothing about what was silently left out. You cannot detect the absence of an action by reading a log that doesn't contain it.
3. **Was the report honest?** Agents today mark their own homework — completion is self-reported by the very party whose work is being judged.

This is where the money, the liability, and the disputes will concentrate. It is also, per the field's own problem statements and surveys, explicitly unsolved. Every competing standard punts these to "an external transparency log" that nobody has built across organizations.

## What Warrant is

Warrant is the layer **above** the delegation chain — we build on the existing token primitives (Biscuit, AIP), we don't rebuild them. We add the three things they leave open:

- **A cross-organization witness.** A shared transparency anchor that makes omission detectable and equivocation impossible — the piece the math says cannot live inside a signed receipt, so it cannot be a feature of someone else's token.
- **Independent completion attestation.** Replacing "the agent says it's done" with a proof signed by someone other than the agent.
- **An adversarial conformance layer.** We break the competing drafts where a verifier accepts what it should reject, then ship the hardened reference — becoming the named authority on what "trustworthy agent delegation" actually means.

## What Warrant honestly is *not*

We are precise about our limits, because overclaiming here is how you lose the room. A witness proves what was *recorded*, not physical ground truth; the strength of an attestation is exactly the visibility of the attester. We do not claim to read an agent's mind or verify its semantic intent by cryptography. We prove the chain is **complete, monotonic, cross-org-attributable, non-equivocating, and independently attested** — and we say so plainly.

## Why now

You cannot start a rails-adjacent trust company after the rails set — and they're setting this year. Regulatory auditability obligations create a forced budget. Payment-network dispute economics need court-survivable evidence. And the competing standards have all published the same gap while shipping nothing to fill it. The window is open and it is timed.

## Why this team

Warrant sits at one intersection: **offensive security** (to break the drafts and prove the gap), **agent systems** (to wrap the real protocols agents use), and **cryptography** (to build the witness, the completeness and attribution proofs, and the attestation binding). Very few teams span all three. That intersection is the moat, not a slogan.

## Where this goes

- **Near term:** the hardened verifier and the cross-organization witness network — the anchor every receipt log needs and no one runs.
- **Mid term:** the conformance certification that regulators and payment networks can mandate, and the dispute-evidence product that survives a courtroom.
- **Long term:** as agents become the majority of economic actors online, the witness network becomes the neutral place their actions are proven — the trust substrate the agent economy settles against. Whoever runs that anchor, with network effects and standards fingerprints, holds a position a spec cannot absorb.

We are not building an agent, a model, or a router. We are building the thing that lets anyone trust them.

---

*Companion documents: `CLAUDE.md` (build context + guardrails), `ROADMAP.md` (execution + decision log).*
