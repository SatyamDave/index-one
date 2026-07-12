# Claim-to-attack matrix

> **Discipline (CLAUDE.md Directive 2).** We only ever attack a **claimed** property.
> An exploit against a system's *published non-goal* is a blog post; an exploit
> where a verifier **accepts what it should reject against a property it claims to
> guarantee** is the company. Every row below is tagged so the two never blur.
>
> **Upstream-status honesty (Directive 5).** For each attack we state whether the
> "accepts it" side runs a **real upstream verifier**, a **faithful reimplementation**
> of the format, or is **modeled** in IndexOne's own crates. Do not present a
> side-by-side that does not exist.

All draft facts are primary-source verified (datatracker, 2026-07-11/12); draft
versions move — re-pin before quoting.

---

## 1. Property map — what each system proves

Legend: **✓** solved/claimed · **~** partial · **✗** explicit non-goal / out of scope · **—** n/a.

| Property | Biscuit | AIP | APS | DRP | EMILIA/EP-AEG | AP2 | **IndexOne adds** |
|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| Per-hop authenticity & integrity | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | reuse (substrate) |
| Monotonic attenuation (narrow-only) | ✓ | ✓ | ✓ | ~ | ~ | ~ | reuse |
| Cross-org offline verification | ✓ | ✓ | ✓ | ~ | ✓ | ~ | reuse |
| **Omission / completeness** | ✗ | ✗ | ✗ *(defers to external log)* | ~ *(SHOULD → SCITT log)* | ~ *(registrable to log)* | ✗ | **log-backed non-inclusion + inclusion-vs-witnessed-root** |
| **Equivocation / log-fork** | — | ✗ | ✗ | ~ *(names it; defers)* | ~ | ✗ | **consistency proofs + witness cosigning (CT discipline)** |
| **Self-reported completion honesty** | — | ✗ *(admitted non-goal)* | — | ~ | ~ | ✗ | **independent + k-of-n attestation** |
| **Cross-org authority attribution** | ~ | ~ | ✗ *(punts)* | ~ | ✓ *(its focus)* | ✗ *(single-hop blind)* | **chain-of-authority to a trusted root** |
| Revocation / non-inclusion | ~ *(revocation ids)* | ✗ | ~ *(cascade)* | ~ | — | ✗ | **sparse-Merkle non-inclusion, log-backed** |

Draft anchors (verified): AIP `draft-prakash-aip-00` (27 Mar 2026); APS `draft-pidlisnyi-aps-02` (04 Jul 2026, ships a conformance suite); DRP `draft-nelson-agent-delegation-receipts-10` (13 Jun 2026); EMILIA/PEDIGREE `draft-rampalli-cross-org-delegation-mapping-05` (06 Jul 2026, EP-AE**G**). HDP `draft-helixar-hdp-agentic-delegation-00` — **not re-verified this round; flag before quoting.** All five are **individual I-Ds, none WG-adopted.**

Verbatim, quotable stances (primary source):
- **AIP** concedes self-reported completion is a non-goal ("trust escalation options … not enforced in v1").
- **APS**: *"A chain does not, by itself, prove completeness … deployments needing it MUST specify an external mechanism … an append-only log with inclusion proofs. This document does not define such a mechanism."*
- **DRP §5.2**: *"Implementations SHOULD submit action log roots to an independently monitored transparency log following the SCITT architecture … to detect truncation and log fork attacks."*
- **SCITT `draft-ietf-scitt-architecture-22`**: inclusion proof only; *"Revocation strategies for compromised keys are out of scope"*; charter non-goal #3: *"Define methods to prevent authenticated issuers from making false claims."*
- **WIMSE `draft-ietf-wimse-arch-08` §3.4.11**: each hop *"MUST explicitly scope and re-bind the security context"* — per-hop only; end-to-end provenance left to implementations.

---

## 2. The attacks — claimed-property? · upstream status · reproduced-by

| # | Attack | Target property | Claimed by target? | "Accepts it" side | Reproduced by | IndexOne verdict |
|---|---|---|---|---|---|---|
| **(b)** | **Omission** — an action absent from the record | completeness | **Implication** of AIP's signature-only model (not a verbatim admitted non-goal) | **Real AIP SDK** (`agent-identity-protocol==0.3.0`) + IndexOne stand-in | `exploits/real_aip/sidebyside.py` · `omission_3hop` · verifier test · conformance | `VerifyError::Omission` |
| **(c)** | **Dishonest self-reported completion** | completion honesty | **AIP verbatim non-goal** (safest headline caveat) | **Real AIP SDK** + stand-in | `real_aip/sidebyside.py` · `omission_3hop` · verifier test · conformance | `VerifyError::Attestation(NotIndependent)` |
| **(a)** | **In-scope action, different declared purpose** | purpose↔action binding | claimed (via `bind_action`) | IndexOne verifier only | verifier tests `action_bound_to_a_different_purpose_is_rejected` (+ `requested_action_differs_from_witnessed_is_rejected`) | `VerifyError::PurposeMismatch` |
| **eq** | **Log equivocation / fork** | non-equivocation | claimed by any log-anchored draft (DRP names it) | modeled | `witness::reconcile_heads` tests · conformance | `EquivocationError` / `VerifyError::Equivocation` |
| **sock** | **Sockpuppet / Sybil attester** | independent attestation | IndexOne's own claim (audit Finding 1) | IndexOne verifier only | verifier test `sockpuppet_key_attestation_is_rejected` | `VerifyError::AttesterNotAnchored` |
| **attr** | **Cross-org attribution (forged hop)** | authority provenance | **AP2 single-hop non-goal** — *supporting demo, not headline* | **Faithful SD-JWT-VC reimpl** (not Google's SDK) + real Ed25519 chain | `exploits/real_ap2/sidebyside.py` · `ap2_attribution` | chain does not trace to trusted root → INVALID |

### The headline vs the supporting cast
- **Headline (undismissible):** **(b) omission** + **(c) self-report**, against the **real AIP reference SDK**. Omission is a *theoretical boundary* — you cannot detect the absence of X by reading a log that lacks X — so no reviewer can wave it away as "of course signatures don't prove ground truth."
- **Supporting only:** **(a)** and **attr** exercise non-goals or rest on an opaque digest (below), so they are demos, not the raise (CLAUDE.md §9).

---

## 3. Honesty caveats that MUST accompany any paper/deck

1. **Real upstream SDK runs only for AIP.** The AP2 side is a **faithful implementation of the SD-JWT-VC format** (ES256/P-256, `cnf` key-binding), **not** Google's reference AP2 SDK (Python-from-GitHub, no PyPI). DRP / EP-AEG / HDP are **modeled** against IndexOne's own verifier — no reference impl is run.
2. **Same scenario, native token formats — not identical bytes.** AIP and IndexOne encode the same 3-hop delegation each in its own format.
3. **Omission-vs-AIP is an implication** of AIP's model; only **self-report** is AIP's *verbatim admitted* non-goal. Frame each accordingly.
4. **AP2 supports delegation chains** (v0.2, SD-JWT `cnf`) — do **not** claim otherwise. The AP2 demo attacks the single-hop *non-goal* (mandate verification is blind to cross-org provenance) and is a supporting demo, per Directive 2.
5. **Attack (a) is now a real purpose binding** (`VERIFIER_AUDIT.md` Finding 2, resolved). `action_digest = bind_action(purpose, params)` and `verify_with_purpose` reject an action witnessed under a purpose different from the final hop's — `VerifyError::PurposeMismatch`. Still honest scope (CLAUDE.md §4): binds to the *declared* purpose, not ground truth. Remaining polish: promote it into the `omission_3hop` flag-plant binary + conformance (below).
6. **A witness anchors what was reported, not ground truth** (CLAUDE.md §4). The strength of any attestation is exactly the attester's visibility.
7. **Any benchmark / "sub-ms / 100%-rejection / N-byte" figure is self-reported** unless re-run from a committed script (§16).

---

## 4. Gaps to a fully reproducible artifact (tracked)

- [x] Install + **hash-pin** the real AIP SDK — `exploits/real_aip/requirements.lock.txt` (`pip-compile --generate-hashes`, all-platform hashes); a CI job (`.github/workflows/attack-artifact.yml`) that **fails** if the upstream can't run or IndexOne doesn't reject (`sidebyside.py --require-real` turns the local soft-skip into a hard check). Confirmed live: real `ChainedToken.authorize` → VALID, composed `verify()` → Omission / NotIndependent.
- [ ] Commit **golden vectors**: the exact upstream token (or bytes + SHA-256) and IndexOne artifact + expected verdicts, so a reviewer reproduces byte-for-byte.
- [ ] Import **APS's shipped conformance fixtures** → a second real upstream beyond AIP.
- [~] Purpose↔digest binding **built** (`bind_action` + `verify_with_purpose`, `VerifyError::PurposeMismatch`); still to do — promote **(a)** into the `omission_3hop` flag-plant binary + conformance suite (verifier-tested today).
- [ ] One-command reproduce (`make reproduce`) + quarantine the `FAKE-SIG` placeholder in `integrations/attack/harness.py`.
