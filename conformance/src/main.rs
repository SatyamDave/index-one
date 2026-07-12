//! IndexOne conformance suite — cross-draft, adversarial.
//!
//! For each property a competing draft either claims or explicitly punts (facts
//! reproduced in `docs/RESEARCH_VERIFICATION.md`), this suite builds a real
//! artifact with the core crates and asserts the IndexOne verifier behaves
//! correctly: it **rejects** what the drafts leave open, and **accepts** the
//! honest case. It exits non-zero if any case fails.
//!
//! Honesty (CLAUDE.md §1.2, §4): each case encodes a claim WE reproduced from a
//! primary source, and tests IndexOne's own verifier — not the upstream SDKs.
//! We attack claimed/known-open properties, never a strawman.

use indexone_attestation::CompletionAttestation;
use indexone_chain::{Chain, ChainError, Principal, Scope};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};
use indexone_verifier::{verify, VerifiableAction, VerifyError};
use indexone_witness::{ActionReceipt, Digest, InclusionProof, Witness};

fn principal(id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        display_name: id.to_string(),
    }
}

fn scope(budget: u64, depth: u32) -> Scope {
    Scope {
        permissions: vec!["payments.charge".to_string()],
        budget: Some(budget),
        currency: Some("USD".to_string()),
        max_depth: depth,
        expires_at: 4_102_444_800,
    }
}

struct World {
    chain: Chain,
    root_key: PublicKey,
    executor: Ed25519Signer,
    attester: Ed25519Signer,
}

/// Human → A(org1) → B(org2) → C(org3); C executes, B (the delegator) can
/// independently attest.
fn build_world() -> World {
    let human = Ed25519Signer::from_seed([1u8; 32]);
    let a = Ed25519Signer::from_seed([2u8; 32]);
    let b = Ed25519Signer::from_seed([3u8; 32]);
    let c = Ed25519Signer::from_seed([4u8; 32]);
    let root_key = human.public_key();

    let mut chain = Chain::issue(&human, principal("human:alice"), scope(10_000, 3));
    chain
        .attenuate(
            &human,
            principal("agent:a@org1"),
            a.public_key(),
            scope(5_000, 2),
            "book travel".into(),
        )
        .unwrap();
    chain
        .attenuate(
            &a,
            principal("agent:b@org2"),
            b.public_key(),
            scope(5_000, 1),
            "charge airline".into(),
        )
        .unwrap();
    chain
        .attenuate(
            &b,
            principal("agent:c@org3"),
            c.public_key(),
            scope(4_000, 0),
            "settle fare".into(),
        )
        .unwrap();

    World {
        chain,
        root_key,
        executor: c,
        attester: b,
    }
}

fn record(chain: &Chain, action: Digest) -> (ActionReceipt, InclusionProof, Digest) {
    let mut w = Witness::new();
    let receipt = ActionReceipt {
        chain_digest: chain.digest(),
        action_digest: action,
        prev_root: w.root(),
    };
    let idx = w.append(&receipt);
    (receipt, w.inclusion_proof(idx).unwrap(), w.root())
}

/// Result of one conformance case.
struct Outcome {
    passed: bool,
}

// ── Cases ──────────────────────────────────────────────────────────────────

/// The honest, complete, independently-attested action must be ACCEPTED.
/// (Control: proves the verifier is not rejecting everything.)
fn case_honest_accepted() -> Outcome {
    let w = build_world();
    let action = [42u8; 32];
    let (receipt, proof, root) = record(&w.chain, action);
    let completion = CompletionAttestation::attest(
        &w.attester,
        principal("agent:b@org2"),
        w.chain.digest(),
        action,
        action,
        root,
        proof,
    );
    let va = VerifiableAction {
        chain: w.chain,
        action_receipt: receipt,
        completion,
    };
    Outcome {
        passed: verify(&va, &w.root_key, &root).is_ok(),
    }
}

/// AIP concedes completion is self-reported (RESEARCH_VERIFICATION §1; §7
/// limitations: "Completion blocks are self-reported"). The verifier MUST reject
/// a completion signed by the executing agent itself.
fn case_self_report_rejected() -> Outcome {
    let w = build_world();
    let action = [42u8; 32];
    let (receipt, proof, root) = record(&w.chain, action);
    let completion = CompletionAttestation::attest(
        &w.executor, // C attests its own work
        principal("agent:c@org3"),
        w.chain.digest(),
        action,
        action,
        root,
        proof,
    );
    let va = VerifiableAction {
        chain: w.chain,
        action_receipt: receipt,
        completion,
    };
    Outcome {
        passed: matches!(
            verify(&va, &w.root_key, &root),
            Err(VerifyError::Attestation(_))
        ),
    }
}

/// DRP / EMILIA defer completeness to an external transparency log (§2); AIP's
/// text never even names omission. The verifier MUST reject an action with no
/// inclusion proof against the witnessed root — omission is detectable here.
fn case_omission_rejected() -> Outcome {
    let w = build_world();
    let recorded = [42u8; 32];
    let (_r, proof, root) = record(&w.chain, recorded);
    let omitted = [99u8; 32]; // never appended to the witness
    let omitted_receipt = ActionReceipt {
        chain_digest: w.chain.digest(),
        action_digest: omitted,
        prev_root: [0u8; 32],
    };
    let completion = CompletionAttestation::attest(
        &w.attester,
        principal("agent:b@org2"),
        w.chain.digest(),
        omitted,
        omitted,
        root,
        proof, // a real proof, but not for the omitted leaf
    );
    // The chain alone is valid — this is the point.
    let chain_valid = w.chain.verify(&w.root_key).is_ok();
    let va = VerifiableAction {
        chain: w.chain,
        action_receipt: omitted_receipt,
        completion,
    };
    Outcome {
        passed: chain_valid
            && matches!(verify(&va, &w.root_key, &root), Err(VerifyError::Omission)),
    }
}

/// Equivocation (forked log views) is unsolvable without a shared witness. The
/// verifier MUST reject a completion whose witnessed root disagrees with the
/// gossip-trusted root.
fn case_equivocation_rejected() -> Outcome {
    let w = build_world();
    let action = [42u8; 32];
    let (receipt, proof, root) = record(&w.chain, action);
    let completion = CompletionAttestation::attest(
        &w.attester,
        principal("agent:b@org2"),
        w.chain.digest(),
        action,
        action,
        root,
        proof,
    );
    let gossip_root = [123u8; 32]; // what everyone else sees
    let va = VerifiableAction {
        chain: w.chain,
        action_receipt: receipt,
        completion,
    };
    Outcome {
        passed: matches!(
            verify(&va, &w.root_key, &gossip_root),
            Err(VerifyError::Equivocation)
        ),
    }
}

/// Monotonic attenuation is claimed by AIP/Biscuit/APS. The chain MUST reject a
/// hop that grants authority its parent never held (scope widening).
fn case_scope_widening_rejected() -> Outcome {
    let human = Ed25519Signer::from_seed([1u8; 32]);
    let a = Ed25519Signer::from_seed([2u8; 32]);
    let mut chain = Chain::issue(&human, principal("human:alice"), scope(10_000, 2));
    let widened = Scope {
        permissions: vec!["payments.charge".to_string(), "payments.refund".to_string()],
        ..scope(10_000, 1)
    };
    let result = chain.attenuate(
        &human,
        principal("agent:a@org1"),
        a.public_key(),
        widened,
        "grab more".into(),
    );
    Outcome {
        passed: matches!(result, Err(ChainError::ScopeWidened)),
    }
}

/// One conformance case: (name, claim source, expectation, runner).
type Case = (&'static str, &'static str, &'static str, fn() -> Outcome);

fn main() {
    let cases: &[Case] = &[
        (
            "Honest action accepted",
            "control",
            "ACCEPT a complete, independently-attested action",
            case_honest_accepted,
        ),
        (
            "Self-reported completion rejected",
            "AIP §7 (self-reported completion) — RESEARCH_VERIFICATION §1",
            "REJECT completion signed by the executor",
            case_self_report_rejected,
        ),
        (
            "Omission rejected",
            "DRP/EMILIA defer completeness to an external log — RESEARCH_VERIFICATION §2",
            "REJECT an action with no inclusion proof",
            case_omission_rejected,
        ),
        (
            "Equivocation rejected",
            "forked log views need a shared witness — CLAUDE.md §4",
            "REJECT a witnessed root != gossip-trusted root",
            case_equivocation_rejected,
        ),
        (
            "Scope widening rejected",
            "monotonic attenuation (AIP/Biscuit/APS)",
            "REJECT a hop granting authority its parent lacked",
            case_scope_widening_rejected,
        ),
    ];

    println!("IndexOne conformance suite — cross-draft, adversarial");
    println!("{}", "─".repeat(78));
    let mut all_passed = true;
    for (name, source, expect, f) in cases {
        let outcome = f();
        all_passed &= outcome.passed;
        println!(
            "[{}] {}\n        expect: {}\n        claim : {}",
            if outcome.passed { "PASS" } else { "FAIL" },
            name,
            expect,
            source
        );
    }
    println!("{}", "─".repeat(78));
    if all_passed {
        println!("CONFORMANT — {} / {} cases pass.", cases.len(), cases.len());
    } else {
        println!("NON-CONFORMANT — at least one case failed.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_conformance_cases_pass() {
        assert!(
            case_honest_accepted().passed,
            "honest action must be accepted"
        );
        assert!(
            case_self_report_rejected().passed,
            "self-report must be rejected"
        );
        assert!(case_omission_rejected().passed, "omission must be rejected");
        assert!(
            case_equivocation_rejected().passed,
            "equivocation must be rejected"
        );
        assert!(
            case_scope_widening_rejected().passed,
            "scope widening must be rejected"
        );
    }
}
