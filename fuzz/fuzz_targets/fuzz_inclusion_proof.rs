#![no_main]
//! Arbitrary bytes → InclusionProof → verify_inclusion against a fixed receipt/root.
use indexone_witness::{verify_inclusion, ActionReceipt, InclusionProof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = serde_json::from_slice::<InclusionProof>(data) {
        let receipt = ActionReceipt {
            chain_digest: [0u8; 32],
            action_digest: [0u8; 32],
            nonce: [0u8; 32],
            prev_root: [0u8; 32],
        };
        let _ = verify_inclusion(&receipt, &proof, &[0u8; 32]);
    }
});
