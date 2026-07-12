#![no_main]
//! Arbitrary bytes → ActionReceipt → canonical_bytes (the witness leaf encoding).
use indexone_witness::ActionReceipt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = serde_json::from_slice::<ActionReceipt>(data) {
        let _ = r.canonical_bytes();
    }
});
