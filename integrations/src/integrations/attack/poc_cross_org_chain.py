"""Runnable entry point for the cross-org attribution attack demo.

Usage:
    python -m integrations.attack.poc_cross_org_chain

NOTE: this Python POC is illustrative — its "signatures" are tagged strings, not
real crypto (see ``harness.py``). The **real-crypto** version of this exact
scenario now lives in the Rust ``/exploits`` crate and runs end-to-end against
the shipping core:

    cargo run --manifest-path exploits/Cargo.toml --bin ap2_attribution

It shows a single-hop AP2-style mandate (real Ed25519) verifying cleanly while
index-one rejects the same forged cross-org authority. Prefer that binary for
any demo; this module remains as a dependency-free, readable sketch of the seam.
"""

from __future__ import annotations

from integrations.attack.harness import run_attack


def main() -> None:
    result = run_attack()

    print("=== index-one cross-org attribution attack POC ===")
    print()
    print(f"Forged mandate handed to Agent C: {result.forged_mandate}")
    print()
    print(f"AP2-style single-hop verification passed: {result.ap2_verification_passed}")
    print(f"Was this actually authorized by Agent A / the human?: {result.actually_authorized}")
    print()
    if result.ap2_verification_passed and not result.actually_authorized:
        print(
            "VULNERABILITY REPRODUCED: a single-hop AP2-style mandate verifies "
            "cleanly even though no valid delegation chain from the human, "
            "through Agent A, to Agent B ever existed. A cross-org, hash-linked, "
            "scope-narrowing chain (indexone-chain) is required to catch this."
        )
    else:
        print("Unexpected result -- scenario did not reproduce the expected gap.")


if __name__ == "__main__":
    main()
