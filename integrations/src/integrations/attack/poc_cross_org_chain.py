"""Runnable entry point for the cross-org attribution attack demo.

Usage:
    python -m integrations.attack.poc_cross_org_chain
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
