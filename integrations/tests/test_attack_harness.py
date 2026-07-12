"""This test actually runs the attack harness (no mocking) -- it's the
"runnable placeholder" demonstrating the cross-org attribution gap, not a
stub. See `integrations.attack.harness` for what it does and doesn't prove.
"""

from integrations.attack import run_attack
from integrations.attack.harness import verify_ap2_mandate


def test_forged_cross_org_mandate_passes_single_hop_ap2_verification() -> None:
    result = run_attack()

    # The structural flaw: single-hop verification passes...
    assert result.ap2_verification_passed is True
    # ...even though Agent A never actually authorized this delegation.
    assert result.actually_authorized is False


def test_verify_ap2_mandate_rejects_tampered_signature() -> None:
    result = run_attack()
    tampered = result.forged_mandate.__class__(
        mandate_id=result.forged_mandate.mandate_id,
        bound_to_user_id=result.forged_mandate.bound_to_user_id,
        issued_by_agent_id=result.forged_mandate.issued_by_agent_id,
        scope_budget=result.forged_mandate.scope_budget,
        fake_signature="not-the-right-signature",
    )
    assert verify_ap2_mandate(tampered) is False
