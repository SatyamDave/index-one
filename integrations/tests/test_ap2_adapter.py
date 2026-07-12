"""Scaffold-level tests for the AP2 adapter. No real conversion logic exists
yet -- these only pin down that the stub interface raises, and that the
data shapes construct as expected.
"""

import pytest

from integrations.ap2 import AP2Mandate, mandate_to_delegation_block


def test_ap2_mandate_constructs_with_expected_fields() -> None:
    mandate = AP2Mandate(
        mandate_id="m-1",
        user_id="human:alice",
        agent_id="agent:a@org1",
        amount_limit_minor_units=10_000,
        currency="USD",
    )
    assert mandate.mandate_id == "m-1"
    assert mandate.currency == "USD"


def test_mandate_to_delegation_block_is_not_yet_implemented() -> None:
    mandate = AP2Mandate(mandate_id="m-1", user_id="human:alice", agent_id="agent:a@org1")
    with pytest.raises(NotImplementedError):
        mandate_to_delegation_block(mandate, purpose="book a flight")
