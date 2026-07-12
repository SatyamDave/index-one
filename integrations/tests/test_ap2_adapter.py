"""Tests for the AP2 <-> IndexOne adapter."""

from __future__ import annotations

import pytest

from integrations.ap2 import (
    AP2ValidationError,
    check_consistency,
    parse_intent_mandate,
    parse_payment_mandate,
    to_delegation_facts,
)


def _intent_dict() -> dict[str, object]:
    return {
        "natural_language_description": "book a flight under $100",
        "intent_expiry": "2026-12-31T00:00:00Z",
        "merchants": ["airline.example"],
    }


def _payment_dict(amount: int = 5_000, currency: str = "USD") -> dict[str, object]:
    return {
        "payment_mandate_contents": {
            "payment_mandate_id": "pm-1",
            "payment_details_total": {"amount": amount, "currency": currency},
            "merchant_agent": "agent:airline@org2",
            "timestamp": "2026-07-11T12:00:00Z",
        },
        "user_authorization": "eyJ...sd-jwt-vp",
    }


def test_parse_and_bridge_to_delegation_facts() -> None:
    intent = parse_intent_mandate(_intent_dict())
    payment = parse_payment_mandate(_payment_dict())
    facts = to_delegation_facts(intent, payment, user_id="human:alice", agent_id="agent:a@org1")
    assert facts.budget_minor == 5_000
    assert facts.currency == "USD"
    # Purpose is the intent description -- the analogue of a delegation block's
    # mandatory purpose/context field.
    assert facts.purpose == "book a flight under $100"


def test_missing_required_field_fails_closed() -> None:
    bad = _intent_dict()
    del bad["intent_expiry"]
    with pytest.raises(AP2ValidationError):
        parse_intent_mandate(bad)


def test_empty_intent_description_rejected() -> None:
    bad = _intent_dict()
    bad["natural_language_description"] = "   "
    with pytest.raises(AP2ValidationError):
        parse_intent_mandate(bad)


def test_consistency_accepts_mandate_within_root_authorization() -> None:
    facts = to_delegation_facts(
        parse_intent_mandate(_intent_dict()),
        parse_payment_mandate(_payment_dict(amount=5_000)),
        user_id="human:alice",
        agent_id="agent:a@org1",
    )
    # Root authorized $100 (10_000 minor); the mandate asks $50 -- fine.
    check_consistency(facts, "human:alice", {"budget": 10_000, "currency": "USD"})


def test_consistency_rejects_mandate_exceeding_root_budget() -> None:
    # The attribution check: an AP2 mandate cannot claim more than the IndexOne
    # chain's root ever authorized.
    facts = to_delegation_facts(
        parse_intent_mandate(_intent_dict()),
        parse_payment_mandate(_payment_dict(amount=20_000)),
        user_id="human:alice",
        agent_id="agent:a@org1",
    )
    with pytest.raises(AP2ValidationError):
        check_consistency(facts, "human:alice", {"budget": 10_000, "currency": "USD"})


def test_consistency_rejects_wrong_user() -> None:
    facts = to_delegation_facts(
        parse_intent_mandate(_intent_dict()),
        parse_payment_mandate(_payment_dict()),
        user_id="human:mallory",
        agent_id="agent:a@org1",
    )
    with pytest.raises(AP2ValidationError):
        check_consistency(facts, "human:alice", {"budget": 10_000, "currency": "USD"})
