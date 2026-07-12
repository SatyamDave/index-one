"""Tests for the real SD-JWT-VC mandate (ES256/P-256, cnf key-binding).

These exercise genuine cryptography — issuer signature, holder key-binding,
selective disclosure, audience/nonce/expiry — not a stand-in. Each failure mode
must fail closed (raise ``MandateError``), never return a bare ``False``.
"""

from __future__ import annotations

import pytest

from integrations.ap2 import (
    AP2ValidationError,
    MandateError,
    check_consistency,
    delegation_facts_from_mandate,
    generate_issuer_key,
    issue_mandate,
    present_mandate,
    public_jwk,
    verify_mandate,
)


def _issue_and_present(
    *,
    audience: str = "merchant_1",
    nonce: str = "tx_abc",
    holder=None,
    issuer=None,
):
    issuer = issuer or generate_issuer_key()
    holder = holder or generate_issuer_key()
    issuance = issue_mandate(
        issuer,
        vct="mandate.payment.1",
        holder_jwk=public_jwk(holder),
        disclosed_claims={
            "user": "human:alice",
            "budget": {"amount": 5_000, "currency": "USD"},
            "purpose": "book a flight",
        },
        always_present={"payee": "merchant_1"},
        expires_at=2_000,
    )
    presentation = present_mandate(
        issuance, holder, audience=audience, nonce=nonce, issued_at=1_000
    )
    return issuer, holder, presentation


def test_roundtrip_verifies_and_reconstructs_claims():
    issuer, _holder, pres = _issue_and_present()
    v = verify_mandate(
        pres,
        issuer.public_key(),
        expected_audience="merchant_1",
        expected_nonce="tx_abc",
        now=1_500,
    )
    assert v.claims["user"] == "human:alice"
    assert v.claims["budget"] == {"amount": 5_000, "currency": "USD"}
    assert v.claims["payee"] == "merchant_1"  # always-present (non-disclosed) claim
    assert v.audience == "merchant_1"


def test_wrong_issuer_key_is_rejected():
    _issuer, _holder, pres = _issue_and_present()
    impostor = generate_issuer_key()
    with pytest.raises(MandateError):
        verify_mandate(
            pres,
            impostor.public_key(),
            expected_audience="merchant_1",
            expected_nonce="tx_abc",
            now=1_500,
        )


def test_wrong_holder_key_breaks_key_binding():
    # A different holder presents (signs the KB-JWT with a key not in `cnf`).
    issuer = generate_issuer_key()
    holder = generate_issuer_key()
    issuance = issue_mandate(
        issuer,
        vct="mandate.payment.1",
        holder_jwk=public_jwk(holder),
        disclosed_claims={"user": "human:alice"},
        expires_at=2_000,
    )
    attacker = generate_issuer_key()
    pres = present_mandate(
        issuance, attacker, audience="merchant_1", nonce="tx_abc", issued_at=1_000
    )
    with pytest.raises(MandateError):
        verify_mandate(
            pres,
            issuer.public_key(),
            expected_audience="merchant_1",
            expected_nonce="tx_abc",
            now=1_500,
        )


def test_wrong_audience_is_rejected():
    issuer, _holder, pres = _issue_and_present()
    with pytest.raises(MandateError):
        verify_mandate(
            pres,
            issuer.public_key(),
            expected_audience="attacker",
            expected_nonce="tx_abc",
            now=1_500,
        )


def test_wrong_nonce_is_rejected_as_replay():
    issuer, _holder, pres = _issue_and_present()
    with pytest.raises(MandateError):
        verify_mandate(
            pres,
            issuer.public_key(),
            expected_audience="merchant_1",
            expected_nonce="other",
            now=1_500,
        )


def test_expired_mandate_is_rejected():
    issuer, _holder, pres = _issue_and_present()
    with pytest.raises(MandateError):
        verify_mandate(
            pres,
            issuer.public_key(),
            expected_audience="merchant_1",
            expected_nonce="tx_abc",
            now=3_000,
        )


def test_dropped_disclosure_breaks_sd_hash():
    issuer, _holder, pres = _issue_and_present()
    # Drop the first disclosure segment; the KB-JWT's sd_hash no longer matches.
    first_disclosure = pres.split("~")[1]
    tampered = pres.replace(first_disclosure + "~", "", 1)
    with pytest.raises(MandateError):
        verify_mandate(
            tampered,
            issuer.public_key(),
            expected_audience="merchant_1",
            expected_nonce="tx_abc",
            now=1_500,
        )


def test_verified_mandate_bridges_to_delegation_facts():
    # The closed loop: verify real crypto, then bridge to IndexOne facts and
    # check them against the chain root scope.
    issuer, _holder, pres = _issue_and_present()
    v = verify_mandate(
        pres,
        issuer.public_key(),
        expected_audience="merchant_1",
        expected_nonce="tx_abc",
        now=1_500,
    )
    facts = delegation_facts_from_mandate(
        v.claims, user_id="human:alice", agent_id="agent:a@org1"
    )
    assert facts.budget_minor == 5_000
    assert facts.currency == "USD"
    assert facts.purpose == "book a flight"
    # Consistent with a root that authorized $60 in USD → passes.
    check_consistency(
        facts,
        "human:alice",
        {"budget": 6_000, "currency": "USD"},
    )
    # A mandate claiming more than the root granted fails closed.
    with pytest.raises(AP2ValidationError):
        check_consistency(facts, "human:alice", {"budget": 1_000, "currency": "USD"})
