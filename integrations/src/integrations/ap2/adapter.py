"""AP2 <-> IndexOne adapter.

Correcting the earlier framing (see ``docs/RESEARCH_VERIFICATION.md`` §4): AP2
*does* support delegation chains, and it produces an audit trail. What it does
**not** provide is a cross-org transparency mechanism to make omission detectable
or an independent completion attestation. So IndexOne does not "close a chain gap
in AP2" — it turns AP2's audit trail into *dispute-defensible attribution*.

This adapter parses the AP2 v0.1 SDK mandate shapes (``mandate.py`` field names
reproduced in RESEARCH_VERIFICATION §4), checks their internal consistency, and
bridges an AP2 mandate to the delegation facts IndexOne witnesses/attests —
flagging when a mandate claims authority the IndexOne chain's root never granted.

Cryptographic verification of the SD-JWT VC / merchant JWT (ES256/P-256) is
delegated to an injected callable; this module never implements crypto. The v0.2
spec renamed mandates to Checkout+Payment (Intent -> an *open mandate*) — TODO to
track once that lands.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class AP2ValidationError(ValueError):
    """An AP2 mandate is malformed, internally inconsistent, or claims authority
    the IndexOne chain root never granted. Raised (fail closed) rather than
    returning a bare ``False``.
    """


@dataclass(frozen=True)
class PaymentItem:
    """A W3C-PaymentRequest-style amount: minor units + ISO currency."""

    amount_minor: int
    currency: str


@dataclass(frozen=True)
class IntentMandate:
    """AP2 v0.1 ``IntentMandate`` (the fields IndexOne cares about)."""

    natural_language_description: str
    intent_expiry: str
    user_cart_confirmation_required: bool = True
    merchants: tuple[str, ...] | None = None
    skus: tuple[str, ...] | None = None
    requires_refundability: bool = False


@dataclass(frozen=True)
class PaymentMandate:
    """AP2 v0.1 ``PaymentMandate`` (``payment_mandate_contents`` flattened to the
    fields IndexOne cares about). ``user_authorization`` is the base64url SD-JWT
    verifiable presentation, verified by an injected callable, not here.
    """

    payment_mandate_id: str
    total: PaymentItem
    merchant_agent: str
    timestamp: str
    user_authorization: str | None = None


def _require(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        raise AP2ValidationError(f"AP2 mandate missing required field: {key!r}")
    return data[key]


def _parse_payment_item(data: dict[str, Any]) -> PaymentItem:
    amount = _require(data, "amount")
    currency = _require(data, "currency")
    if not isinstance(amount, int):
        raise AP2ValidationError("payment amount must be an integer (minor units)")
    if not isinstance(currency, str):
        raise AP2ValidationError("payment currency must be a string")
    return PaymentItem(amount_minor=amount, currency=currency)


def parse_intent_mandate(data: dict[str, Any]) -> IntentMandate:
    """Parse an AP2 v0.1 ``IntentMandate`` dict. Raises on missing required
    fields (``natural_language_description``, ``intent_expiry``).
    """
    description = str(_require(data, "natural_language_description"))
    if not description.strip():
        raise AP2ValidationError("IntentMandate.natural_language_description is empty")
    merchants = data.get("merchants")
    skus = data.get("skus")
    return IntentMandate(
        natural_language_description=description,
        intent_expiry=str(_require(data, "intent_expiry")),
        user_cart_confirmation_required=bool(data.get("user_cart_confirmation_required", True)),
        merchants=tuple(merchants) if merchants is not None else None,
        skus=tuple(skus) if skus is not None else None,
        requires_refundability=bool(data.get("requires_refundability", False)),
    )


def parse_payment_mandate(data: dict[str, Any]) -> PaymentMandate:
    """Parse an AP2 v0.1 ``PaymentMandate`` dict (reads
    ``payment_mandate_contents``).
    """
    contents = _require(data, "payment_mandate_contents")
    if not isinstance(contents, dict):
        raise AP2ValidationError("payment_mandate_contents must be an object")
    return PaymentMandate(
        payment_mandate_id=str(_require(contents, "payment_mandate_id")),
        total=_parse_payment_item(_require(contents, "payment_details_total")),
        merchant_agent=str(_require(contents, "merchant_agent")),
        timestamp=str(_require(contents, "timestamp")),
        user_authorization=data.get("user_authorization"),
    )


@dataclass(frozen=True)
class DelegationFacts:
    """The authority facts IndexOne witnesses/attests, extracted from an AP2
    mandate: which user, which issuing agent, how much, and why.
    """

    user_id: str
    agent_id: str
    budget_minor: int
    currency: str
    purpose: str


def to_delegation_facts(
    intent: IntentMandate,
    payment: PaymentMandate,
    *,
    user_id: str,
    agent_id: str,
) -> DelegationFacts:
    """Bridge an AP2 (intent, payment) pair to IndexOne delegation facts. The
    purpose is the intent's natural-language description — the analogue of an
    IndexOne delegation block's mandatory ``purpose``/``context`` field.
    """
    return DelegationFacts(
        user_id=user_id,
        agent_id=agent_id,
        budget_minor=payment.total.amount_minor,
        currency=payment.total.currency,
        purpose=intent.natural_language_description,
    )


def check_consistency(
    facts: DelegationFacts,
    indexone_root_principal_id: str,
    indexone_root_scope: dict[str, Any],
) -> None:
    """Assert an AP2 mandate does not claim more than the IndexOne chain's root
    authorized. Raises :class:`AP2ValidationError` (fail closed) when the mandate
    binds a different user, a different currency, or a budget exceeding the root
    scope's ceiling — the check that makes AP2's audit trail attributable.
    """
    if facts.user_id != indexone_root_principal_id:
        raise AP2ValidationError(
            f"AP2 mandate user {facts.user_id!r} != IndexOne root "
            f"principal {indexone_root_principal_id!r}"
        )
    root_currency = indexone_root_scope.get("currency")
    if root_currency is not None and facts.currency != root_currency:
        raise AP2ValidationError(
            f"AP2 mandate currency {facts.currency!r} != root currency {root_currency!r}"
        )
    root_budget = indexone_root_scope.get("budget")
    if root_budget is not None and facts.budget_minor > int(root_budget):
        raise AP2ValidationError(
            f"AP2 mandate budget {facts.budget_minor} exceeds IndexOne root "
            f"authorization {root_budget}"
        )
    if not facts.purpose.strip():
        raise AP2ValidationError("AP2 mandate has no purpose (empty intent description)")
