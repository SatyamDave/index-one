"""AP2 <-> index-one adapter.

AP2 (google-agentic-commerce/AP2) mandates bind an Intent/Cart/Payment
mandate to a single user via a W3C Verifiable Credential (ECDSA P-256). The
seam we sit on top of: AP2 proves "this mandate is bound to this user", not
"this action's authority flowed, hop by hop, through these N agents across
M organizations". That's the gap `integrations.attack` demonstrates and
this adapter exists to close.

TODO(@satyam): everything here is a stub. No real AP2 parsing/VC
verification or real capability-chain construction yet -- this only pins
down the shapes the real implementation will fill in.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AP2Mandate:
    """Minimal mirror of an AP2 mandate's fields relevant to index-one.

    TODO(@satyam): replace with the real AP2 mandate schema (Intent/Cart/
    Payment mandate variants) once we pin down which mandate type(s) we
    adapt first. See AP2's mandate spec for the authoritative shape.
    """

    mandate_id: str
    user_id: str
    agent_id: str
    scope: dict[str, object] = field(default_factory=dict)
    amount_limit_minor_units: int | None = None
    currency: str | None = None
    expires_at: int | None = None
    # Raw VC signature bytes/JWS, unverified at this layer.
    verifiable_credential: str | None = None


@dataclass(frozen=True)
class DelegationBlockView:
    """Python-side mirror of `indexone_chain::DelegationBlock`.

    Placeholder until the Rust core is exposed to Python (e.g. via PyO3
    bindings). This lets integration code and tests take shape against a
    stable interface today.

    TODO(@udaya, @satyam): replace with real bindings into `indexone-chain`
    once the Rust crate has an FFI/PyO3 surface.
    """

    from_principal: str
    to_principal: str
    scope: dict[str, object]
    purpose: str


def mandate_to_delegation_block(mandate: AP2Mandate, *, purpose: str) -> DelegationBlockView:
    """Convert a single AP2 mandate into one index-one delegation block.

    Note this only ever produces *one* block from *one* mandate -- AP2 has
    no native concept of a multi-hop chain, which is exactly the limitation
    `integrations.attack` demonstrates. Building a full cross-org chain
    requires composing multiple mandates/blocks, which is out of scope for
    this adapter alone.

    TODO(@satyam): implement. Needs: (1) verifying `verifiable_credential`
    against AP2's VC format, (2) mapping AP2's scope/amount fields onto
    `indexone_chain::Scope`, (3) real signing via `indexone-crypto` once
    that binding exists.
    """
    raise NotImplementedError("mandate_to_delegation_block: TODO(@satyam) - see docstring")
