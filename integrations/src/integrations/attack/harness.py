"""Runnable placeholder: demonstrates that a single-hop AP2-style mandate
cannot attribute authority across a 3-agent, cross-org delegation chain.

This module contains NO real cryptography. "Signatures" below are plain
tagged strings (`FAKE-SIG(not-crypto):...`), not an implementation of any
signature scheme -- they exist only so the demo has *something* to check
the internal consistency of, the same way AP2's mandate verification checks
"does this credential's claimed issuer match its signature", without that
check being able to say anything about *how the issuer came to have
authority to issue it*.

The scenario:
    Human  --authorizes-->  Agent A (org1)
    Agent A                                          -- never delegates to B
    Agent B (org2, compromised/over-permissioned) mints its OWN single-hop
        mandate, claiming to act for Human, and hands it to:
    Agent C (org3), who acts on it.

AP2-style verification of the mandate Agent C received only checks that
mandate's own internal consistency (issuer/signature match, not expired).
It has no way to check whether Agent A ever actually delegated this scope
to Agent B in the first place -- there's no hash-linked chain back to a
Block 0 human root, and no requirement that scope only narrow hop to hop.
That's exactly the gap index-one's chain (`indexone-chain`) is designed to
close: `Chain::verify` (once implemented) would reject this because Agent B
has no valid `DelegationBlock` from Agent A to attenuate from.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SingleHopMandate:
    """An AP2-style mandate: binds ONE user_id to ONE issuing agent, for a
    scope/budget. No field exists for "the chain of agents that led here".
    """

    mandate_id: str
    bound_to_user_id: str
    issued_by_agent_id: str
    scope_budget: int
    fake_signature: str  # NOT real crypto -- see module docstring.


def mint_ap2_mandate(
    *, mandate_id: str, user_id: str, issuing_agent_id: str, budget: int
) -> SingleHopMandate:
    """Mint a single-hop AP2-style mandate. Anyone who can call this can mint
    a mandate binding ANY `user_id` to their own `issuing_agent_id` -- there
    is no check here (nor in AP2's mandate format) that `issuing_agent_id`
    actually holds a valid delegation from `user_id` or from whoever
    delegated to them. That absence is the point of this demo.
    """
    fake_signature = f"FAKE-SIG(not-crypto):{issuing_agent_id}:{mandate_id}"
    return SingleHopMandate(
        mandate_id=mandate_id,
        bound_to_user_id=user_id,
        issued_by_agent_id=issuing_agent_id,
        scope_budget=budget,
        fake_signature=fake_signature,
    )


def verify_ap2_mandate(mandate: SingleHopMandate) -> bool:
    """AP2-style single-hop verification: checks the mandate is internally
    consistent (its "signature" matches its claimed issuer). This is all a
    single-hop mandate format *can* check -- it has no visibility into
    whatever chain of delegations (if any) actually preceded it.
    """
    expected = f"FAKE-SIG(not-crypto):{mandate.issued_by_agent_id}:{mandate.mandate_id}"
    return mandate.fake_signature == expected


@dataclass(frozen=True)
class ThreeAgentChain:
    """The three cross-org agents in the attack scenario."""

    human_id: str = "human:alice"
    agent_a_id: str = "agent:a@org1"  # holds the real, human-authorized mandate
    agent_b_id: str = "agent:b@org2"  # never authorized, mints a mandate anyway
    agent_c_id: str = "agent:c@org3"  # receives and acts on Agent B's mandate

    human_authorized_budget: int = 100_00  # $100.00, in minor units


@dataclass(frozen=True)
class AttackResult:
    forged_mandate: SingleHopMandate
    ap2_verification_passed: bool
    """Whether AP2-style single-hop verification accepts the mandate Agent C received."""
    actually_authorized: bool
    """Ground truth: did Agent A ever actually delegate this to Agent B?"""


def run_attack(chain: ThreeAgentChain | None = None) -> AttackResult:
    """Run the scenario and return whether the structural flaw reproduces.

    Ground truth: Agent A never delegated anything to Agent B (`agent_a_id`
    never appears anywhere in the mandate Agent C receives). Yet Agent B
    mints a mandate claiming to act for the human, at the *full* originally
    authorized budget (no narrowing), and hands it to Agent C.

    The assertion this demo exists to make runnable: `verify_ap2_mandate`
    returns True for that forged mandate. A verifier at Agent C, using only
    AP2-style single-hop verification, has no way to detect that Agent A
    was cut out of the chain, or that no scope-narrowing ever happened.
    """
    chain = chain or ThreeAgentChain()

    forged_mandate = mint_ap2_mandate(
        mandate_id="mandate-b-to-c-001",
        user_id=chain.human_id,
        issuing_agent_id=chain.agent_b_id,
        budget=chain.human_authorized_budget,  # not narrowed -- copied wholesale
    )

    return AttackResult(
        forged_mandate=forged_mandate,
        ap2_verification_passed=verify_ap2_mandate(forged_mandate),
        actually_authorized=False,  # agent_a_id never appears in the mandate at all
    )
