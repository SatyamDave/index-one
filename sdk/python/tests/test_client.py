"""Tests for the IndexOne SDK.

Pure-Python tests always run. The real round-trip test runs only when the
``indexone-cli`` sidecar is available (``INDEXONE_CLI`` set, or on ``PATH``); it
is skipped otherwise so CI passes without a built Rust binary.
"""

from __future__ import annotations

import hashlib
import os
import shutil

import pytest

import indexone
from indexone import (
    Client,
    IndexOneError,
    Principal,
    Scope,
    attenuate,
    attest,
    chain_digest,
    composed_verify,
    issue,
    pubkey,
    verify,
    witness_append,
    wrap,
)

FAR_FUTURE = 4_102_444_800


def _cli_available() -> bool:
    return bool(os.environ.get("INDEXONE_CLI") or shutil.which("indexone-cli"))


def test_scope_and_principal_construct() -> None:
    scope = Scope(
        permissions=["payments.charge"],
        max_depth=2,
        expires_at=FAR_FUTURE,
        budget=10_000,
        currency="USD",
    )
    assert scope.budget == 10_000
    assert Principal(id="human:alice", display_name="Alice").id == "human:alice"


def test_wrap_returns_client() -> None:
    client = wrap("00" * 32, Principal("human:alice", "Alice"))
    assert isinstance(client, Client)


def test_missing_cli_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # With no INDEXONE_CLI and nothing on PATH, calls fail closed with a clear
    # typed error rather than silently succeeding.
    monkeypatch.delenv("INDEXONE_CLI", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(IndexOneError):
        verify({"root": {}}, {"algorithm": "Ed25519", "bytes": []})


@pytest.mark.skipif(
    not _cli_available(),
    reason="indexone-cli not built; set INDEXONE_CLI or run `cargo build -p indexone-cli`",
)
def test_real_round_trip_through_sidecar() -> None:
    # A real issue -> attenuate -> verify against the Rust core: the effective
    # scope is the narrowest (last) hop's, proving attenuation held end to end.
    root_seed = "01" * 32
    a_seed = "02" * 32
    issued = issue(
        root_seed,
        Principal("human:alice", "Alice"),
        Scope(
            ["payments.charge"], max_depth=2, expires_at=FAR_FUTURE, budget=10_000, currency="USD"
        ),
    )
    step = attenuate(
        issued["chain"],
        root_seed,
        Principal("agent:a@org1", "A"),
        a_seed,
        Scope(
            ["payments.charge"], max_depth=1, expires_at=FAR_FUTURE, budget=5_000, currency="USD"
        ),
        "book travel",
    )
    effective = verify(step["chain"], issued["root_key"])
    assert effective.budget == 5_000
    assert effective.max_depth == 1


def test_verify_rejects_wrong_root_key_fails_closed() -> None:
    if not _cli_available():
        pytest.skip("indexone-cli not built")
    issued = issue(
        "01" * 32,
        Principal("human:alice", "Alice"),
        Scope(
            ["payments.charge"], max_depth=1, expires_at=FAR_FUTURE, budget=10_000, currency="USD"
        ),
    )
    wrong_key = {"algorithm": "Ed25519", "bytes": list(range(32))}
    with pytest.raises(IndexOneError):
        verify(issued["chain"], wrong_key)


def test_public_surface_exported() -> None:
    for name in (
        "Client",
        "wrap",
        "issue",
        "attenuate",
        "verify",
        "Scope",
        "Principal",
        "pubkey",
        "chain_digest",
        "witness_append",
        "attest",
        "composed_verify",
    ):
        assert hasattr(indexone, name)


def _three_hop_chain() -> tuple[dict, dict, str]:
    """Human -> A@org1 -> B@org2 -> C@org3 (executor). Returns (chain, root_key,
    chain_digest_hex)."""
    seed = lambda b: bytes([b] * 32).hex()  # noqa: E731
    issued = issue(
        seed(1),
        Principal("human:alice", "Alice"),
        Scope(
            ["payments.charge"], max_depth=3, expires_at=FAR_FUTURE, budget=10_000, currency="USD"
        ),
    )
    chain, root_key = issued["chain"], issued["root_key"]
    for signer_b, to_b, to_id, depth in [
        (1, 2, "agent:a@org1", 2),
        (2, 3, "agent:b@org2", 1),
        (3, 4, "agent:c@org3", 0),
    ]:
        chain = attenuate(
            chain,
            seed(signer_b),
            Principal(to_id, to_id),
            seed(to_b),
            Scope(
                ["payments.charge"],
                max_depth=depth,
                expires_at=FAR_FUTURE,
                budget=4_000,
                currency="USD",
            ),
            f"hop to {to_id}",
        )["chain"]
    return chain, root_key, chain_digest(chain)


@pytest.mark.skipif(not _cli_available(), reason="indexone-cli not built")
def test_full_surface_honest_action_verifies() -> None:
    # The whole product surface from Python: chain -> witnessed action ->
    # independent attestation -> composed verify() == VALID.
    chain, root_key, cd = _three_hop_chain()
    action = hashlib.sha256(b"charge $40").hexdigest()
    nonce = hashlib.sha256(b"nonce-1").hexdigest()
    notary_key = pubkey("09" * 32)

    w = witness_append(cd, action, nonce)
    completion = attest(
        "09" * 32,
        Principal("attester:notary", "Notary"),
        cd,
        action,
        action,
        w["root"],
        w["inclusion_proof"],
    )
    effective = composed_verify(
        chain,
        root_key,
        w["root"],
        w["receipt"],
        completion,
        trusted_attesters=[notary_key],
    )
    assert effective.budget == 4_000


@pytest.mark.skipif(not _cli_available(), reason="indexone-cli not built")
def test_omitted_action_is_invalid_through_sdk() -> None:
    # The Day-12 lead case, end to end in Python: an action never witnessed,
    # presented against the honest root, fails closed as an omission.
    chain, root_key, cd = _three_hop_chain()
    honest = hashlib.sha256(b"charge $40").hexdigest()
    nonce = hashlib.sha256(b"nonce-1").hexdigest()
    notary_key = pubkey("09" * 32)

    w = witness_append(cd, honest, nonce)  # only the honest action is witnessed
    omitted = hashlib.sha256(b"secret $9000").hexdigest()
    omitted_receipt = witness_append(cd, omitted, nonce)["receipt"]  # in a throwaway log
    completion = attest(
        "09" * 32,
        Principal("attester:notary", "Notary"),
        cd,
        omitted,
        omitted,
        w["root"],
        w["inclusion_proof"],  # honest root/proof, but the receipt is the omitted one
    )
    with pytest.raises(IndexOneError, match="omission"):
        composed_verify(
            chain,
            root_key,
            w["root"],
            omitted_receipt,
            completion,
            trusted_attesters=[notary_key],
        )


@pytest.mark.skipif(not _cli_available(), reason="indexone-cli not built")
def test_self_reported_completion_is_invalid_through_sdk() -> None:
    # The executor (C) attests its own work -> not independent -> INVALID.
    chain, root_key, cd = _three_hop_chain()
    action = hashlib.sha256(b"charge $40").hexdigest()
    nonce = hashlib.sha256(b"nonce-1").hexdigest()
    c_key = pubkey("04" * 32)  # C's key (the executor)

    w = witness_append(cd, action, nonce)
    self_report = attest(
        "04" * 32,
        Principal("agent:c@org3", "C"),
        cd,
        action,
        action,
        w["root"],
        w["inclusion_proof"],
    )
    with pytest.raises(IndexOneError):
        composed_verify(
            chain,
            root_key,
            w["root"],
            w["receipt"],
            self_report,
            trusted_attesters=[c_key],
        )


def _perm(action, *, amount_max=None, resource_in=None):  # type: ignore[no-untyped-def]
    constraints = []
    if amount_max is not None:
        constraints.append({"amount_max": amount_max})
    if resource_in is not None:
        constraints.append({"resource_in": resource_in})
    return {"action": action, "constraints": constraints} if constraints else action


@pytest.mark.skipif(not _cli_available(), reason="indexone-cli not built")
def test_structured_constraints_narrow_through_sidecar() -> None:
    # A structured permission (amount cap + resource set) attenuated to a tighter
    # one verifies; the returned effective permission is the constrained object.
    root_seed = "01" * 32
    a_seed = "02" * 32
    issued = issue(
        root_seed,
        Principal("human:alice", "Alice"),
        Scope(
            [_perm("payments.charge", amount_max=500, resource_in=["airlines", "hotels"])],
            max_depth=2,
            expires_at=FAR_FUTURE,
            budget=10_000,
            currency="USD",
        ),
    )
    step = attenuate(
        issued["chain"],
        root_seed,
        Principal("agent:a@org1", "A"),
        a_seed,
        Scope(
            [_perm("payments.charge", amount_max=300, resource_in=["airlines"])],
            max_depth=1,
            expires_at=FAR_FUTURE,
            budget=5_000,
            currency="USD",
        ),
        "book a flight",
    )
    effective = verify(step["chain"], issued["root_key"])
    perm = effective.permissions[0]
    assert isinstance(perm, dict)
    assert perm["action"] == "payments.charge"


@pytest.mark.skipif(not _cli_available(), reason="indexone-cli not built")
def test_widening_a_structured_constraint_fails_closed() -> None:
    # Raising the amount ceiling above the parent's is a widening — the core
    # rejects the attenuation, and the SDK surfaces it as a typed error.
    root_seed = "01" * 32
    a_seed = "02" * 32
    issued = issue(
        root_seed,
        Principal("human:alice", "Alice"),
        Scope(
            [_perm("payments.charge", amount_max=500)],
            max_depth=2,
            expires_at=FAR_FUTURE,
            budget=10_000,
            currency="USD",
        ),
    )
    with pytest.raises(IndexOneError):
        attenuate(
            issued["chain"],
            root_seed,
            Principal("agent:a@org1", "A"),
            a_seed,
            Scope(
                [_perm("payments.charge", amount_max=1_000)],  # raises the cap → widening
                max_depth=1,
                expires_at=FAR_FUTURE,
                budget=5_000,
                currency="USD",
            ),
            "grab more authority",
        )
