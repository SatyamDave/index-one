"""Tests for the IndexOne SDK.

Pure-Python tests always run. The real round-trip test runs only when the
``indexone-cli`` sidecar is available (``INDEXONE_CLI`` set, or on ``PATH``); it
is skipped otherwise so CI passes without a built Rust binary.
"""

from __future__ import annotations

import os
import shutil

import pytest

import indexone
from indexone import Client, IndexOneError, Principal, Scope, attenuate, issue, verify, wrap

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
    for name in ("Client", "wrap", "issue", "attenuate", "verify", "Scope", "Principal"):
        assert hasattr(indexone, name)


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
