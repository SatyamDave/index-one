"""IndexOne SDK client -- thin bindings over the Rust core via the sidecar CLI.

This SDK does NOT reimplement chain or crypto logic in Python (CLAUDE.md §11).
Every signing/verification call shells out to the ``indexone-cli`` binary built
from ``core/cli`` (``cargo build -p indexone-cli``), which runs the real
``indexone-chain`` + ``indexone-crypto`` code. Locate the binary via the
``INDEXONE_CLI`` environment variable or by having it on ``PATH``.

Key material is a 32-byte hex seed the client manages; the sidecar derives the
Ed25519 keypair deterministically.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


class IndexOneError(RuntimeError):
    """A verification failure or a sidecar/transport error.

    A failed ``verify`` (e.g. a widened scope or a broken chain) raises this with
    the typed reason the core reported -- the SDK fails closed, never returning a
    bare ``False``.
    """


@dataclass(frozen=True)
class Scope:
    """Mirrors ``indexone_chain::Scope``. See ``/core/chain/src/lib.rs``."""

    permissions: list[str]
    max_depth: int
    expires_at: int
    budget: int | None = None
    currency: str | None = None


@dataclass(frozen=True)
class Principal:
    """Mirrors ``indexone_chain::Principal``."""

    id: str
    display_name: str


def _cli_path() -> str:
    """Locate the ``indexone-cli`` sidecar, or raise with a build hint."""
    env = os.environ.get("INDEXONE_CLI")
    if env:
        if not os.path.exists(env):
            raise IndexOneError(f"INDEXONE_CLI points at a missing file: {env}")
        return env
    found = shutil.which("indexone-cli")
    if found:
        return found
    raise IndexOneError(
        "indexone-cli not found. Build it with `cargo build -p indexone-cli` and "
        "either put it on PATH or set INDEXONE_CLI to the binary path."
    )


def _invoke(request: dict[str, Any]) -> dict[str, Any]:
    """Send one JSON request to the sidecar and return its parsed response.

    Raises ``IndexOneError`` if the sidecar reports ``ok: false`` (fail closed).
    """
    proc = subprocess.run(
        [_cli_path()],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        check=False,
    )
    if not proc.stdout.strip():
        raise IndexOneError(f"indexone-cli produced no output (stderr: {proc.stderr.strip()})")
    response: dict[str, Any] = json.loads(proc.stdout)
    if not response.get("ok", False):
        raise IndexOneError(response.get("error", "unknown error from indexone-cli"))
    return response


def _scope_payload(scope: Scope) -> dict[str, Any]:
    return asdict(scope)


def issue(seed_hex: str, principal: Principal, scope: Scope) -> dict[str, Any]:
    """Issue a fresh capability chain from a human root authority.

    Returns ``{"chain": <chain>, "root_key": <public key>}`` -- keep ``root_key``;
    it is the trust anchor a verifier checks the chain against.
    """
    resp = _invoke(
        {
            "cmd": "issue",
            "seed": seed_hex,
            "principal": asdict(principal),
            "scope": _scope_payload(scope),
        }
    )
    return {"chain": resp["chain"], "root_key": resp["root_key"]}


def attenuate(
    chain: dict[str, Any],
    signer_seed_hex: str,
    to: Principal,
    to_seed_hex: str,
    scope: Scope,
    purpose: str,
) -> dict[str, Any]:
    """Append a scope-narrowing delegation hop, signed by the current tail key.

    ``signer_seed_hex`` must be the seed whose key the current tail delegated to
    (the root seed for the first hop). Returns ``{"chain", "to_key"}``.
    """
    resp = _invoke(
        {
            "cmd": "attenuate",
            "chain": chain,
            "signer_seed": signer_seed_hex,
            "to": asdict(to),
            "to_seed": to_seed_hex,
            "scope": _scope_payload(scope),
            "purpose": purpose,
        }
    )
    return {"chain": resp["chain"], "to_key": resp["to_key"]}


def verify(chain: dict[str, Any], root_key: dict[str, Any]) -> Scope:
    """Verify a chain against a trusted root key; return its effective (narrowest)
    scope. Raises ``IndexOneError`` (fail closed) on any invalid chain.
    """
    resp = _invoke({"cmd": "verify", "chain": chain, "root_key": root_key})
    s = resp["effective_scope"]
    return Scope(
        permissions=s["permissions"],
        max_depth=s["max_depth"],
        expires_at=s["expires_at"],
        budget=s.get("budget"),
        currency=s.get("currency"),
    )


class Client:
    """Wraps one agent's identity (a 32-byte hex seed + principal) so it can issue
    and extend capability chains without re-passing its seed each call.
    """

    def __init__(self, seed_hex: str, principal: Principal) -> None:
        self.seed_hex = seed_hex
        self.principal = principal

    def issue(self, scope: Scope) -> dict[str, Any]:
        """Issue a root chain from this client's identity."""
        return issue(self.seed_hex, self.principal, scope)

    def attenuate(
        self,
        chain: dict[str, Any],
        to: Principal,
        to_seed_hex: str,
        scope: Scope,
        purpose: str,
    ) -> dict[str, Any]:
        """Delegate onward, signing with this client's seed (must be the current
        tail's key).
        """
        return attenuate(chain, self.seed_hex, to, to_seed_hex, scope, purpose)


def wrap(seed_hex: str, principal: Principal) -> Client:
    """The ``pip install indexone`` one-liner: wrap an identity as a
    :class:`Client` that can issue and verify capability chains on its behalf.
    """
    return Client(seed_hex, principal)
