"""index-one SDK client -- thin public wrapper over the Rust core.

TODO(@satyam, @udaya): everything here is a stub. Real implementation will
bind to `indexone-chain` / `indexone-crypto` (likely via PyO3, or a small
sidecar process/gRPC if we decide not to ship native extensions per
platform yet) -- not reimplement chain logic in Python.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Scope:
    """Mirrors `indexone_chain::Scope`. See `/core/chain/src/lib.rs`."""

    permissions: list[str]
    budget: int | None = None
    currency: str | None = None
    max_depth: int = 1
    expires_at: int | None = None


class Client:
    """Wraps a single agent's identity for signing and verifying
    capability-chain blocks.

    TODO(@satyam, @udaya): implement `sign`/`attenuate`/`verify` against
    the Rust core.
    """

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def sign(self, payload: bytes) -> bytes:
        """Sign `payload`, producing a new/extended capability-chain token.

        TODO: implement via `indexone-chain::Chain::attenuate` +
        `indexone-crypto::Signer`.
        """
        raise NotImplementedError("Client.sign: TODO - see module docstring")

    def verify(self, token: bytes) -> Scope:
        """Verify a capability-chain token and return its effective (most
        narrowed) scope.

        TODO: implement via `indexone-chain::Chain::verify`.
        """
        raise NotImplementedError("Client.verify: TODO - see module docstring")


def wrap(agent: Any, *, scope: Scope | None = None) -> Client:
    """Wrap an arbitrary agent object, returning a `Client` that can sign
    and verify capability-chain tokens on its behalf.

    This is the `pip install indexone` one-liner entry point:

        agent = indexone.wrap(my_agent, scope=...)

    TODO(@satyam): decide what "wrap" actually does to `agent` (attach
    middleware to its request pipeline? just hand back a co-located
    `Client`?) once the MCP/AP2 integration points in `/integrations` are
    further along.
    """
    raise NotImplementedError("wrap: TODO - see function docstring")


def verify(token: bytes) -> Scope:
    """Module-level convenience wrapper: verify a capability-chain token
    without needing to construct a `Client` first.

    TODO: implement via `indexone-chain::Chain::verify`.
    """
    raise NotImplementedError("verify: TODO - see function docstring")
