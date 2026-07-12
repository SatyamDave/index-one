"""MCP request-header signing/verification hooks.

Transport model: per-request Ed25519 header signing, in the spirit of Web
Bot Auth -- the capability-chain token travels as a header alongside a
signature over the request, so an MCP server can verify both "this request
carries a valid delegation chain" and "this specific request wasn't
tampered with in transit".

TODO(@satyam): everything here is a stub. No real header canonicalization,
signing, or verification yet.
"""

from __future__ import annotations

from typing import Protocol


class RequestLike(Protocol):
    """Minimal shape this module needs from an HTTP/MCP request object.

    TODO(@satyam): replace with whatever request type the MCP server/client
    library we settle on actually uses.
    """

    method: str
    url: str
    headers: dict[str, str]


def sign_request_headers(request: RequestLike, *, chain_token: bytes) -> dict[str, str]:
    """Produce the signed headers for an outgoing MCP request carrying
    `chain_token` (a serialized index-one capability chain).

    TODO(@satyam): implement. Needs: (1) a canonical request signing base
    string (method + path + relevant headers + body digest), (2) an
    Ed25519 signature over it via `indexone-crypto` (once bound to
    Python), (3) header names/format -- align with Web Bot Auth's
    `Signature` / `Signature-Input` headers where practical.
    """
    raise NotImplementedError("sign_request_headers: TODO(@satyam) - see module docstring")


def verify_request_headers(request: RequestLike) -> bool:
    """Verify an incoming MCP request's signature headers and extract/validate
    the carried capability chain.

    Returns whether the request's signature and chain both verify. Chain
    *revocation* freshness is a separate, explicit check (see
    `indexone-revocation`) layered on top of this, not folded in here.

    TODO(@satyam): implement.
    """
    raise NotImplementedError("verify_request_headers: TODO(@satyam) - see module docstring")
