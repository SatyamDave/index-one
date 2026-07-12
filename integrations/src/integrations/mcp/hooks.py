"""MCP request-header signing/verification hooks (Web Bot Auth model).

Transport per ``docs/RESEARCH_VERIFICATION.md`` §5: Web Bot Auth signs each
request with Ed25519 using **RFC 9421 HTTP Message Signatures**, carried in three
headers — ``Signature`` (the signature), ``Signature-Input`` (covered components
+ created/keyid/alg/tag), and ``Signature-Agent`` (the key-directory URL). Public
keys are published as JWKS at ``/.well-known/http-message-signatures-directory``.

These hooks build/verify that envelope and carry the IndexOne capability-chain
token alongside it (in ``X-IndexOne-Token``), so an MCP server can check both
"this request wasn't tampered with" and "it carries a delegation chain". The
Ed25519 signing/verification itself is delegated to an injected signer/verifier
(the real keys live in the IndexOne core / SDK); this module is transport only.
Chain *revocation* freshness is a separate check (``indexone-revocation``).
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

TOKEN_HEADER = "X-IndexOne-Token"
DEFAULT_COMPONENTS: tuple[str, ...] = ("@method", "@path", TOKEN_HEADER.lower())
_SIG_LABEL = "sig1"
_TAG = "web-bot-auth"


class MCPVerificationError(ValueError):
    """A request's signature or carried token failed to verify. Raised (fail
    closed) rather than returning a bare ``False``.
    """


@runtime_checkable
class Signer(Protocol):
    """An injected Ed25519 signer. ``key_id`` is the JWK thumbprint published in
    the key directory.
    """

    key_id: str

    def sign(self, payload: bytes) -> bytes: ...


@runtime_checkable
class Verifier(Protocol):
    """An injected Ed25519 verifier keyed by ``key_id``."""

    def verify(self, payload: bytes, signature: bytes, key_id: str) -> bool: ...


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _signature_base(
    *,
    method: str,
    path: str,
    token_value: str,
    components: Sequence[str],
    created: int,
    key_id: str,
) -> str:
    """The RFC 9421 signature base: one line per covered component, then the
    ``@signature-params`` line. Only the components this module supports
    (``@method``, ``@path``, and the token header) are recognized.
    """
    values: dict[str, str] = {
        "@method": method.upper(),
        "@path": path,
        TOKEN_HEADER.lower(): token_value,
    }
    lines: list[str] = []
    for component in components:
        if component not in values:
            raise MCPVerificationError(f"unsupported covered component: {component!r}")
        lines.append(f'"{component}": {values[component]}')
    covered = " ".join(f'"{c}"' for c in components)
    params = f'({covered});created={created};keyid="{key_id}";alg="ed25519";tag="{_TAG}"'
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def sign_request(
    *,
    method: str,
    path: str,
    chain_token: bytes,
    signer: Signer,
    key_directory_url: str,
    created: int,
    components: Sequence[str] = DEFAULT_COMPONENTS,
) -> dict[str, str]:
    """Produce the signed headers for an outgoing MCP request carrying
    ``chain_token`` (a serialized IndexOne capability chain). ``created`` is
    supplied explicitly so signing is deterministic and testable.
    """
    token_value = _b64u(chain_token)
    base = _signature_base(
        method=method,
        path=path,
        token_value=token_value,
        components=components,
        created=created,
        key_id=signer.key_id,
    )
    signature = signer.sign(base.encode("utf-8"))
    covered = " ".join(f'"{c}"' for c in components)
    sig_input = (
        f"{_SIG_LABEL}=({covered});created={created};"
        f'keyid="{signer.key_id}";alg="ed25519";tag="{_TAG}"'
    )
    return {
        TOKEN_HEADER: token_value,
        "Signature-Input": sig_input,
        "Signature": f"{_SIG_LABEL}=:{_b64u(signature)}:",
        "Signature-Agent": key_directory_url,
    }


def _parse_signature_input(raw: str) -> tuple[tuple[str, ...], int, str]:
    """Parse a ``Signature-Input`` value we produced → (components, created,
    key_id). Fails closed on anything malformed.
    """
    try:
        _, rest = raw.split("=", 1)
        covered_part, _, param_part = rest.partition(")")
        components = tuple(
            tok.strip().strip('"') for tok in covered_part.lstrip("(").split() if tok
        )
        params: dict[str, str] = {}
        for item in param_part.lstrip(";").split(";"):
            if not item:
                continue
            key, _, value = item.partition("=")
            params[key.strip()] = value.strip().strip('"')
        return components, int(params["created"]), params["keyid"]
    except (ValueError, KeyError) as exc:
        raise MCPVerificationError(f"malformed Signature-Input: {raw!r}") from exc


def verify_request(
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    verifier: Verifier,
) -> bytes:
    """Verify an incoming MCP request's Web Bot Auth headers and return the
    carried IndexOne token bytes. Raises :class:`MCPVerificationError` on any
    missing header, malformed input, or signature mismatch (fail closed).
    """
    lookup = {k.lower(): v for k, v in headers.items()}
    for required in ("signature", "signature-input", TOKEN_HEADER.lower()):
        if required not in lookup:
            raise MCPVerificationError(f"missing required header: {required}")

    components, created, key_id = _parse_signature_input(lookup["signature-input"])
    token_value = lookup[TOKEN_HEADER.lower()]

    sig_raw = lookup["signature"]
    if not sig_raw.startswith(f"{_SIG_LABEL}=:") or not sig_raw.endswith(":"):
        raise MCPVerificationError("malformed Signature header")
    signature = _b64u_decode(sig_raw[len(_SIG_LABEL) + 2 : -1])

    base = _signature_base(
        method=method,
        path=path,
        token_value=token_value,
        components=components,
        created=created,
        key_id=key_id,
    )
    if not verifier.verify(base.encode("utf-8"), signature, key_id):
        raise MCPVerificationError("request signature did not verify")
    return _b64u_decode(token_value)
