"""A real SD-JWT-VC mandate: ES256/P-256, ``cnf`` key-binding, KB-JWT.

This replaces the earlier "crypto is an injected callable; this module never
implements crypto" stand-in (see ``adapter.py``) with a genuine, self-consistent
implementation of the AP2 mandate format's cryptography, using only the
``cryptography`` library. It follows the SD-JWT-VC structure AP2 v0.2 specifies
(verified against ``github.com/google-agentic-commerce/AP2``,
``docs/ap2/agent_authorization.md``): an issuer-signed JWT carrying selectively
disclosable claims and a ``cnf`` key-binding claim, ``~``-joined disclosures, and
a holder-signed Key-Binding JWT that binds ``aud``/``nonce`` and hashes the
preceding token (``sd_hash``).

HONESTY / SCOPE (CLAUDE.md §1.5, §4):
- This is a *faithful implementation of the SD-JWT-VC format and its ES256/P-256
  cryptography*, NOT a run of Google's reference AP2 SDK (which is Python-only,
  installed from GitHub, not on PyPI). Issuer and verifier here agree on the same
  construction; interop with the reference SDK's exact byte layout is a separate
  task and is not claimed.
- What a verified mandate proves: the holder of the key named in ``cnf`` signed a
  fresh, audience-bound authorization under a trusted issuer. It says **nothing**
  about whether real-world authority actually flowed across organizations — that
  cross-org attribution gap is exactly what IndexOne adds and what
  ``ap2_attribution`` demonstrates. A valid mandate authenticates key possession,
  not the provenance of authority across hops.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

Jwk = dict[str, str]


class MandateError(ValueError):
    """An SD-JWT-VC mandate failed to construct or verify. Raised (fail closed)
    rather than returning a bare ``False``.
    """


# ── base64url + ES256 (JWS) primitives ──────────────────────────────────────


def _b64u(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    import base64

    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_issuer_key() -> ec.EllipticCurvePrivateKey:
    """A fresh ES256 (P-256) signing key."""
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> Jwk:
    """The P-256 public JWK for `key` (the form that goes in a ``cnf`` claim)."""
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }


def _jwk_to_public(jwk: Jwk) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise MandateError("cnf key must be an EC P-256 JWK")
    x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _jws_sign(
    key: ec.EllipticCurvePrivateKey,
    header: dict[str, Any],
    payload: dict[str, Any],
) -> str:
    """A compact ES256 JWS. JWS uses raw R||S (P1363), not the DER cryptography
    emits, so we convert."""
    signing_input = f"{_b64u(_canon(header))}.{_b64u(_canon(payload))}"
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input}.{_b64u(raw)}"


def _jws_verify(pub: ec.EllipticCurvePublicKey, token: str) -> dict[str, Any]:
    """Verify a compact ES256 JWS; return its payload or raise."""
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise MandateError("malformed JWS (need three dot-separated segments)") from exc
    raw = _b64u_decode(sig_b64)
    if len(raw) != 64:
        raise MandateError("ES256 signature must be 64 bytes (raw R||S)")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, f"{h_b64}.{p_b64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise MandateError("JWS signature is invalid") from exc
    return json.loads(_b64u_decode(p_b64))


def _canon(obj: dict[str, Any]) -> bytes:
    """Deterministic JSON bytes (sorted keys, tight separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── SD-JWT-VC mandate ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VerifiedMandate:
    """The result of verifying a presented mandate: the reconstructed claims
    (including selectively-disclosed ones) and the audience/nonce it was bound
    to. Only produced when every cryptographic check passed."""

    claims: dict[str, Any]
    audience: str
    nonce: str


def _disclosure(name: str, value: Any) -> str:
    """One SD-JWT disclosure: ``b64url(json([salt, name, value]))``."""
    salt = _b64u(os.urandom(16))
    return _b64u(_canon_list([salt, name, value]))


def _canon_list(items: list[Any]) -> bytes:
    return json.dumps(items, separators=(",", ":")).encode("utf-8")


def issue_mandate(
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    vct: str,
    holder_jwk: Jwk,
    disclosed_claims: dict[str, Any],
    always_present: dict[str, Any] | None = None,
    expires_at: int,
) -> str:
    """Issue an SD-JWT-VC: an issuer-signed JWT that binds the holder's key via
    ``cnf`` and carries `disclosed_claims` as selective disclosures.

    Returns the issuance form ``<issuer-jwt>~<disclosure>~...~`` (no KB-JWT yet;
    the holder adds that in :func:`present_mandate`).
    """
    disclosures = [_disclosure(name, value) for name, value in disclosed_claims.items()]
    sd_digests = [_b64u(_sha256(d.encode("ascii"))) for d in disclosures]
    payload: dict[str, Any] = {
        "vct": vct,
        "_sd": sorted(sd_digests),
        "_sd_alg": "sha-256",
        "cnf": {"jwk": holder_jwk},
        "exp": expires_at,
        **(always_present or {}),
    }
    issuer_jwt = _jws_sign(issuer_key, {"alg": "ES256", "typ": "dc+sd-jwt"}, payload)
    return "~".join([issuer_jwt, *disclosures]) + "~"


def present_mandate(
    issuance: str,
    holder_key: ec.EllipticCurvePrivateKey,
    *,
    audience: str,
    nonce: str,
    issued_at: int,
) -> str:
    """The holder (the ``cnf`` key) binds the issuance to an audience+nonce by
    appending a Key-Binding JWT whose ``sd_hash`` covers the presented prefix.
    Returns the full presentation ``<issuer-jwt>~<disclosures>~<kb-jwt>``.
    """
    # sd_hash is over the presentation prefix up to and including the final '~'
    # (SD-JWT §KB): the issuer JWT plus the disclosures being presented.
    sd_hash = _b64u(_sha256(issuance.encode("ascii")))
    kb = _jws_sign(
        holder_key,
        {"alg": "ES256", "typ": "kb+sd-jwt"},
        {"iat": issued_at, "aud": audience, "nonce": nonce, "sd_hash": sd_hash},
    )
    return issuance + kb


def verify_mandate(
    presentation: str,
    issuer_public: ec.EllipticCurvePublicKey,
    *,
    expected_audience: str,
    expected_nonce: str,
    now: int,
) -> VerifiedMandate:
    """Verify a presented SD-JWT-VC mandate end to end (fail closed):

    1. the issuer JWT's ES256 signature under the trusted `issuer_public`;
    2. expiry (``exp``) against `now`;
    3. every presented disclosure's digest is in the issuer's ``_sd`` set;
    4. the KB-JWT is signed by the key in the issuer's ``cnf`` claim (key-binding);
    5. the KB-JWT's ``sd_hash`` matches the presented prefix (no disclosure was
       added or dropped after issuance);
    6. ``aud``/``nonce`` match what the verifier expects (audience + replay).

    Returns the reconstructed claims, or raises :class:`MandateError`.
    """
    parts = presentation.split("~")
    if len(parts) < 2 or parts[-1] == "":
        raise MandateError("presentation must end with a Key-Binding JWT")
    issuer_jwt = parts[0]
    disclosures = parts[1:-1]
    kb_jwt = parts[-1]

    # 1–2. Issuer signature + expiry.
    body = _jws_verify(issuer_public, issuer_jwt)
    if int(body.get("exp", 0)) <= now:
        raise MandateError("mandate has expired")

    # 3. Every presented disclosure must be one the issuer committed to in _sd.
    committed = set(body.get("_sd", []))
    claims: dict[str, Any] = {
        k: v for k, v in body.items() if k not in {"_sd", "_sd_alg", "cnf"}
    }
    for d in disclosures:
        if _b64u(_sha256(d.encode("ascii"))) not in committed:
            raise MandateError("presented a disclosure the issuer never committed to")
        _salt, name, value = json.loads(_b64u_decode(d))
        claims[name] = value

    # 4. Key-binding: the KB-JWT must be signed by the cnf key.
    cnf = body.get("cnf", {}).get("jwk")
    if not cnf:
        raise MandateError("issuer JWT carries no cnf key-binding claim")
    kb = _jws_verify(_jwk_to_public(cnf), kb_jwt)

    # 5. sd_hash binds the KB-JWT to exactly the presented prefix.
    prefix = "~".join([issuer_jwt, *disclosures]) + "~"
    if kb.get("sd_hash") != _b64u(_sha256(prefix.encode("ascii"))):
        raise MandateError("KB-JWT sd_hash does not match the presented disclosures")

    # 6. Audience + replay.
    if kb.get("aud") != expected_audience:
        raise MandateError(
            f"mandate audience {kb.get('aud')!r} != expected {expected_audience!r}"
        )
    if kb.get("nonce") != expected_nonce:
        raise MandateError("mandate nonce does not match (possible replay)")

    return VerifiedMandate(
        claims=claims, audience=expected_audience, nonce=expected_nonce
    )
