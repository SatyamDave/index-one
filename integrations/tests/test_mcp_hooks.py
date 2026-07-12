"""Tests for the MCP / Web Bot Auth header hooks.

The Ed25519 signer/verifier are injected; these tests use a deterministic fake
(a blake2b tag over payload+key_id) to exercise the transport logic without real
crypto -- real Ed25519 lives in the IndexOne core / SDK.
"""

from __future__ import annotations

import hashlib

import pytest

from integrations.mcp import MCPVerificationError, sign_request, verify_request


class _FakeSigner:
    key_id = "test-key-thumbprint"

    def sign(self, payload: bytes) -> bytes:
        return hashlib.blake2b(payload + self.key_id.encode(), digest_size=32).digest()


class _FakeVerifier:
    def verify(self, payload: bytes, signature: bytes, key_id: str) -> bool:
        expected = hashlib.blake2b(payload + key_id.encode(), digest_size=32).digest()
        return signature == expected


TOKEN = b"indexone-capability-chain-bytes"


def test_sign_then_verify_round_trips_and_returns_token() -> None:
    headers = sign_request(
        method="POST",
        path="/mcp/tools/charge",
        chain_token=TOKEN,
        signer=_FakeSigner(),
        key_directory_url="https://org1.example/.well-known/http-message-signatures-directory",
        created=1_700_000_000,
    )
    assert set(headers) >= {"Signature", "Signature-Input", "Signature-Agent", "X-IndexOne-Token"}
    recovered = verify_request(
        method="POST",
        path="/mcp/tools/charge",
        headers=headers,
        verifier=_FakeVerifier(),
    )
    assert recovered == TOKEN


def test_tampered_path_fails_closed() -> None:
    headers = sign_request(
        method="POST",
        path="/mcp/tools/charge",
        chain_token=TOKEN,
        signer=_FakeSigner(),
        key_directory_url="https://org1.example/dir",
        created=1_700_000_000,
    )
    # An attacker replays the signature against a different path.
    with pytest.raises(MCPVerificationError):
        verify_request(
            method="POST",
            path="/mcp/tools/refund",
            headers=headers,
            verifier=_FakeVerifier(),
        )


def test_tampered_token_fails_closed() -> None:
    headers = sign_request(
        method="GET",
        path="/mcp/resource",
        chain_token=TOKEN,
        signer=_FakeSigner(),
        key_directory_url="https://org1.example/dir",
        created=1_700_000_000,
    )
    headers["X-IndexOne-Token"] = "dGFtcGVyZWQ"  # swap in a different token
    with pytest.raises(MCPVerificationError):
        verify_request(
            method="GET",
            path="/mcp/resource",
            headers=headers,
            verifier=_FakeVerifier(),
        )


def test_missing_header_fails_closed() -> None:
    with pytest.raises(MCPVerificationError):
        verify_request(
            method="GET",
            path="/x",
            headers={"Signature": "sig1=:AAA:"},
            verifier=_FakeVerifier(),
        )
