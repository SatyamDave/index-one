"""Scaffold-level tests for MCP request-header hooks. No real signing or
verification exists yet -- these only pin down that the stub interface
raises as expected.
"""

from dataclasses import dataclass, field

import pytest

from integrations.mcp import sign_request_headers, verify_request_headers


@dataclass
class FakeRequest:
    method: str = "POST"
    url: str = "https://example.org/mcp"
    headers: dict[str, str] = field(default_factory=dict)


def test_sign_request_headers_is_not_yet_implemented() -> None:
    with pytest.raises(NotImplementedError):
        sign_request_headers(FakeRequest(), chain_token=b"placeholder-token")


def test_verify_request_headers_is_not_yet_implemented() -> None:
    with pytest.raises(NotImplementedError):
        verify_request_headers(FakeRequest())
