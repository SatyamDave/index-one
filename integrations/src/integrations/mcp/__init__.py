"""MCP request-header signing/verification hooks (Web Bot Auth / RFC 9421)."""

from .hooks import (
    TOKEN_HEADER,
    MCPVerificationError,
    Signer,
    Verifier,
    sign_request,
    verify_request,
)

__all__ = [
    "TOKEN_HEADER",
    "MCPVerificationError",
    "Signer",
    "Verifier",
    "sign_request",
    "verify_request",
]
