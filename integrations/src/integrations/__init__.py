"""Rail integrations and attack POC for index-one.

Submodules:
    ap2    -- adapters against the AP2 mandate format.
    mcp    -- MCP request-header signing/verification hooks.
    attack -- cross-org attribution attack harness (runnable placeholder).
"""

from . import ap2, attack, mcp

__all__ = ["ap2", "mcp", "attack"]
