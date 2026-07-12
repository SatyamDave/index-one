"""Adapters between AP2 (google-agentic-commerce/AP2) mandates and index-one
capability-chain blocks.
"""

from .adapter import AP2Mandate, mandate_to_delegation_block

__all__ = ["AP2Mandate", "mandate_to_delegation_block"]
