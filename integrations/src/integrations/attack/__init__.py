"""Cross-org attribution attack harness.

Demonstrates, with a runnable placeholder (no real cryptography), the gap
index-one exists to close: a single-hop AP2-style mandate lets you verify
"this mandate is bound to this agent", but gives you no way to attribute a
downstream action back to the original human principal once authority has
passed through a 3-agent, cross-org delegation chain.
"""

from .harness import ThreeAgentChain, run_attack

__all__ = ["ThreeAgentChain", "run_attack"]
