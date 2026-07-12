"""index-one SDK.

    pip install indexone

Target one-liner usage (once implemented):

    import indexone

    agent = indexone.wrap(my_agent, scope=..., budget=...)
    token = agent.sign(action)
    indexone.verify(token)

No real signing/verification is implemented yet -- see `indexone.client`
for the stubbed interface. The SDK is a thin wrapper; real cryptography
lives in the `indexone-chain` / `indexone-crypto` Rust core (`/core`), not
in this package.
"""

from .client import Client, verify, wrap

__all__ = ["Client", "wrap", "verify"]
