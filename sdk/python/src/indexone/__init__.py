"""IndexOne SDK.

    pip install indexone

Thin bindings over the Rust core (``/core``) via the ``indexone-cli`` sidecar --
real signing/verification lives in ``indexone-chain`` / ``indexone-crypto``, not
in this package. Build the sidecar with ``cargo build -p indexone-cli`` and put
it on ``PATH`` or point ``INDEXONE_CLI`` at it.

    import indexone
    from indexone import Principal, Scope

    alice = indexone.wrap("00" * 32, Principal("human:alice", "Alice"))
    scope = Scope(["payments.charge"], max_depth=2, expires_at=EXP, budget=10_000)
    issued = alice.issue(scope)
    step = alice.attenuate(
        issued["chain"], Principal("agent:a@org1", "A"), "11" * 32,
        Scope(["payments.charge"], max_depth=1, expires_at=EXP, budget=5_000),
        "book travel",
    )
    # Raises IndexOneError (fail closed) if the chain is invalid:
    effective = indexone.verify(step["chain"], issued["root_key"])
"""

from .client import (
    Client,
    IndexOneError,
    Principal,
    Scope,
    attenuate,
    attest,
    bind_action,
    chain_digest,
    composed_verify,
    issue,
    pubkey,
    verify,
    witness_append,
    wrap,
)

__all__ = [
    "Client",
    "IndexOneError",
    "Principal",
    "Scope",
    "attenuate",
    "attest",
    "bind_action",
    "chain_digest",
    "composed_verify",
    "issue",
    "pubkey",
    "verify",
    "witness_append",
    "wrap",
]
