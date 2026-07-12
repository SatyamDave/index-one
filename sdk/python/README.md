# indexone (SDK)

Thin public SDK for index-one: wrap any agent, sign and verify its
cross-org delegation chain.

```
pip install indexone
```

```python
import indexone

agent = indexone.wrap(my_agent, scope=...)
token = agent.sign(action)
indexone.verify(token)
```

Not implemented yet -- every call above currently raises
`NotImplementedError`. This package is a thin wrapper; real cryptography
and chain logic live in `/core` (Rust). See `/docs/REFERENCE.md`.
