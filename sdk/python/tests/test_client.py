"""Scaffold-level tests for the SDK client stub. No real signing/
verification exists yet -- these only pin down that the stub interface
raises as expected.
"""

import pytest

import indexone
from indexone.client import Client


def test_client_sign_is_not_yet_implemented() -> None:
    client = Client(agent_id="agent:a@org1")
    with pytest.raises(NotImplementedError):
        client.sign(b"payload")


def test_client_verify_is_not_yet_implemented() -> None:
    client = Client(agent_id="agent:a@org1")
    with pytest.raises(NotImplementedError):
        client.verify(b"token")


def test_module_level_wrap_is_not_yet_implemented() -> None:
    with pytest.raises(NotImplementedError):
        indexone.wrap(object())


def test_module_level_verify_is_not_yet_implemented() -> None:
    with pytest.raises(NotImplementedError):
        indexone.verify(b"token")
