"""Shared fixtures.

Every test gets its own policy, its own database and its own temp directory,
so nothing leaks between tests and none of them touch a real `swarms.db` in
the working directory.
"""
from __future__ import annotations

import pytest

from swarms.config import Policy
from swarms.guard import Guard
from swarms.store import AuditStore

POLICY = {
    "version": 1,
    "name": "test",
    "actions": {
        "send_email": {
            "capability": "email.send",
            "control_args": ["to", "cc"],
            "data_args": ["subject", "body"],
        },
        "run_command": {
            "capability": "exec.run",
            "control_args": ["command"],
            "data_args": ["stdin"],
        },
        "charge_card": {
            "capability": "payments.charge",
            "control_args": ["customer_id", "amount"],
            "data_args": ["description"],
            "require_approval": True,
        },
        # A second approval-gated action, so cross-action reuse of an
        # approval is actually testable.
        "wire_transfer": {
            "capability": "payments.wire",
            "control_args": ["customer_id", "amount"],
            "data_args": ["reference"],
            "require_approval": True,
        },
    },
    "principals": {
        "mailer": {"capabilities": ["email.send"]},
        "runner": {"capabilities": ["exec.*"]},
        "billing": {"capabilities": ["payments.charge", "payments.wire"]},
        "nobody": {"capabilities": []},
    },
    "defaults": {"unlabeled_value": "trusted"},
}


@pytest.fixture
def policy() -> Policy:
    return Policy.from_dict(POLICY)


@pytest.fixture
def store(tmp_path) -> AuditStore:
    return AuditStore(str(tmp_path / "audit.db"))


@pytest.fixture
def guard(policy, store) -> Guard:
    return Guard(policy, store)


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Keep policy discovery and the default database out of the repo."""
    monkeypatch.setenv("SWARMS_DB", str(tmp_path / "swarms.db"))
    monkeypatch.delenv("SWARMS_POLICY", raising=False)
    monkeypatch.delenv("SWARMS_API_KEYS", raising=False)
    monkeypatch.delenv("SWARMS_ENV", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path
