"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from agentcrash.api.app import create_app
from agentcrash.core.orchestrator import Orchestrator
from agentcrash.core.store import Store
from agentcrash.sandbox.manager import SandboxManager, default_demo_environment


@pytest.fixture()
def store() -> Store:
    return Store(":memory:")


@pytest.fixture()
def environment():
    return default_demo_environment()


@pytest.fixture()
def manager(environment) -> SandboxManager:
    return SandboxManager(environment)


@pytest.fixture()
def orchestrator(store, environment, manager) -> Orchestrator:
    return Orchestrator(store, environment, manager)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A real app instance with its own data directory, so tests never share state."""
    monkeypatch.chdir(tmp_path)
    with TestClient(create_app()) as c:
        yield c
