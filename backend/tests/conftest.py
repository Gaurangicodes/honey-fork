"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

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
