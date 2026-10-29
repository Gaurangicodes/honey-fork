"""Optional ecosystem adapters (SRS 20.6).

Importing this package has no side effects: no adapter makes a network call
until one of its methods is invoked, and none is enabled unless its feature flag
is set. That is what lets the core proof loop run unchanged with every adapter
disabled (FR-INT-01).
"""

from __future__ import annotations

from typing import Any, Mapping

from .base import (
    GLOBAL_FLAG,
    AdapterRegistry,
    AdapterResult,
    Integration,
    IntegrationState,
    IntegrationUnavailable,
    SetupStep,
)
from .dodo_adapter import DodoPaymentsIntegration
from .socket_adapter import SocketIntegration
from .tigergraph_adapter import TigerGraphIntegration, build_upsert_payload
from .wisprflow_adapter import (
    VOICE_OPERATIONS,
    VoiceCommandRefused,
    WisprFlowIntegration,
)

__all__ = [
    "GLOBAL_FLAG",
    "AdapterRegistry",
    "AdapterResult",
    "DodoPaymentsIntegration",
    "Integration",
    "IntegrationState",
    "IntegrationUnavailable",
    "SetupStep",
    "SocketIntegration",
    "TigerGraphIntegration",
    "VOICE_OPERATIONS",
    "VoiceCommandRefused",
    "WisprFlowIntegration",
    "build_registry",
    "build_upsert_payload",
]


def build_registry(environ: Mapping[str, str] | None = None) -> AdapterRegistry:
    """Build the registry of optional adapters.

    Every adapter is constructed regardless of its flag so the dashboard can
    show a disabled adapter, its flag name and its setup steps. Construction is
    free: no adapter reads a credential or opens a connection until called.
    """
    return AdapterRegistry(
        [
            SocketIntegration(environ),
            TigerGraphIntegration(environ),
            WisprFlowIntegration(environ),
            DodoPaymentsIntegration(environ),
        ]
    )


def registry_from_state(state: Any) -> AdapterRegistry | None:
    """Fetch the registry attached to the API state, if present."""
    return getattr(state, "integrations", None)
