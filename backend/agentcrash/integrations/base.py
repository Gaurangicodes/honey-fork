"""Optional ecosystem adapters (SRS 20.6, FR-INT-01..05).

Every adapter in this package is **optional**. The core proof loop — attack →
enforceable policy → replay → legitimate regression — must run with all of them
disabled, so nothing here may be required by the orchestrator, the verifier, the
policy proxy or the evidence store.

Three rules are enforced structurally rather than by convention:

1. **Opt-in.** An adapter is only enabled when its feature flag is explicitly
   set. Presence of a credential alone does not start outbound calls.
2. **Honest states.** An adapter reports ``disabled``, ``not_configured``,
   ``ok``, ``error`` or ``unsupported``. It never reports a result it did not
   obtain. :class:`AdapterResult` refuses to carry findings unless the state is
   ``ok``, so "not run" can never be dressed up as a clean scan.
3. **No control.** Adapters return data. They cannot approve a policy, sign a
   transaction, authorise a transfer or alter a verdict (FR-INT-04).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

# Feature-flag prefix. A flag is read as ``<PREFIX><ADAPTER>`` e.g.
# ``AGENTCRASH_INTEGRATION_SOCKET``.
FLAG_PREFIX = "AGENTCRASH_INTEGRATION_"

# Global kill switch. Set to a falsey value to force every adapter off at once,
# which is how the demo proves the core loop survives with nothing connected.
GLOBAL_FLAG = "AGENTCRASH_INTEGRATIONS_ENABLED"

_FALSEY = {"", "0", "false", "no", "off", "disabled"}


def flag_enabled(environ: Mapping[str, str], name: str) -> bool:
    """True when an env flag is set to something other than a falsey token."""
    value = environ.get(name)
    if value is None:
        return False
    return value.strip().lower() not in _FALSEY


class IntegrationState(str, Enum):
    """The only states an adapter may report (FR-INT-01)."""

    # Flag not set: the adapter is off by choice and made no calls.
    DISABLED = "disabled"
    # Flag set but required configuration is missing.
    NOT_CONFIGURED = "not_configured"
    # Configured and reachable; results below are real.
    OK = "ok"
    # Configured but the last call failed. Carries a machine-readable reason.
    ERROR = "error"
    # The capability has no public API; see the adapter for the supported path.
    UNSUPPORTED = "unsupported"


class IntegrationUnavailable(Exception):
    """Raised when an adapter is asked to work while not in the ``ok`` state."""

    def __init__(self, name: str, state: IntegrationState, detail: str) -> None:
        super().__init__(f"{name} is {state.value}: {detail}")
        self.name = name
        self.state = state
        self.detail = detail


@dataclass
class AdapterResult:
    """What an adapter returns.

    ``state`` must be ``OK`` for ``findings`` to be non-empty. This is the
    structural half of FR-INT-02: an adapter cannot claim it ran when it did
    not, because the constructor rejects findings on any other state.
    """

    adapter: str
    state: IntegrationState
    detail: str = ""
    # Human-readable reason the adapter is not usable, when it is not.
    reason: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    # Non-secret provenance: endpoint, org, counts, timings.
    meta: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.state is not IntegrationState.OK and self.findings:
            raise ValueError(
                f"{self.adapter}: refusing to report {len(self.findings)} findings "
                f"in state {self.state.value!r}; findings require state 'ok'"
            )

    @property
    def ran(self) -> bool:
        """True only when a real call produced real data."""
        return self.state is IntegrationState.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "state": self.state.value,
            "detail": self.detail,
            "reason": self.reason,
            "ran": self.ran,
            "findings": self.findings,
            "meta": self.meta,
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class SetupStep:
    """One line of explicit setup documentation (FR-INT-01)."""

    description: str
    env_var: str | None = None
    example: str | None = None


class Integration:
    """Base class for an optional adapter.

    Subclasses set the class attributes and implement their capability methods.
    """

    name: str = "integration"
    # SRS section 25 priority: "P1" or "P2".
    priority: str = "P1"
    docs_url: str = ""
    # Environment variables required before the adapter can call out.
    required_config: tuple[str, ...] = ()
    # What the adapter is for, in the SRS's own words.
    role: str = ""
    # What must be demonstrated before the adapter counts as accepted.
    acceptance: str = ""

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        transport: Any = None,
    ) -> None:
        self._environ = dict(os.environ if environ is None else environ)
        # An injected httpx transport lets tests exercise the real request
        # building, parsing and error handling without network access.
        self._transport = transport

    # -- configuration -------------------------------------------------------

    @property
    def flag_name(self) -> str:
        return f"{FLAG_PREFIX}{self.name.upper()}"

    @property
    def enabled(self) -> bool:
        """FR-INT-01: opt-in, and the global switch can force everything off."""
        if not flag_enabled(self._environ, GLOBAL_FLAG):
            return False
        return flag_enabled(self._environ, self.flag_name)

    def missing_config(self) -> list[str]:
        return [v for v in self.required_config if not self._environ.get(v)]

    def _configured(self) -> bool:
        return not self.missing_config()

    # -- status --------------------------------------------------------------

    def state(self) -> IntegrationState:
        if not self.enabled:
            return IntegrationState.DISABLED
        if not self._configured():
            return IntegrationState.NOT_CONFIGURED
        return IntegrationState.OK

    def status(self) -> dict[str, Any]:
        """A dashboard-safe description. Never contains credential values."""
        state = self.state()
        return {
            "adapter": self.name,
            "role": self.role,
            "priority": self.priority,
            "state": state.value,
            "enabled": self.enabled,
            "flag": self.flag_name,
            "configured": self._configured(),
            # Names only, never values.
            "required_config": list(self.required_config),
            "missing_config": self.missing_config(),
            "docs_url": self.docs_url,
            "acceptance": self.acceptance,
            "detail": self._status_detail(state),
            "setup": [s.__dict__ for s in self.setup()],
        }

    def _status_detail(self, state: IntegrationState) -> str:
        if state is IntegrationState.DISABLED:
            return f"Not enabled. Set {self.flag_name}=1 to opt in."
        if state is IntegrationState.NOT_CONFIGURED:
            missing = ", ".join(self.missing_config())
            return f"Enabled but missing configuration: {missing}."
        if state is IntegrationState.UNSUPPORTED:
            return "No public API; see docs_url for the supported path."
        return "Configured."

    def setup(self) -> list[SetupStep]:
        """Explicit setup steps (FR-INT-01). Overridden per adapter."""
        steps = [
            SetupStep(
                description="Enable the adapter",
                env_var=self.flag_name,
                example="1",
            )
        ]
        steps += [
            SetupStep(description=f"Provide {v}", env_var=v) for v in self.required_config
        ]
        return steps

    def require_ready(self) -> None:
        """Raise unless the adapter can make a real call."""
        state = self.state()
        if state is not IntegrationState.OK:
            raise IntegrationUnavailable(self.name, state, self._status_detail(state))

    def unavailable(self, detail: str | None = None) -> AdapterResult:
        """An honest 'did not run' result for the current state."""
        state = self.state()
        return AdapterResult(
            adapter=self.name,
            state=state,
            detail=detail or self._status_detail(state),
            reason="adapter not usable",
        )

    # -- http ----------------------------------------------------------------

    def _client(self, base_url: str, timeout: float = 15.0) -> Any:
        import httpx

        kwargs: dict[str, Any] = {"base_url": base_url, "timeout": timeout}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.Client(**kwargs)


class AdapterRegistry:
    """Holds the optional adapters and reports their combined status."""

    def __init__(self, integrations: list[Integration] | None = None) -> None:
        self._items: list[Integration] = list(integrations or [])

    def register(self, integration: Integration) -> None:
        self._items.append(integration)

    def __iter__(self):
        return iter(self._items)

    def get(self, name: str) -> Integration | None:
        for item in self._items:
            if item.name == name:
                return item
        return None

    def statuses(self) -> list[dict[str, Any]]:
        return [i.status() for i in self._items]

    def summary(self) -> dict[str, Any]:
        """Aggregate view. Adapters are optional, so the core is unaffected."""
        statuses = self.statuses()
        counts: dict[str, int] = {}
        for s in statuses:
            counts[s["state"]] = counts.get(s["state"], 0) + 1
        return {
            "integrations": statuses,
            "counts": counts,
            "any_enabled": any(s["enabled"] for s in statuses),
            "note": (
                "Optional adapters. The core attack -> policy -> replay proof "
                "runs with every adapter disabled."
            ),
        }
