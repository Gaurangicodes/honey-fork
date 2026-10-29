"""Dodo Payments adapter (FR-INT-05, SRS section 25 — P2, future billing).

SRS section 25 puts Dodo at **P2**: "No live payment flow required for the
hackathon MVP", and section 14 defers it as a business-model item. So this
adapter deliberately implements **read-only** usage metering, not checkout:

* a hosted SaaS would bill per scan, so the honest thing to build now is the
  ability to *report* how many scans a workspace has run against a Dodo meter;
* no checkout session, no charge, and no live payment path exists here. If a
  checkout endpoint is ever added it must not be reachable from the demo.

Contract (verified against https://docs.dodopayments.com/api-reference):

* Test base ``https://test.dodopayments.com``, live ``https://live.dodopayments.com``.
* ``Authorization: Bearer dodo_test_...`` / ``dodo_live_...``. A key prefixed for
  the wrong mode returns 401, so the mode and the key must agree.
* ``GET /payments?page_size=N`` returns ``{"items": [...], "total_count": N}``.
"""

from __future__ import annotations

from typing import Any

from .base import AdapterResult, Integration, IntegrationState, SetupStep

TEST_BASE_URL = "https://test.dodopayments.com"
LIVE_BASE_URL = "https://live.dodopayments.com"


class DodoPaymentsIntegration(Integration):
    name = "dodo"
    priority = "P2"
    docs_url = "https://docs.dodopayments.com/api-reference/introduction"
    required_config = ("DODO_PAYMENTS_API_KEY",)
    role = "Future hosted SaaS billing"
    acceptance = "No live payment flow required for hackathon MVP."

    @property
    def mode(self) -> str:
        """``test`` or ``live``, taken from the key prefix when present."""
        key = self._environ.get("DODO_PAYMENTS_API_KEY", "")
        if key.startswith("dodo_live_"):
            return "live"
        if key.startswith("dodo_test_"):
            return "test"
        return self._environ.get("DODO_PAYMENTS_MODE", "test")

    def _mode_conflict(self) -> str | None:
        """An explicit mode that disagrees with the key's prefix.

        The prefix is what Dodo enforces, so it wins. But an operator who sets
        ``DODO_PAYMENTS_MODE=test`` while holding a live key asked to stay in
        test and would silently be sent to live, which is the one accident a
        billing integration must not have. Surface it instead of complying.
        """
        explicit = self._environ.get("DODO_PAYMENTS_MODE")
        if not explicit:
            return None
        key = self._environ.get("DODO_PAYMENTS_API_KEY", "")
        prefix_mode = "live" if key.startswith("dodo_live_") else (
            "test" if key.startswith("dodo_test_") else None
        )
        if prefix_mode and explicit != prefix_mode:
            return prefix_mode
        return None

    @property
    def base_url(self) -> str:
        override = self._environ.get("DODO_PAYMENTS_API_URL")
        if override:
            return override.rstrip("/")
        return LIVE_BASE_URL if self.mode == "live" else TEST_BASE_URL

    def setup(self) -> list[SetupStep]:
        return [
            SetupStep(
                "Create an API key in the Dodo dashboard (Developer -> API Keys), "
                "read-only is sufficient for this adapter",
                "DODO_PAYMENTS_API_KEY",
                "dodo_test_...",
            ),
            SetupStep("Enable the adapter", self.flag_name, "1"),
            SetupStep(
                "Optional: force the mode when the key has no prefix",
                "DODO_PAYMENTS_MODE",
                "test",
            ),
            SetupStep(
                "Note: this adapter is read-only and performs no checkout or charge.",
            ),
        ]

    # -- capability ----------------------------------------------------------

    def payment_summary(self, *, page_size: int = 10) -> AdapterResult:
        """Read recent payments so usage can be metered. Never creates a charge."""
        if self.state() is not IntegrationState.OK:
            return self.unavailable()

        key = self._environ["DODO_PAYMENTS_API_KEY"]
        conflict = self._mode_conflict()
        if conflict:
            return AdapterResult(
                adapter=self.name,
                state=IntegrationState.ERROR,
                detail=(
                    f"DODO_PAYMENTS_MODE={self._environ['DODO_PAYMENTS_MODE']} conflicts "
                    f"with the key's {conflict}-mode prefix. Refusing to guess."
                ),
                reason="explicit mode conflicts with key prefix",
                error_code="DODO_MODE_MISMATCH",
            )
        # A key carrying the wrong mode's prefix is rejected by Dodo with 401.
        expected_prefix = f"dodo_{self.mode}_"
        if key.startswith("dodo_") and not key.startswith(expected_prefix):
            return AdapterResult(
                adapter=self.name,
                state=IntegrationState.ERROR,
                detail=(
                    f"Key prefix does not match mode '{self.mode}'. A {self.mode}-mode "
                    f"call needs a {expected_prefix} key."
                ),
                reason="key/mode mismatch",
                error_code="DODO_MODE_MISMATCH",
            )

        import httpx

        try:
            with self._client(self.base_url) as client:
                response = client.get(
                    "/payments",
                    params={"page_size": page_size},
                    headers={"Authorization": f"Bearer {key}"},
                )
        except httpx.HTTPError as exc:
            return self._error("DODO_UNREACHABLE", f"Dodo Payments unreachable: {exc}")

        if response.status_code == 401:
            return self._error("DODO_UNAUTHORIZED", "Dodo Payments rejected the API key.")
        if response.status_code == 403:
            return self._error(
                "DODO_FORBIDDEN",
                "Key lacks read access to payments (INSUFFICIENT_PERMISSION).",
            )
        if response.status_code >= 400:
            return self._error(
                "DODO_BAD_RESPONSE",
                f"Dodo Payments returned HTTP {response.status_code}.",
                status=response.status_code,
            )

        try:
            payload = response.json()
        except ValueError as exc:
            return self._error("DODO_BAD_RESPONSE", f"Unparseable response: {exc}")

        items = payload.get("items") or []
        # Surface counts and statuses only. Amounts, customer emails and payment
        # ids stay out: they are not needed to meter usage and are unnecessary
        # sensitive data in a security report (NFR-07).
        statuses: dict[str, int] = {}
        for item in items:
            status = str(item.get("status") or "unknown")
            statuses[status] = statuses.get(status, 0) + 1
        return AdapterResult(
            adapter=self.name,
            state=IntegrationState.OK,
            detail=f"Read {len(items)} recent payment(s) in {self.mode} mode.",
            findings=[
                {
                    "kind": "billing_summary",
                    "mode": self.mode,
                    "recent_payments": len(items),
                    "total_count": payload.get("total_count"),
                    "statuses": statuses,
                    "source": "dodo",
                }
            ],
            meta={"mode": self.mode, "base_url": self.base_url, "read_only": True},
        )

    def _error(self, code: str, detail: str, *, status: int | None = None) -> AdapterResult:
        meta: dict[str, Any] = {"mode": self.mode}
        if status is not None:
            meta["status"] = status
        return AdapterResult(
            adapter=self.name,
            state=IntegrationState.ERROR,
            detail=detail,
            reason=detail,
            error_code=code,
            meta=meta,
        )
