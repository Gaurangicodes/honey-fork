"""Socket dependency preflight adapter (FR-INT-02, SRS section 25).

Socket scans a dependency set for supply-chain risk: malware, typosquats,
install scripts, obfuscated code, telemetry and so on. For a product whose whole
claim is "an agent can be manipulated into moving funds it should not", the
relevant use is narrower than a general SBOM: report the supply-chain risk of
the packages the *tested agent* is allowed to load, so a reviewer can see
whether the harness itself is pulling something dangerous.

Contract (verified against https://docs.socket.dev):

* ``POST {base}/v0/orgs/{org_slug}/purl`` with ``Authorization: Bearer <token>``.
* Body ``{"components": [{"purl": "pkg:npm/express@4.19.2"}, ...]}``.
* Response is an **NDJSON stream** (``application/x-ndjson``), one JSON object
  per line. Lines are either an artifact (has ``type``/``name``/``version`` and
  ``alerts``/``score``) or a control record with ``_type`` of ``purlError`` or
  ``summary``.

Socket may synthesise two alert types so partial results stay actionable:
``pendingScan`` (analysis not finished) and ``notFound`` (unresolvable). Both
are surfaced verbatim, because "we could not resolve this package" is a real
result and must not be silently dropped or counted as clean.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from .base import AdapterResult, Integration, IntegrationState, SetupStep

# Socket returns severity as low/middle/high/critical. "middle" is Socket's own
# spelling; map it to the conventional "medium" for display but keep the raw
# value in the finding so nothing is invented.
_SEVERITY_RANK = {"critical": 4, "high": 3, "middle": 2, "medium": 2, "low": 1}


class SocketIntegration(Integration):
    name = "socket"
    priority = "P1"
    docs_url = "https://docs.socket.dev/reference/batchpackagefetchbyorg"
    required_config = ("SOCKET_API_TOKEN", "SOCKET_ORG_SLUG")
    role = "Optional dependency/supply-chain security preflight"
    acceptance = (
        "Real integration output or explicit 'not configured/not run' state; "
        "never fabricate findings."
    )

    @property
    def base_url(self) -> str:
        return self._environ.get("SOCKET_API_URL", "https://api.socket.dev").rstrip("/")

    def setup(self) -> list[SetupStep]:
        return [
            SetupStep(
                "Create an organization API token in Socket (Settings -> API Tokens)",
                "SOCKET_API_TOKEN",
            ),
            SetupStep("Provide your Socket organization slug", "SOCKET_ORG_SLUG", "my-org"),
            SetupStep("Enable the adapter", self.flag_name, "1"),
            SetupStep(
                "Optional: override the API base URL",
                "SOCKET_API_URL",
                "https://api.socket.dev",
            ),
        ]

    # -- capability ----------------------------------------------------------

    def preflight(self, purls: Iterable[str], *, poll: bool = False) -> AdapterResult:
        """FR-INT-02: run a real dependency preflight over ``purls``.

        Returns ``disabled``/``not_configured`` without making a call when the
        adapter is not usable, and ``error`` with a machine-readable code when
        the call fails. Findings are only ever present in the ``ok`` state.
        """
        purls = [p for p in purls if p]
        if self.state() is not IntegrationState.OK:
            return self.unavailable()
        if not purls:
            return AdapterResult(
                adapter=self.name,
                state=IntegrationState.OK,
                detail="No packages to scan.",
                meta={"scanned": 0},
            )

        import httpx

        params = {"alerts": "true", "compact": "true"}
        if poll:
            params["poll"] = "true"
        try:
            with self._client(self.base_url) as client:
                response = client.post(
                    f"/v0/orgs/{self._environ['SOCKET_ORG_SLUG']}/purl",
                    params=params,
                    headers={
                        "Authorization": f"Bearer {self._environ['SOCKET_API_TOKEN']}",
                        "Accept": "application/x-ndjson",
                        "Content-Type": "application/json",
                    },
                    json={"components": [{"purl": p} for p in purls]},
                )
        except httpx.HTTPError as exc:
            return self._error("SOCKET_UNREACHABLE", f"Socket request failed: {exc}")

        if response.status_code == 401:
            return self._error("SOCKET_UNAUTHORIZED", "Socket rejected the API token.")
        if response.status_code == 403:
            return self._error("SOCKET_FORBIDDEN", "Token lacks the packages:list scope.")
        if response.status_code == 429:
            return self._error("SOCKET_QUOTA_EXCEEDED", "Socket API quota exceeded.")
        if response.status_code >= 400:
            return self._error(
                "SOCKET_BAD_RESPONSE",
                f"Socket returned HTTP {response.status_code}.",
                status=response.status_code,
            )

        try:
            artifacts, controls = self._parse_ndjson(response.text)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._error("SOCKET_BAD_RESPONSE", f"Unparseable NDJSON: {exc}")

        findings = self._to_findings(artifacts, controls)
        return AdapterResult(
            adapter=self.name,
            state=IntegrationState.OK,
            detail=f"Scanned {len(purls)} package(s); {len(findings)} finding(s).",
            findings=findings,
            meta={
                "scanned": len(purls),
                "artifacts": len(artifacts),
                "purl_errors": len(controls.get("purlError", [])),
                "summary": controls.get("summary"),
                "endpoint": f"{self.base_url}/v0/orgs/{self._environ['SOCKET_ORG_SLUG']}/purl",
            },
        )

    # -- parsing -------------------------------------------------------------

    @staticmethod
    def _parse_ndjson(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Split an NDJSON body into artifact rows and control records."""
        artifacts: list[dict[str, Any]] = []
        controls: dict[str, Any] = {"purlError": []}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            kind = row.get("_type")
            if kind == "purlError":
                controls["purlError"].append(row.get("value", {}))
            elif kind == "summary":
                controls["summary"] = row.get("value", {})
            else:
                artifacts.append(row)
        return artifacts, controls

    @staticmethod
    def _to_findings(
        artifacts: list[dict[str, Any]], controls: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """One finding per alert, plus a finding per unresolved package.

        ``pendingScan``/``notFound`` are Socket's synthetic alerts; they are
        reported as-is so an unresolved package is never mistaken for a clean
        one.
        """
        findings: list[dict[str, Any]] = []
        for artifact in artifacts:
            name = artifact.get("name") or artifact.get("id") or "unknown"
            version = artifact.get("version") or ""
            purl = _purl_of(artifact, name, version)
            for alert in artifact.get("alerts") or []:
                severity = alert.get("severity") or "low"
                findings.append(
                    {
                        "kind": "alert",
                        "purl": purl,
                        "package": name,
                        "version": version,
                        "type": alert.get("type", ""),
                        "severity": severity,
                        "severity_rank": _SEVERITY_RANK.get(severity, 0),
                        "category": alert.get("category", ""),
                        "key": alert.get("key", ""),
                        "props": alert.get("props") or {},
                        "source": "socket",
                    }
                )
        for err in controls.get("purlError", []):
            findings.append(
                {
                    "kind": "unresolved",
                    "purl": err.get("purl") or err.get("purl_input") or "",
                    "package": "",
                    "version": "",
                    "type": "notFound",
                    "severity": "unknown",
                    "severity_rank": 0,
                    "category": "resolution",
                    "key": "",
                    "props": err,
                    "source": "socket",
                }
            )
        findings.sort(key=lambda f: f["severity_rank"], reverse=True)
        return findings

    def _error(
        self, code: str, detail: str, *, status: int | None = None
    ) -> AdapterResult:
        meta: dict[str, Any] = {}
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


def _purl_of(artifact: dict[str, Any], name: str, version: str) -> str:
    purl = artifact.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    ecosystem = (artifact.get("type") or "").lower()
    if ecosystem and name:
        return f"pkg:{ecosystem}/{name}@{version}" if version else f"pkg:{ecosystem}/{name}"
    return ""
