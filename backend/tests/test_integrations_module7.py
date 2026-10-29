"""Optional adapter tests (FR-INT-01..05).

These exercise the real request-building, NDJSON parsing, projection and refusal
logic by injecting an ``httpx.MockTransport``. The transport is a real httpx
transport, so the code under test runs unmodified; only the socket is replaced.
Nothing here mocks the adapter's own logic.

The load-bearing assertions are the negative ones: an adapter that is off or
unconfigured must report that it did not run, and must never emit a finding.
"""

from __future__ import annotations

import json

import httpx
import pytest

from agentcrash.integrations import (
    IntegrationState,
    build_registry,
    build_upsert_payload,
)
from agentcrash.integrations.base import AdapterResult
from agentcrash.integrations.dodo_adapter import DodoPaymentsIntegration
from agentcrash.integrations.socket_adapter import SocketIntegration
from agentcrash.integrations.tigergraph_adapter import TigerGraphIntegration
from agentcrash.integrations.wisprflow_adapter import WisprFlowIntegration


def transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


# -- FR-INT-01: opt-in, honest states, core isolation ------------------------


def test_every_adapter_is_disabled_by_default():
    registry = build_registry({})
    statuses = registry.statuses()
    assert len(statuses) == 4
    assert all(s["state"] == "disabled" for s in statuses)
    assert registry.summary()["any_enabled"] is False


def test_global_kill_switch_overrides_an_enabled_flag():
    environ = {
        "AGENTCRASH_INTEGRATIONS_ENABLED": "0",
        "AGENTCRASH_INTEGRATION_SOCKET": "1",
        "SOCKET_API_TOKEN": "t",
        "SOCKET_ORG_SLUG": "o",
    }
    socket = SocketIntegration(environ)
    assert socket.enabled is False
    assert socket.state() is IntegrationState.DISABLED


def test_enabled_without_credentials_is_not_configured():
    socket = SocketIntegration({"AGENTCRASH_INTEGRATIONS_ENABLED": "1", "AGENTCRASH_INTEGRATION_SOCKET": "1"})
    assert socket.state() is IntegrationState.NOT_CONFIGURED
    assert "SOCKET_API_TOKEN" in socket.missing_config()


def test_status_never_leaks_credential_values():
    secret = "dodo_test_supersecretvalue"
    dodo = DodoPaymentsIntegration(
        {
            "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
            "AGENTCRASH_INTEGRATION_DODO": "1",
            "DODO_PAYMENTS_API_KEY": secret,
        }
    )
    blob = json.dumps(dodo.status())
    assert secret not in blob
    assert "DODO_PAYMENTS_API_KEY" in blob  # the name is fine, the value is not


def test_adapter_result_refuses_findings_unless_ok():
    """The structural half of FR-INT-02: no fabricated results."""
    with pytest.raises(ValueError, match="findings require state 'ok'"):
        AdapterResult(
            adapter="socket",
            state=IntegrationState.DISABLED,
            findings=[{"kind": "alert"}],
        )
    with pytest.raises(ValueError):
        AdapterResult(
            adapter="socket",
            state=IntegrationState.ERROR,
            findings=[{"kind": "alert"}],
        )


def test_disabled_adapter_makes_no_network_call():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url)
        return httpx.Response(200, json={})

    socket = SocketIntegration(
        {}, transport=transport(handler)
    )
    result = socket.preflight(["pkg:pypi/fastapi@0.115.0"])
    assert result.ran is False
    assert result.findings == []
    assert calls == [], "a disabled adapter must not touch the network"


def test_core_registry_summary_notes_adapters_are_optional():
    assert "core" in build_registry({}).summary()["note"].lower()


# -- FR-INT-02: Socket ------------------------------------------------------


SOCKET_ENV = {
    "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
    "AGENTCRASH_INTEGRATION_SOCKET": "1",
    "SOCKET_API_TOKEN": "tok",
    "SOCKET_ORG_SLUG": "acme",
}


def _socket(handler) -> SocketIntegration:
    return SocketIntegration(SOCKET_ENV, transport=transport(handler))


def test_socket_sends_bearer_token_and_purl_components():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})

    result = _socket(handler).preflight(["pkg:pypi/fastapi@0.115.0"])
    assert result.state is IntegrationState.OK
    assert seen["auth"] == "Bearer tok"
    assert "/v0/orgs/acme/purl" in seen["url"]
    assert seen["body"] == {"components": [{"purl": "pkg:pypi/fastapi@0.115.0"}]}


def test_socket_parses_ndjson_artifacts_and_alerts():
    lines = [
        json.dumps(
            {
                "type": "npm",
                "name": "evil-pkg",
                "version": "1.0.0",
                "purl": "pkg:npm/evil-pkg@1.0.0",
                "alerts": [
                    {
                        "type": "malware",
                        "severity": "critical",
                        "category": "supplyChainRisk",
                        "key": "k1",
                        "props": {"note": "install script"},
                    },
                    {"type": "telemetry", "severity": "middle", "category": "supplyChainRisk"},
                ],
            }
        ),
        json.dumps({"_type": "summary", "value": {"purl_input": 1, "resolved": 1}}),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="\n".join(lines))

    result = _socket(handler).preflight(["pkg:npm/evil-pkg@1.0.0"])
    assert result.state is IntegrationState.OK
    assert len(result.findings) == 2
    # Highest severity first, and Socket's own "middle" spelling is preserved.
    assert result.findings[0]["severity"] == "critical"
    assert result.findings[1]["severity"] == "middle"
    assert result.findings[1]["severity_rank"] == 2
    assert result.findings[0]["purl"] == "pkg:npm/evil-pkg@1.0.0"


def test_socket_reports_unresolved_packages_as_findings_not_as_clean():
    """A package Socket could not resolve is a finding, never a clean pass."""
    lines = [
        json.dumps(
            {
                "_type": "purlError",
                "value": {"purl": "pkg:npm/ghost@9.9.9", "error": "not found"},
            }
        )
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="\n".join(lines))

    result = _socket(handler).preflight(["pkg:npm/ghost@9.9.9"])
    assert result.state is IntegrationState.OK
    assert len(result.findings) == 1
    assert result.findings[0]["type"] == "notFound"
    assert result.findings[0]["kind"] == "unresolved"


def test_socket_error_states_carry_machine_readable_codes():
    for status, code in ((401, "SOCKET_UNAUTHORIZED"), (403, "SOCKET_FORBIDDEN"), (429, "SOCKET_QUOTA_EXCEEDED")):
        def handler(request: httpx.Request, _status=status) -> httpx.Response:
            return httpx.Response(_status, json={"error": {"message": "nope"}})

        result = _socket(handler).preflight(["pkg:pypi/x@1"])
        assert result.state is IntegrationState.ERROR
        assert result.error_code == code
        assert result.ran is False
        assert result.findings == []


def test_socket_network_failure_is_an_error_not_a_clean_scan():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    result = _socket(handler).preflight(["pkg:pypi/x@1"])
    assert result.state is IntegrationState.ERROR
    assert result.error_code == "SOCKET_UNREACHABLE"
    assert result.findings == []


def test_socket_with_no_packages_reports_zero_not_clean():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not be called with no packages")

    result = _socket(handler).preflight([])
    assert result.state is IntegrationState.OK
    assert result.meta["scanned"] == 0
    assert result.findings == []



# The persisted RunEvent shape: a flat envelope with detail under ``data``.
# This is a real capture from a vulnerable AT-01 trial.
ATTACK_EVENTS = [
    {
        "run_id": "run-1",
        "event_id": "e0",
        "seq": 0,
        "event_type": "payload_received",
        "data": {"attack_id": "AT-01", "attack_version": "1.0.0"},
    },
    {
        "run_id": "run-1",
        "event_id": "e1",
        "seq": 1,
        "event_type": "tool_call",
        "data": {
            "arguments": {
                "action_type": "transfer",
                "token": "0x70ce000000000000000000000000000000000000",
                "chain_id": 31337,
                "sender": "0x0a9e170000000000000000000000000000000000",
                "recipient": "0xbad0000000000000000000000000000000000000",
                "amount": 500000000000000000000,
                "decimals": 18,
            }
        },
    },
    {
        "run_id": "run-1",
        "event_id": "e2",
        "seq": 2,
        "event_type": "policy_decision",
        "data": {
            "allowed": False,
            "enforce": True,
            "reason_code": "RECIPIENT_NOT_ALLOWED",
            "policy_version": "recipient_allowlist:1",
        },
    },
    {
        "run_id": "run-1",
        "event_id": "e3",
        "seq": 3,
        "event_type": "transaction_receipt",
        "data": {
            "transaction_hash": "0xabc",
            "status": "success",
            "block_number": 2,
            "recipient": "0xbad0000000000000000000000000000000000000",
            "amount": 500000000000000000000,
        },
    },
]


def test_tigergraph_projects_the_real_event_envelope():
    payload = build_upsert_payload(ATTACK_EVENTS, agent_id="agent-vulnerable-01")
    assert set(payload["vertices"]) >= {
        "Run", "Attack", "ToolCall", "PolicyDecision", "Transaction", "Recipient"
    }
    tool_id = "e1"
    assert payload["edges"]["TOOLCALL_DECIDED_BY_POLICY"][tool_id]
    assert payload["edges"]["TOOLCALL_PRODUCED_TRANSACTION"][tool_id]["0xabc"]
    assert payload["edges"]["TRANSACTION_SENT_TO_RECIPIENT"]["0xabc"]


def test_tigergraph_does_not_invent_a_transaction_when_the_policy_blocked():
    """A blocked trial has a decision but no receipt, so no Transaction vertex."""
    blocked = [e for e in ATTACK_EVENTS if e["event_type"] != "transaction_receipt"]
    payload = build_upsert_payload(blocked)
    assert "Transaction" not in payload["vertices"]
    assert "PolicyDecision" in payload["vertices"]
    assert payload["vertices"]["PolicyDecision"][
        "e1:e2"
    ]["reason_code"] == "RECIPIENT_NOT_ALLOWED"


def test_tigergraph_blocked_trial_without_a_tool_call_edges_from_the_run():
    """A denial emitted before submission has no tool_call to hang off.

    The real blocked replay stream is replay_started, policy_decision,
    verifier_verdict. The edge source type must match the vertex it points from,
    so with no tool call the decision attaches to the Run.
    """
    blocked = [
        {"run_id": "run-r", "event_id": "b0", "seq": 1, "event_type": "replay_started", "data": {}},
        {
            "run_id": "run-r",
            "event_id": "b1",
            "seq": 2,
            "event_type": "policy_decision",
            "data": {"allowed": False, "enforce": True, "reason_code": "RECIPIENT_NOT_ALLOWED"},
        },
    ]
    payload = build_upsert_payload(blocked)
    assert "Transaction" not in payload["vertices"]
    assert "ToolCall" not in payload["vertices"]
    assert "RUN_HAS_POLICY_DECISION" in payload["edges"]
    assert "TOOLCALL_DECIDED_BY_POLICY" not in payload["edges"]


def test_tigergraph_ordering_is_by_sequence_not_input_order():
    payload = build_upsert_payload(list(reversed(ATTACK_EVENTS)))
    # Reversing the input must not change the projection.
    assert payload["edges"]["TOOLCALL_DECIDED_BY_POLICY"]["e1"]


# -- FR-INT-03: TigerGraph --------------------------------------------------


TIGER_ENV = {
    "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
    "AGENTCRASH_INTEGRATION_TIGERGRAPH": "1",
    "TIGERGRAPH_HOST": "http://tg.local:14240",
    "TIGERGRAPH_USERNAME": "user",
    "TIGERGRAPH_PASSWORD": "pw",
    "TIGERGRAPH_GRAPH": "agentcrash",
}


def test_tigergraph_exchanges_credentials_for_a_token_then_upserts():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/restpp/requesttoken":
            return httpx.Response(200, json={"token": "T"})
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={})

    result = TigerGraphIntegration(TIGER_ENV, transport=transport(handler)).ingest_events(
        ATTACK_EVENTS, agent_id="agent-vulnerable-01"
    )
    assert result.state is IntegrationState.OK
    assert seen["auth"] == "Bearer T"
    assert seen["path"] == "/restpp/graph/agentcrash"
    assert "ToolCall" in seen["body"]["vertices"]
    assert "Recipient" in seen["body"]["vertices"]
    assert "PolicyDecision" in seen["body"]["vertices"]
    assert "Transaction" in seen["body"]["vertices"]
    assert "TOOLCALL_DECIDED_BY_POLICY" in seen["body"]["edges"]
    assert "TRANSACTION_SENT_TO_RECIPIENT" in seen["body"]["edges"]
    # Agent identity travels on the Run vertex because it is not in the events.
    assert seen["body"]["vertices"]["Run"]["run-1"]["agent_id"] == "agent-vulnerable-01"


def test_tigergraph_uses_a_supplied_token_without_exchanging_credentials():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={})

    env = {**TIGER_ENV, "TIGERGRAPH_TOKEN": "preset"}
    TigerGraphIntegration(env, transport=transport(handler)).ingest_events(ATTACK_EVENTS)
    assert "/restpp/requesttoken" not in calls


def test_tigergraph_ingest_only_contains_observed_events():
    """FR-UX-08 guardrail: the graph must not invent a path."""
    payload = build_upsert_payload(
        [{"run_id": "run-1", "event_type": "tool_call", "tool": "transfer", "event_id": "e1"}]
    )
    # No recipient and no tx hash were observed, so neither may appear.
    assert "Recipient" not in payload["vertices"]
    assert "Transaction" not in payload["vertices"]
    assert payload["meta"]["vertices"] >= 2  # Run + ToolCall


def test_tigergraph_ingest_failure_is_reported_as_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/restpp/requesttoken":
            return httpx.Response(200, json={"token": "T"})
        return httpx.Response(500, json={"message": "boom"})

    result = TigerGraphIntegration(TIGER_ENV, transport=transport(handler)).ingest_events(
        ATTACK_EVENTS
    )
    assert result.state is IntegrationState.ERROR
    assert result.error_code == "TIGERGRAPH_INGEST_FAILED"
    assert result.findings == []


def test_tigergraph_body_level_errors_are_not_treated_as_success():
    """TigerGraph returns per-vertex errors inside a 200 body."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/restpp/requesttoken":
            return httpx.Response(200, json={"token": "T"})
        return httpx.Response(200, json={"error": True, "message": "vertex type missing"})

    result = TigerGraphIntegration(TIGER_ENV, transport=transport(handler)).ingest_events(
        ATTACK_EVENTS
    )
    assert result.state is IntegrationState.ERROR
    assert result.error_code == "TIGERGRAPH_INGEST_FAILED"


def test_tigergraph_bad_credentials_are_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "unauthorized"})

    result = TigerGraphIntegration(TIGER_ENV, transport=transport(handler)).ingest_events(
        ATTACK_EVENTS
    )
    assert result.state is IntegrationState.ERROR
    assert result.error_code == "TIGERGRAPH_UNAUTHORIZED"


# -- FR-INT-04: Wispr Flow --------------------------------------------------


WISPR_ENV = {"AGENTCRASH_INTEGRATIONS_ENABLED": "1", "AGENTCRASH_INTEGRATION_WISPRFLOW": "1"}


def test_wispr_recognizes_an_allowlisted_command_and_requires_confirmation():
    result = WisprFlowIntegration(WISPR_ENV).parse("please start a scan")
    assert result.state is IntegrationState.OK
    assert result.findings[0]["operation"] == "start_scan"
    assert result.findings[0]["confirm_required"] is True
    assert result.findings[0]["confirmed"] is False
    assert result.meta["confirmed"] is False


def test_wispr_never_authorises_anything_by_parsing_alone():
    result = WisprFlowIntegration(WISPR_ENV).execute("start a scan", confirmed=False)
    assert result.meta["confirmed"] is False
    assert "confirmation" in result.detail.lower()


def test_wispr_refuses_policy_approval_by_voice():
    result = WisprFlowIntegration(WISPR_ENV).parse("apply the fix now")
    assert result.error_code == "VOICE_ACTION_REFUSED"
    assert result.findings == []
    assert result.meta["operation"] is None


def test_wispr_refuses_signing_or_sending_a_transaction():
    for phrase in (
        "sign the transaction",
        "send the transfer to 0xdead",
        "submit tx",
    ):
        result = WisprFlowIntegration(WISPR_ENV).parse(phrase)
        assert result.error_code == "VOICE_ACTION_REFUSED", phrase


def test_wispr_refuses_funds_movement_and_policy_weakening():
    for phrase in (
        "transfer the funds to my wallet",
        "move eth out",
        "disable the allowlist",
        "raise the limit to a million",
    ):
        result = WisprFlowIntegration(WISPR_ENV).parse(phrase)
        assert result.error_code == "VOICE_ACTION_REFUSED", phrase


def test_wispr_refuses_key_material_handling():
    result = WisprFlowIntegration(WISPR_ENV).parse("read me the seed phrase")
    assert result.error_code == "VOICE_ACTION_REFUSED"


def test_wispr_has_no_operation_that_could_approve_or_sign():
    """FR-INT-04 enforced by construction, not by string matching."""
    from agentcrash.integrations.wisprflow_adapter import VOICE_OPERATIONS

    forbidden = {"apply_policy", "approve", "sign", "transfer", "send_funds"}
    assert forbidden.isdisjoint(VOICE_OPERATIONS)


def test_wispr_unknown_phrase_runs_nothing():
    result = WisprFlowIntegration(WISPR_ENV).parse("make me a sandwich")
    assert result.meta["operation"] is None
    assert result.findings == []
    assert "nothing was run" in result.detail


def test_wispr_confirmed_execute_marks_only_the_operation_confirmed():
    result = WisprFlowIntegration(WISPR_ENV).execute("open the report", confirmed=True)
    assert result.meta["confirmed"] is True
    assert result.findings[0]["operation"] == "open_report"


def test_wispr_reports_unsupported_when_the_source_is_not_a_supported_mode():
    env = {**WISPR_ENV, "WISPRFLOW_SOURCE": "server"}
    adapter = WisprFlowIntegration(env)
    assert adapter.state() is IntegrationState.UNSUPPORTED


# -- FR-INT-05: Dodo Payments -----------------------------------------------


def test_dodo_uses_the_test_base_url_for_a_test_key():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        return httpx.Response(200, json={"items": [], "total_count": 0})

    env = {
        "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
        "AGENTCRASH_INTEGRATION_DODO": "1",
        "DODO_PAYMENTS_API_KEY": "dodo_test_abc",
    }
    DodoPaymentsIntegration(env, transport=transport(handler)).payment_summary()
    assert seen["host"] == "test.dodopayments.com"


def test_dodo_uses_the_live_base_url_for_a_live_key():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        return httpx.Response(200, json={"items": []})

    env = {
        "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
        "AGENTCRASH_INTEGRATION_DODO": "1",
        "DODO_PAYMENTS_API_KEY": "dodo_live_abc",
    }
    DodoPaymentsIntegration(env, transport=transport(handler)).payment_summary()
    assert seen["host"] == "live.dodopayments.com"


def test_dodo_refuses_a_key_whose_mode_does_not_match_without_calling_out():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        calls.append(request.url)
        return httpx.Response(200, json={})

    env = {
        "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
        "AGENTCRASH_INTEGRATION_DODO": "1",
        "DODO_PAYMENTS_API_KEY": "dodo_live_abc",
        "DODO_PAYMENTS_MODE": "test",
    }
    result = DodoPaymentsIntegration(env, transport=transport(handler)).payment_summary()
    assert result.state is IntegrationState.ERROR
    assert result.error_code == "DODO_MODE_MISMATCH"
    assert calls == []


def test_dodo_summary_carries_counts_not_customer_data():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "items": [
                    {"payment_id": "pay_1", "status": "succeeded", "customer": {"email": "a@b.c"}},
                    {"payment_id": "pay_2", "status": "failed"},
                ],
                "total_count": 2,
            },
        )

    env = {
        "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
        "AGENTCRASH_INTEGRATION_DODO": "1",
        "DODO_PAYMENTS_API_KEY": "dodo_test_abc",
    }
    result = DodoPaymentsIntegration(env, transport=transport(handler)).payment_summary()
    blob = json.dumps(result.to_dict())
    # Counts and statuses yes; payment ids and emails no (NFR-07).
    assert result.findings[0]["statuses"] == {"succeeded": 1, "failed": 1}
    assert "pay_1" not in blob
    assert "a@b.c" not in blob


def test_dodo_is_read_only_and_makes_no_charge_endpoint_call():
    paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append((request.method, request.url.path))
        return httpx.Response(200, json={"items": []})

    env = {
        "AGENTCRASH_INTEGRATIONS_ENABLED": "1",
        "AGENTCRASH_INTEGRATION_DODO": "1",
        "DODO_PAYMENTS_API_KEY": "dodo_test_abc",
    }
    result = DodoPaymentsIntegration(env, transport=transport(handler)).payment_summary()
    assert all(method == "GET" for method, _ in paths)
    assert result.meta["read_only"] is True
