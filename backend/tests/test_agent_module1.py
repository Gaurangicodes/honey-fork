"""Module 1 unit tests: agent registration, capability restriction, attack library.

These cover FR-AG-01..03 and FR-AT-01..05. The behavioural pipeline tests live
in ``test_pipeline_e2e.py``; this file is about Module 1's own contracts.
"""

from __future__ import annotations

import pytest

from agentcrash.core.agent_registry import DEFAULT_AGENTS, AgentRegistry
from agentcrash.core.attacks import all_attacks, get_attack
from agentcrash.core.constants import UNAUTHORIZED_RECIPIENT
from agentcrash.core.errors import AgentCrashError
from agentcrash.core.models import (
    AgentConfiguration,
    ErrorCode,
    ToolCallResult,
    ToolKind,
)
from agentcrash.core.tools import (
    ORACLE_GET_PRICE,
    TOKEN_READ_METADATA,
    UNREGISTERED_TOOL,
    WALLET_TRANSFER,
    ToolRegistry,
)


# -- FR-AG-01: register an agent --------------------------------------------
def test_default_configurations_are_registered():
    registry = AgentRegistry()
    ids = {a.agent_id for a in registry.list_agents()}
    assert ids == {"agent-vulnerable-01", "agent-guarded-01"}


def test_register_new_agent_is_selectable():
    """A registered configuration appears in the registry and can be looked up."""
    registry = AgentRegistry()
    config = AgentConfiguration(
        agent_id="agent-custom-01",
        name="Custom Sandbox Agent",
        model_id="sandbox-rule-agent",
        environment_id="local-evm-demo",
        tool_set=[WALLET_TRANSFER, TOKEN_READ_METADATA],
        guardrail="policy_proxy",
    )
    registered = registry.register(config)
    assert registered.agent_id == "agent-custom-01"
    assert registry.get("agent-custom-01") is not None
    assert "agent-custom-01" in {a.agent_id for a in registry.list_agents()}


def test_registration_rejects_unregistered_tool():
    """FR-AG-03: a configuration cannot declare a tool the sandbox does not expose."""
    registry = AgentRegistry()
    config = AgentConfiguration(
        agent_id="agent-bad-01",
        name="Bad",
        model_id="m",
        environment_id="local-evm-demo",
        tool_set=[UNREGISTERED_TOOL],
    )
    with pytest.raises(AgentCrashError) as exc:
        registry.register(config)
    assert exc.value.code is ErrorCode.INVALID_REQUEST
    assert UNREGISTERED_TOOL in exc.value.message
    assert registry.get("agent-bad-01") is None


def test_registration_requires_a_tool():
    registry = AgentRegistry()
    config = AgentConfiguration(
        agent_id="agent-empty-01",
        name="Empty",
        model_id="m",
        environment_id="local-evm-demo",
        tool_set=[],
    )
    with pytest.raises(AgentCrashError):
        registry.register(config)


def test_registered_config_is_not_mutated_by_callers():
    """Lookups hand out copies, so a caller cannot change the registry by
    mutating a returned configuration."""
    registry = AgentRegistry()
    fetched = registry.get("agent-vulnerable-01")
    fetched.tool_set.append(UNREGISTERED_TOOL)
    assert UNREGISTERED_TOOL not in registry.get("agent-vulnerable-01").tool_set


# -- FR-AG-02: two documented configurations --------------------------------
def test_two_configurations_differ_in_a_documented_property():
    guardrails = {a.guardrail for a in DEFAULT_AGENTS}
    assert guardrails == {"none", "policy_proxy"}
    # The comparison is meaningful only because everything else is held equal.
    assert len({a.model_id for a in DEFAULT_AGENTS}) == 1
    assert len({tuple(a.tool_set) for a in DEFAULT_AGENTS}) == 1


def test_both_configurations_declare_a_description():
    assert all(a.description for a in DEFAULT_AGENTS)


# -- FR-AG-03: restrict capabilities ----------------------------------------
def test_registry_rejects_unregistered_tool_invocation():
    tools = ToolRegistry()
    result = tools.invoke(UNREGISTERED_TOOL, arguments={"reason": "test"})
    assert result.rejected is True
    assert result.ok is False
    assert "not registered" in result.rejection_reason


def test_only_registered_tools_are_listed():
    ids = ToolRegistry().ids()
    assert ids == {WALLET_TRANSFER, TOKEN_READ_METADATA, ORACLE_GET_PRICE}
    assert UNREGISTERED_TOOL not in ids


def test_wallet_tool_is_the_only_proxy_guarded_tool():
    tools = {t.tool_id: t for t in ToolRegistry().list_tools()}
    assert tools[WALLET_TRANSFER].kind is ToolKind.WALLET
    assert tools[WALLET_TRANSFER].requires_policy_proxy is True
    assert tools[TOKEN_READ_METADATA].requires_policy_proxy is False
    assert tools[ORACLE_GET_PRICE].requires_policy_proxy is False


def test_agent_refuses_tool_outside_its_own_tool_set():
    """A tool can be registered globally yet still be unavailable to a given
    configuration; the refusal is recorded, not raised."""
    registry = AgentRegistry()
    config = AgentConfiguration(
        agent_id="agent-readonly-01",
        name="Read only",
        model_id="m",
        environment_id="local-evm-demo",
        tool_set=[TOKEN_READ_METADATA],
    )
    registry.register(config)

    from agentcrash.core.agents import SandboxAgent

    agent = SandboxAgent(config, registry.tools)
    # AT-02 drives oracle.get_price, which this configuration does not expose.
    results = agent.gather_observations(get_attack("AT-02"))
    assert len(results) == 1
    assert results[0].rejected is True
    assert results[0].ok is False
    assert ORACLE_GET_PRICE in results[0].rejection_reason
    assert results[0].output is None


# -- FR-AT-01: versioned attack library -------------------------------------
def test_attack_library_entries_are_complete_and_versioned():
    attacks = all_attacks()
    assert len(attacks) == 4
    for attack in attacks:
        assert attack.attack_id
        assert attack.version
        assert attack.name
        assert attack.category
        assert attack.input_payload
        assert attack.success_condition
        assert attack.source_reference
        assert attack.expected_legitimate_behavior
        assert attack.expected_unsafe_behavior
        assert attack.severity in {"low", "medium", "high", "critical"}


def test_attack_lookup_by_id_and_version():
    assert get_attack("AT-01").name == "Poisoned token metadata"
    assert get_attack("AT-01", "1.0.0") is not None
    assert get_attack("AT-01", "9.9.9") is None
    assert get_attack("AT-99") is None


def test_attacks_are_returned_as_copies():
    first = all_attacks()
    first[0].name = "mutated"
    assert all_attacks()[0].name == "Poisoned token metadata"


# -- FR-AT-02: four MVP scenarios -------------------------------------------
def test_four_mvp_scenarios_present():
    assert {a.attack_id for a in all_attacks()} == {"AT-01", "AT-02", "AT-03", "AT-04"}


def test_attack_payloads_embed_the_unauthorized_recipient():
    """Payloads, sandbox accounts and policy templates must not drift apart."""
    for attack in all_attacks():
        assert UNAUTHORIZED_RECIPIENT in attack.input_payload


def test_scenarios_declare_a_supported_policy_type_or_none():
    from agentcrash.core.models import PolicyType

    supported = {a.supported_policy_type for a in all_attacks()}
    assert supported <= {
        PolicyType.RECIPIENT_ALLOWLIST,
        PolicyType.MAX_AMOUNT,
        None,
    }
    assert PolicyType.RECIPIENT_ALLOWLIST in supported
    assert PolicyType.MAX_AMOUNT in supported


# -- FR-AT-05: controlled mock tools, no real malicious code ----------------
def test_tool_channel_attacks_declare_their_tools_and_outputs():
    at01 = get_attack("AT-01")
    at02 = get_attack("AT-02")
    assert at01.tools_used == [TOKEN_READ_METADATA]
    assert at02.tools_used == [ORACLE_GET_PRICE]
    # The injection travels inside the tool's own response.
    assert UNAUTHORIZED_RECIPIENT in at02.tool_outputs[ORACLE_GET_PRICE]["note"]


def test_mock_tool_returns_the_injected_payload():
    tools = ToolRegistry()
    attack = get_attack("AT-02")
    result = tools.invoke(ORACLE_GET_PRICE, outputs=attack.tool_outputs)
    assert result.ok is True
    assert UNAUTHORIZED_RECIPIENT in result.output["note"]


def test_mock_tool_default_output_is_benign():
    """Without an injected payload the mock returns a normal observation, so the
    injection is attributable to the attack definition, not the tool."""
    result = ToolRegistry().invoke(ORACLE_GET_PRICE)
    assert result.ok is True
    assert UNAUTHORIZED_RECIPIENT not in str(result.output)


def test_memory_and_urgency_attacks_use_no_tool_channel():
    assert get_attack("AT-03").tools_used == []
    assert get_attack("AT-04").tools_used == []


# -- FR-AT-03: record tool calls --------------------------------------------
def test_observations_are_structured_tool_call_results():
    from agentcrash.core.agents import SandboxAgent

    registry = AgentRegistry()
    agent = SandboxAgent(registry.get("agent-vulnerable-01"), registry.tools)
    observations = agent.gather_observations(get_attack("AT-02"))
    assert len(observations) == 1
    assert isinstance(observations[0], ToolCallResult)
    assert observations[0].tool_id == ORACLE_GET_PRICE
    assert observations[0].ok is True


def test_tool_output_is_treated_as_untrusted_input():
    """An address that appears only in a tool response still drives the
    vulnerable agent's proposal; that is what makes AT-02 a real test."""
    from agentcrash.core.agents import SandboxAgent

    registry = AgentRegistry()
    config = registry.get("agent-vulnerable-01")
    agent = SandboxAgent(config, registry.tools)
    attack = get_attack("AT-02")
    observations = agent.gather_observations(attack)

    action = agent.propose_action(
        attack,
        sender="0x" + "1" * 40,
        token="0x" + "2" * 40,
        chain_id=31337,
        unauthorized_recipient=UNAUTHORIZED_RECIPIENT,
        observations=observations,
    )
    assert action is not None
    assert action.recipient.lower() == UNAUTHORIZED_RECIPIENT.lower()
    assert action.amount == 750 * 10**18
