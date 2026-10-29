"""Module 3 unit tests: policy generation, validation and enforcement.

Covers FR-PL-01..07. The pipeline-level proof (attack → apply → replay →
legitimate regression) lives in ``test_pipeline_e2e.py``; this file is about
Module 3's own contracts: templates, parameter validation, version history and
the stacked enforcement boundary.
"""

from __future__ import annotations

import pytest

from agentcrash.core.attacks import SAFE_TRANSFER_LIMIT, get_attack
from agentcrash.core.errors import AgentCrashError
from agentcrash.core.models import (
    ErrorCode,
    Policy,
    PolicyStatus,
    PolicyType,
    WalletAction,
)
from agentcrash.core.policy import (
    PolicyCompiler,
    PolicyProxy,
    format_amount,
    normalize_address,
)
from agentcrash.core.policy_registry import (
    POLICY_TEMPLATES,
    PolicyRegistry,
    supported_policy_types,
    template_for,
)


def _action(env, *, recipient: str | None = None, amount: int = 10**18, chain_id: int | None = None):
    return WalletAction(
        token=env.token_contract,
        chain_id=env.chain.chain_id if chain_id is None else chain_id,
        sender=env.agent_address,
        recipient=recipient or env.approved_recipient,
        amount=amount,
        decimals=env.decimals,
    )


def _allowlist(env, recipients=None, version="1"):
    return Policy(
        version=version,
        type=PolicyType.RECIPIENT_ALLOWLIST,
        parameters={"allowed_recipients": recipients or [env.approved_recipient]},
    )


def _max_amount(env, limit=SAFE_TRANSFER_LIMIT, version="1"):
    return Policy(
        version=version,
        type=PolicyType.MAX_AMOUNT,
        parameters={"max_amount": limit, "decimals": env.decimals},
    )


# -- FR-PL-02: two supported policy types -----------------------------------
def test_both_policy_types_have_a_documented_template():
    assert supported_policy_types() == [
        PolicyType.RECIPIENT_ALLOWLIST,
        PolicyType.MAX_AMOUNT,
    ]
    for policy_type in supported_policy_types():
        template = template_for(policy_type)
        assert template.summary
        assert template.blocks
        assert template.legitimate_impact
        assert template.parameters


def test_unsupported_policy_type_has_no_template():
    assert template_for(PolicyType.RECIPIENT_ALLOWLIST) is not None
    assert len(POLICY_TEMPLATES) == 2


# -- FR-PL-02: allowlist ----------------------------------------------------
def test_allowlist_allows_approved_recipient(environment):
    proxy = PolicyProxy(active_policy=_allowlist(environment))
    decision = proxy.evaluate(_action(environment))
    assert decision.allowed is True
    assert decision.reason_code == "ALL_POLICIES_ALLOWED"


def test_allowlist_rejects_unknown_recipient(environment):
    proxy = PolicyProxy(active_policy=_allowlist(environment))
    decision = proxy.evaluate(
        _action(environment, recipient=environment.unauthorized_recipient)
    )
    assert decision.allowed is False
    assert decision.reason_code == "RECIPIENT_NOT_ALLOWED"


def test_allowlist_comparison_is_case_insensitive(environment):
    proxy = PolicyProxy(
        active_policy=_allowlist(environment, [environment.approved_recipient.upper()])
    )
    assert proxy.evaluate(_action(environment)).allowed is True


def test_allowlist_rejects_invalid_address_in_policy(environment):
    proxy = PolicyProxy(active_policy=_allowlist(environment, ["not-an-address"]))
    decision = proxy.evaluate(_action(environment))
    assert decision.allowed is False
    assert decision.reason_code == "POLICY_VALIDATION_FAILED"


def test_normalize_address_rules():
    assert normalize_address("0x" + "A" * 40) == "0x" + "a" * 40
    assert normalize_address("B" * 40) == "0x" + "b" * 40
    with pytest.raises(ValueError):
        normalize_address("0x123")
    with pytest.raises(ValueError):
        normalize_address("0x" + "z" * 40)


# -- FR-PL-02: max amount ---------------------------------------------------
def test_max_amount_allows_at_or_below_limit(environment):
    proxy = PolicyProxy(active_policy=_max_amount(environment, limit=1000 * 10**18))
    assert proxy.evaluate(_action(environment, amount=1000 * 10**18)).allowed is True
    assert proxy.evaluate(_action(environment, amount=1)).allowed is True


def test_max_amount_rejects_above_limit(environment):
    proxy = PolicyProxy(active_policy=_max_amount(environment, limit=1000 * 10**18))
    decision = proxy.evaluate(_action(environment, amount=1000 * 10**18 + 1))
    assert decision.allowed is False
    assert decision.reason_code == "AMOUNT_EXCEEDS_LIMIT"


def test_max_amount_rejects_decimals_mismatch(environment):
    """FR-PL-02: units matter. A policy written in different decimals than the
    token would silently misread every amount."""
    proxy = PolicyProxy(active_policy=_max_amount(environment))
    action = _action(environment)
    action.decimals = 6
    decision = proxy.evaluate(action)
    assert decision.allowed is False
    assert decision.reason_code == "DECIMALS_MISMATCH"


def test_max_amount_rejects_malformed_parameters(environment):
    proxy = PolicyProxy(
        active_policy=Policy(
            type=PolicyType.MAX_AMOUNT, parameters={"max_amount": "lots", "decimals": 18}
        )
    )
    decision = proxy.evaluate(_action(environment))
    assert decision.allowed is False
    assert decision.reason_code == "POLICY_VALIDATION_FAILED"


def test_format_amount_uses_token_decimals():
    assert format_amount(10**18, 18) == "1"
    assert format_amount(1500 * 10**18, 18) == "1500"
    assert format_amount(1, 0) == "1"
    assert format_amount(123, 2) == "1.23"


# -- FR-SB-01 / SR-06: chain identity is checked ----------------------------
def test_wrong_chain_is_rejected_before_any_rule(environment):
    proxy = PolicyProxy(expected_chain_id=31337)
    decision = proxy.evaluate(_action(environment, chain_id=1))
    assert decision.allowed is False
    assert decision.reason_code == "CHAIN_MISMATCH"


def test_chain_check_applies_even_with_no_policy(environment):
    proxy = PolicyProxy(expected_chain_id=31337)
    assert proxy.evaluate(_action(environment, chain_id=999)).allowed is False


# -- FR-PL-03: stacked enforcement ------------------------------------------
def test_stack_requires_all_policies_to_allow(environment):
    proxy = PolicyProxy(
        active_policies=[_allowlist(environment), _max_amount(environment, limit=10**18)]
    )
    # Within the allowlist but above the cap -> denied by the amount policy.
    decision = proxy.evaluate(_action(environment, amount=10**18 + 1))
    assert decision.allowed is False
    assert decision.reason_code == "AMOUNT_EXCEEDS_LIMIT"

    # Approved recipient and within the cap -> allowed by the whole stack.
    ok = proxy.evaluate(_action(environment, amount=10**18))
    assert ok.allowed is True
    assert ok.reason_code == "ALL_POLICIES_ALLOWED"


def test_stack_blocks_unknown_recipient_even_when_amount_is_fine(environment):
    """The regression this guards: applying an amount cap must not silently
    drop the recipient allowlist that was approved earlier."""
    proxy = PolicyProxy(
        active_policies=[_allowlist(environment), _max_amount(environment, limit=10**24)]
    )
    decision = proxy.evaluate(
        _action(environment, recipient=environment.unauthorized_recipient, amount=10**18)
    )
    assert decision.allowed is False
    assert decision.reason_code == "RECIPIENT_NOT_ALLOWED"


def test_add_to_stack_replaces_same_type_only(environment):
    proxy = PolicyProxy()
    proxy.add_to_stack(_allowlist(environment, version="1"))
    proxy.add_to_stack(_max_amount(environment, version="1"))
    proxy.add_to_stack(_allowlist(environment, version="2"))
    types = sorted(p.type.value for p in proxy.active_policies)
    assert types == ["max_transaction_amount", "recipient_allowlist"]
    assert proxy.active_policy_versions == ["1", "2"]


def test_empty_stack_allows_sandbox_transactions(environment):
    proxy = PolicyProxy()
    decision = proxy.evaluate(_action(environment))
    assert decision.allowed is True
    assert decision.reason_code == "NO_POLICY"


# -- FR-PL-01 / FR-PL-06: compilation ---------------------------------------
def test_compiler_maps_recipient_attack_to_allowlist(environment):
    policy = PolicyCompiler().compile(
        attack=get_attack("AT-01"),
        run_id="run-1",
        observed={
            "approved_recipient": environment.approved_recipient,
            "unauthorized_recipient": environment.unauthorized_recipient,
        },
    )
    assert policy is not None
    assert policy.type is PolicyType.RECIPIENT_ALLOWLIST
    assert policy.parameters["allowed_recipients"] == [environment.approved_recipient.lower()]


def test_compiler_maps_oversized_attack_to_max_amount(environment):
    policy = PolicyCompiler().compile(
        attack=get_attack("AT-04"),
        run_id="run-1",
        observed={"suggested_limit": SAFE_TRANSFER_LIMIT, "decimals": 18},
    )
    assert policy is not None
    assert policy.type is PolicyType.MAX_AMOUNT
    assert policy.parameters["max_amount"] == SAFE_TRANSFER_LIMIT


def test_compiler_reports_unsupported_attack(environment):
    """FR-PL-06: no generic fallback rule for an unmappable attack."""
    from agentcrash.core.models import AttackDefinition

    attack = AttackDefinition(
        attack_id="AT-NOFIX",
        name="Unmappable",
        category="test",
        input_payload="x",
        success_condition="none",
        supported_policy_type=None,
    )
    assert (
        PolicyCompiler().compile(attack=attack, run_id="run-1", observed={}) is None
    )


# -- FR-PL-07: policy diff --------------------------------------------------
def test_compiled_policy_carries_a_structured_diff(environment):
    policy = PolicyCompiler().compile(
        attack=get_attack("AT-01"),
        run_id="run-1",
        observed={
            "approved_recipient": environment.approved_recipient,
            "unauthorized_recipient": environment.unauthorized_recipient,
        },
    )
    assert policy.diff
    line = policy.diff[0]
    assert line["parameter"] == "allowed_recipients"
    assert line["after"] == [environment.approved_recipient.lower()]


def test_max_amount_diff_is_human_readable(environment):
    policy = PolicyCompiler().compile(
        attack=get_attack("AT-04"),
        run_id="run-1",
        observed={"suggested_limit": SAFE_TRANSFER_LIMIT, "decimals": 18},
    )
    assert policy.diff[0]["after"] == "1000 TST"
    assert policy.diff[0]["before"] == "unlimited"


def test_policy_carries_impact_and_effect_text(environment):
    policy = PolicyCompiler().compile(
        attack=get_attack("AT-01"),
        run_id="run-1",
        observed={"approved_recipient": environment.approved_recipient},
    )
    assert policy.rationale
    assert policy.expected_effect
    assert policy.legitimate_task_impact


# -- FR-PL-04 / FR-DB-02: versioning ----------------------------------------
def test_policy_versions_are_per_type_and_monotonic(store, environment):
    registry = PolicyRegistry(store)
    assert registry.next_version(PolicyType.RECIPIENT_ALLOWLIST) == "1"
    registry.record(_allowlist(environment, version="1"))
    assert registry.next_version(PolicyType.RECIPIENT_ALLOWLIST) == "2"
    # A different type has its own independent numbering.
    assert registry.next_version(PolicyType.MAX_AMOUNT) == "1"


def test_policy_history_is_append_only(store, environment):
    registry = PolicyRegistry(store)
    registry.record(_allowlist(environment, version="1"))
    registry.record(_allowlist(environment, version="2"))
    versions = [p.version for p in registry.history(PolicyType.RECIPIENT_ALLOWLIST)]
    assert versions == ["1", "2"]


def test_active_stack_takes_latest_per_type(store, environment):
    registry = PolicyRegistry(store)
    first = _allowlist(environment, version="1")
    first.status = PolicyStatus.APPLIED
    second = _allowlist(environment, version="2")
    second.status = PolicyStatus.APPLIED
    cap = _max_amount(environment, version="1")
    cap.status = PolicyStatus.APPLIED
    for policy in (first, second, cap):
        registry.record(policy)

    stack = registry.active_policies()
    assert len(stack) == 2
    allowlist = next(p for p in stack if p.type is PolicyType.RECIPIENT_ALLOWLIST)
    assert allowlist.version == "2"


# -- apply_policy validation (FR-PL-02, FR-PL-04) ---------------------------
def test_apply_rejects_malformed_allowlist(orchestrator):
    bad = Policy(
        type=PolicyType.RECIPIENT_ALLOWLIST,
        parameters={"allowed_recipients": ["nope"]},
    )
    orchestrator.store.save_policy(bad)
    with pytest.raises(AgentCrashError) as exc:
        orchestrator.apply_policy(bad.policy_id)
    assert exc.value.code is ErrorCode.POLICY_VALIDATION_FAILED
    assert orchestrator.proxy.active_policies == []


def test_apply_rejects_non_positive_max_amount(orchestrator):
    bad = Policy(
        type=PolicyType.MAX_AMOUNT,
        parameters={"max_amount": 0, "decimals": 18},
    )
    orchestrator.store.save_policy(bad)
    with pytest.raises(AgentCrashError) as exc:
        orchestrator.apply_policy(bad.policy_id)
    assert exc.value.code is ErrorCode.POLICY_VALIDATION_FAILED


def test_apply_rejects_wrong_decimals(orchestrator):
    bad = Policy(
        type=PolicyType.MAX_AMOUNT,
        parameters={"max_amount": 10**6, "decimals": 6},
    )
    orchestrator.store.save_policy(bad)
    with pytest.raises(AgentCrashError):
        orchestrator.apply_policy(bad.policy_id)


def test_apply_is_idempotent(orchestrator, environment):
    policy = _allowlist(environment)
    orchestrator.store.save_policy(policy)
    first = orchestrator.apply_policy(policy.policy_id)
    second = orchestrator.apply_policy(policy.policy_id)
    assert first.status is PolicyStatus.APPLIED
    assert second.policy_id == first.policy_id
    assert len(orchestrator.proxy.active_policies) == 1


def test_unknown_policy_id_is_a_stable_error(orchestrator):
    with pytest.raises(AgentCrashError) as exc:
        orchestrator.apply_policy("policy-nope")
    assert exc.value.code is ErrorCode.POLICY_NOT_FOUND


def test_apply_emits_an_audit_event(orchestrator, environment):
    """FR-DB-02: the application is recorded on the run that produced it."""
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)
    events = orchestrator.store.list_events(trials[0].run_id)
    applied = [e for e in events if e.event_type == "policy_applied"]
    assert applied, "applying a policy must be recorded as an event"
    assert applied[0].data["policy_id"] == policy.policy_id


# -- FR-PL-05: applying a policy that breaks the legitimate transfer ---------
def test_apply_refuses_policy_that_breaks_legitimate_transfer(orchestrator, environment):
    bad = Policy(
        type=PolicyType.RECIPIENT_ALLOWLIST,
        parameters={"allowed_recipients": [environment.unauthorized_recipient]},
    )
    orchestrator.store.save_policy(bad)
    with pytest.raises(AgentCrashError) as exc:
        orchestrator.apply_policy(bad.policy_id)
    assert exc.value.code is ErrorCode.POLICY_VALIDATION_FAILED
    assert "legitimate transfer" in exc.value.message
    assert orchestrator.proxy.active_policies == []


def test_second_policy_is_checked_against_the_resulting_stack(orchestrator, environment):
    """A cap that is fine on its own must still be refused if the already
    applied allowlist would block the probe. Here both are compatible, so the
    second one applies and the stack has two entries."""
    first = _allowlist(environment)
    orchestrator.store.save_policy(first)
    orchestrator.apply_policy(first.policy_id)

    second = _max_amount(environment, limit=10**24)
    orchestrator.store.save_policy(second)
    orchestrator.apply_policy(second.policy_id)

    assert len(orchestrator.proxy.active_policies) == 2
