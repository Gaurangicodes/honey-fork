"""Module 2 unit tests: sandbox lifecycle, verification, deltas, receipts."""

from __future__ import annotations

import pytest

from agentcrash.core.models import Verdict
from agentcrash.core.attacks import get_attack
from agentcrash.sandbox.chain import SimulatedChain, TransferFailed
from agentcrash.sandbox.manager import SandboxManager, default_demo_environment
from agentcrash.sandbox.verifier import OutcomeVerifier


# -- FR-SB-01 ---------------------------------------------------------------
def test_environment_initialises_known_balances(environment):
    env = environment
    assert env.chain.get_balance(env.agent_address, env.token_contract) == env.agent_initial_balance
    assert env.chain.get_balance(env.approved_recipient, env.token_contract) == 0
    assert env.chain.get_balance(env.unauthorized_recipient, env.token_contract) == 0
    assert env.agent_address != env.approved_recipient
    assert env.approved_recipient != env.unauthorized_recipient


# -- FR-SB-02 ---------------------------------------------------------------
def test_snapshot_captures_required_fields(manager, environment):
    snapshot = manager.capture_state(run_id="run-1", policy_version=None, attack_id="AT-01")
    assert snapshot.chain_id == environment.chain.chain_id
    assert snapshot.block_number >= 1
    assert snapshot.token_contract == environment.token_contract
    assert set(snapshot.wallet_addresses) == {
        "agent",
        "approved_recipient",
        "unauthorized_recipient",
    }
    assert snapshot.attack_id == "AT-01"
    assert snapshot.fingerprint().startswith("0x")


def test_fingerprint_stable_across_policy_versions(manager):
    """The equivalence gate compares state, not the active policy version: a
    replay legitimately runs the same state under a different policy."""
    a = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    b = manager.capture_state(run_id="r", policy_version="2", attack_id="AT-01")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_changes_when_balances_change(manager, environment):
    a = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    environment.chain.transfer(
        environment.agent_address,
        environment.approved_recipient,
        environment.token_contract,
        10**18,
    )
    b = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    assert a.fingerprint() != b.fingerprint()


# -- FR-SB-03 ---------------------------------------------------------------
def _deltas(env, manager, before):
    return manager.balance_deltas(before)


def test_verifier_detects_exploit_from_state_change(manager, environment):
    verifier = OutcomeVerifier(
        environment.unauthorized_recipient, environment.token_contract
    )
    before = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    receipt = environment.chain.transfer(
        environment.agent_address,
        environment.unauthorized_recipient,
        environment.token_contract,
        10**18,
    )
    deltas = _deltas(environment, manager, before)
    result = verifier.verify(
        attack=get_attack("AT-01"),
        before=before,
        deltas=deltas,
        receipts=[receipt],
        policy_blocked=False,
        attack_triggered=True,
    )
    assert result.verdict is Verdict.EXPLOIT_SUCCEEDED
    assert receipt.tx_hash in result.reason


def test_verifier_does_not_trust_narration(manager, environment):
    """A claimed transfer with no receipt and no state change is not an exploit."""
    verifier = OutcomeVerifier(
        environment.unauthorized_recipient, environment.token_contract
    )
    before = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    result = verifier.verify(
        attack=get_attack("AT-01"),
        before=before,
        deltas=manager.balance_deltas(before),
        receipts=[],
        policy_blocked=False,
        attack_triggered=True,
    )
    assert result.verdict is Verdict.ATTACK_NOT_TRIGGERED


def test_verifier_classifies_policy_block(manager, environment):
    verifier = OutcomeVerifier(
        environment.unauthorized_recipient, environment.token_contract
    )
    before = manager.capture_state(run_id="r", policy_version="2", attack_id="AT-01")
    result = verifier.verify(
        attack=get_attack("AT-01"),
        before=before,
        deltas=manager.balance_deltas(before),
        receipts=[],
        policy_blocked=True,
        attack_triggered=True,
    )
    assert result.verdict is Verdict.ATTEMPT_BLOCKED


def test_verifier_classifies_untriggered_attack(manager, environment):
    verifier = OutcomeVerifier(
        environment.unauthorized_recipient, environment.token_contract
    )
    before = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    result = verifier.verify(
        attack=get_attack("AT-01"),
        before=before,
        deltas=manager.balance_deltas(before),
        receipts=[],
        policy_blocked=False,
        attack_triggered=False,
    )
    assert result.verdict is Verdict.ATTACK_NOT_TRIGGERED


def test_block_without_trigger_is_not_labelled_blocked(manager, environment):
    """Guardrail B: never report a policy rejection as blocking an attack that
    never triggered."""
    verifier = OutcomeVerifier(
        environment.unauthorized_recipient, environment.token_contract
    )
    before = manager.capture_state(run_id="r", policy_version="2", attack_id="AT-01")
    result = verifier.verify(
        attack=get_attack("AT-01"),
        before=before,
        deltas=manager.balance_deltas(before),
        receipts=[],
        policy_blocked=True,
        attack_triggered=False,
    )
    assert result.verdict is Verdict.ATTACK_NOT_TRIGGERED


# -- FR-SB-04 ---------------------------------------------------------------
def test_balance_deltas_are_exact(manager, environment):
    before = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    amount = 3 * 10**18
    environment.chain.transfer(
        environment.agent_address,
        environment.approved_recipient,
        environment.token_contract,
        amount,
    )
    deltas = {d.address.lower(): d for d in manager.balance_deltas(before)}
    agent_delta = deltas[environment.agent_address.lower()]
    recipient_delta = deltas[environment.approved_recipient.lower()]
    assert agent_delta.delta == -amount
    assert recipient_delta.delta == amount
    assert agent_delta.before - agent_delta.after == amount


# -- FR-SB-05 ---------------------------------------------------------------
def test_receipt_recorded_with_hash_status_block(environment):
    receipt = environment.chain.transfer(
        environment.agent_address,
        environment.approved_recipient,
        environment.token_contract,
        10**18,
    )
    assert receipt.tx_hash.startswith("0x")
    assert receipt.status == "success"
    assert receipt.block_number >= 1
    fetched = environment.chain.get_receipt(receipt.tx_hash)
    assert fetched is not None and fetched.tx_hash == receipt.tx_hash


def test_no_transaction_is_stated_explicitly(manager, environment):
    """If no transaction was submitted, the verifier says so rather than
    implying a transfer happened."""
    verifier = OutcomeVerifier(
        environment.unauthorized_recipient, environment.token_contract
    )
    before = manager.capture_state(run_id="r", policy_version=None, attack_id="AT-01")
    result = verifier.verify(
        attack=get_attack("AT-01"),
        before=before,
        deltas=manager.balance_deltas(before),
        receipts=[],
        policy_blocked=False,
        attack_triggered=False,
    )
    assert "no wallet transaction" in result.reason.lower()
    assert result.receipt is None


# -- chain semantics --------------------------------------------------------
def test_transfer_reverts_on_insufficient_balance(environment):
    with pytest.raises(TransferFailed):
        environment.chain.transfer(
            environment.agent_address,
            environment.approved_recipient,
            environment.token_contract,
            environment.agent_initial_balance + 1,
        )


def test_reverted_transfer_leaves_balances_unchanged(environment):
    before = environment.chain.get_balance(
        environment.agent_address, environment.token_contract
    )
    with pytest.raises(TransferFailed):
        environment.chain.transfer(
            environment.agent_address,
            environment.approved_recipient,
            environment.token_contract,
            before + 1,
        )
    assert (
        environment.chain.get_balance(environment.agent_address, environment.token_contract)
        == before
    )


# -- reset ------------------------------------------------------------------
def test_reset_restores_initial_balances(environment):
    manager = SandboxManager(environment)
    environment.chain.transfer(
        environment.agent_address,
        environment.unauthorized_recipient,
        environment.token_contract,
        5 * 10**18,
    )
    manager.reset()
    assert (
        environment.chain.get_balance(environment.agent_address, environment.token_contract)
        == environment.agent_initial_balance
    )
    assert (
        environment.chain.get_balance(
            environment.unauthorized_recipient, environment.token_contract
        )
        == 0
    )


def test_reset_does_not_touch_other_chains():
    chain = SimulatedChain(chain_id=1)
    env = default_demo_environment(chain=chain)
    manager = SandboxManager(env)
    assert manager.capture_state(None, None, None).chain_id == 1
