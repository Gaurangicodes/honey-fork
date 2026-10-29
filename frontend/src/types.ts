// Response shapes mirror backend/agentcrash/core/models.py. Field names are the
// serialised ones the API actually returns, so a drift shows up as a type error
// rather than as `undefined` in the UI.

export type Verdict =
  | "EXPLOIT_SUCCEEDED"
  | "ATTEMPT_BLOCKED"
  | "ATTACK_NOT_TRIGGERED"
  | "TEST_ERROR";

export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type RunType = "attack" | "replay" | "regression";
export type PolicyType = "recipient_allowlist" | "max_transaction_amount";
export type FixStatus =
  | "VERIFIED"
  | "BLOCKED_BUT_REGRESSION"
  | "NOT_REPRODUCED"
  | "TEST_ERROR"
  | "INCOMPLETE";

export interface SandboxHealth {
  environment_id: string;
  adapter: string;
  chain_id: number;
  block_number: number;
  token_contract: string;
}

export interface Health {
  status: string;
  sandbox: SandboxHealth;
  active_policy_version: string | null;
  active_policy_versions: string[];
  active_policy_count: number;
}

export interface AgentConfiguration {
  agent_id: string;
  name: string;
  model_id: string;
  configuration_version: string;
  tool_set: string[];
  policy_version: string | null;
  environment_id: string;
  guardrail: string;
  description: string;
  system_instructions: string;
  registered_at: string;
}

export interface AttackDefinition {
  attack_id: string;
  version: string;
  name: string;
  category: string;
  description: string;
  input_payload: string;
  target_capability: string;
  tools_used: string[];
  expected_legitimate_behavior: string;
  expected_unsafe_behavior: string;
  success_condition: string;
  source_reference: string;
  severity: string;
  supported_policy_type: PolicyType | null;
  test_status: string;
}

export interface ToolCall {
  tool: string;
  arguments: Record<string, unknown>;
  ok?: boolean;
  rejected?: boolean;
  rejection_reason?: string;
}

export interface BalanceDelta {
  address: string;
  token: string;
  before: number;
  after: number;
  delta: number;
}

export interface ScanRun {
  run_id: string;
  agent_id: string;
  attack_id: string | null;
  parent_run_id: string | null;
  run_type: RunType;
  trial_index: number | null;
  repeat_count: number;
  status: RunStatus;
  verdict: Verdict | null;
  verdict_reason: string;
  policy_version: string | null;
  agent_config_version: string | null;
  attack_version: string | null;
  environment_id: string;
  environment_snapshot_id: string | null;
  started_at: string;
  finished_at: string | null;
  tool_calls: ToolCall[];
  transaction_hashes: string[];
  balance_deltas: BalanceDelta[];
  error_code: string | null;
  error_message: string | null;
}

export interface RunEvent {
  event_id: string;
  run_id: string;
  seq: number;
  timestamp: string;
  event_type: string;
  message: string;
  data: Record<string, unknown> | null;
}

export interface Rate {
  name: string;
  numerator: number;
  denominator: number;
  value: number | null;
  note: string;
}

export interface PolicyDiffEntry {
  parameter: string;
  before: unknown;
  after: unknown;
  note?: string;
}

export interface Policy {
  policy_id: string;
  /** Versions are strings on the wire ("1", "2"), not numbers. */
  version: string;
  type: PolicyType;
  parameters: Record<string, unknown>;
  source_run_id: string | null;
  source_attack_id: string | null;
  status: string;
  rationale: string;
  expected_effect: string;
  legitimate_task_impact: string;
  /** FR-PL-07: structured before/after parameter changes. */
  diff: PolicyDiffEntry[];
  created_at: string;
}

export interface PolicyTemplate {
  type: PolicyType;
  label: string;
  summary: string;
  parameters: string[];
  blocks: string;
  legitimate_impact: string;
}

export interface RegressionResult {
  regression_id: string;
  original_run_id: string;
  replay_run_id: string | null;
  policy_version: string | null;
  attack_blocked: boolean;
  legitimate_task_passed: boolean;
  verification_status: string;
  fix_status: FixStatus;
  aggregate: boolean;
  details: Record<string, unknown>;
}

export interface ProofStatus {
  state: string;
  label: string;
  verified: boolean;
  detail: string;
}

export interface ReplayResult {
  replay_run: ScanRun;
  regression: RegressionResult;
  proof_status: ProofStatus;
  active_stack: Policy[];
}

export interface Comparison {
  original: ScanRun;
  replay: ScanRun;
  state_equivalence: { equivalent: boolean; detail: string };
  proof_status: ProofStatus;
  regression: RegressionResult | null;
}

export interface Report {
  report_id: string;
  run_ids: string[];
  created_at: string;
  metrics: Record<string, Rate | Record<string, unknown>>;
  sections: Record<string, unknown>;
  limitations: string[];
  integrity_hash: string;
}

export interface ScanAccepted {
  run_id: string;
  status: RunStatus;
  agent_id: string;
  queued: boolean;
  total_trials: number;
  completed_trials: number;
  trial_run_ids: string[];
}
