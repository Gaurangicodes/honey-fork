import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, api } from "./api";
import { AttackGraph } from "./components/AttackGraph";
import { AttackTimeline } from "./components/AttackTimeline";
import { PolicyLab } from "./components/PolicyLab";
import { ProofReport } from "./components/ProofReport";
import { ReplayArena } from "./components/ReplayArena";
import {
  Chip,
  Copyable,
  Empty,
  ErrorNote,
  Panel,
  Spinner,
  Stat,
} from "./components/primitives";
import { VERDICT_META, formatTime, shortAddress } from "./format";
import { usePolling } from "./usePolling";
import type {
  AgentConfiguration,
  AttackDefinition,
  Comparison,
  Health,
  Policy,
  PolicyTemplate,
  ReplayResult,
  Report,
  ScanRun,
} from "./types";

export function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [agents, setAgents] = useState<AgentConfiguration[]>([]);
  const [attacks, setAttacks] = useState<AttackDefinition[]>([]);
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [fatal, setFatal] = useState<string | null>(null);

  const [agentId, setAgentId] = useState("");
  const [selectedAttacks, setSelectedAttacks] = useState<string[]>([]);
  const [repeatCount, setRepeatCount] = useState(1);

  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [activeTrials, setActiveTrials] = useState<ScanRun[]>([]);
  const [selectedTrialId, setSelectedTrialId] = useState<string | null>(null);

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policyNote, setPolicyNote] = useState<string | null>(null);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [policyError, setPolicyError] = useState<string | null>(null);

  const [replay, setReplay] = useState<ReplayResult | null>(null);
  const [receipt, setReceipt] = useState<Record<string, unknown> | null>(null);
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const loadRuns = useCallback(async () => {
    setRuns(await api.scans(50));
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [h, a, at, t] = await Promise.all([
          api.health(),
          api.agents(),
          api.attacks(),
          api.policyTemplates(),
        ]);
        setHealth(h);
        setAgents(a);
        setAttacks(at);
        setTemplates(t);
        setAgentId((current) => current || (a[0]?.agent_id ?? ""));
        setSelectedAttacks(at.map((x) => x.attack_id));
        await loadRuns();
      } catch (err) {
        setFatal(err instanceof Error ? err.message : String(err));
      }
    })();
  }, [loadRuns]);

  const scanActive = usePolling(
    () => api.trials(activeRunId as string),
    Boolean(activeRunId),
    700,
  );

  useEffect(() => {
    if (!scanActive.data) return;
    setActiveTrials(scanActive.data);
    // Auto-select the first trial of a newly opened run, but never carry a
    // selection across runs: the graph and timeline read the selected trial.
    setSelectedTrialId((current) =>
      current && scanActive.data!.some((t) => t.run_id === current)
        ? current
        : (scanActive.data![0]?.run_id ?? null),
    );
    if (scanActive.data.length >= plannedTrials) {
      void loadRuns();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanActive.data]);

  const plannedTrials = selectedAttacks.length * repeatCount;

  const events = usePolling(
    () => api.events(selectedTrialId as string),
    Boolean(selectedTrialId),
    900,
  );

  const selectedTrial = useMemo(
    () => activeTrials.find((t) => t.run_id === selectedTrialId) ?? null,
    [activeTrials, selectedTrialId],
  );

  const attackFor = useCallback(
    (attackId: string | null) => attacks.find((a) => a.attack_id === attackId) ?? null,
    [attacks],
  );

  const templateFor = useCallback(
    (type: string | null | undefined) => templates.find((t) => t.type === type) ?? null,
    [templates],
  );

  const guard = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    setNotice(null);
    try {
      await fn();
    } catch (err) {
      // FR-UI-06: surface the error as an error, with its stable code.
      const detail =
        err instanceof ApiError ? `${err.code}: ${err.message}` : String(err);
      setNotice(detail);
    } finally {
      setBusy(null);
    }
  };

  const startScan = () =>
    guard("scan", async () => {
      const accepted = await api.startScan({
        agent_id: agentId,
        attack_ids: selectedAttacks,
        repeat_count: repeatCount,
      });
      setActiveRunId(accepted.run_id);
      setActiveTrials([]);
      setSelectedTrialId(null);
      setPolicy(null);
      setPolicyNote(null);
      setReplay(null);
      setReceipt(null);
      setComparison(null);
      setReport(null);
      setNotice(`Queued ${accepted.run_id} — ${accepted.total_trials} trial(s).`);
    });

  const proposePolicy = (trialId: string) =>
    guard("propose", async () => {
      const result = await api.proposePolicy(trialId);
      setPolicy(result.policy);
      // FR-PL-06: when nothing maps to a template, say so rather than
      // substituting a generic rule.
      setPolicyNote(result.policy ? null : (result.message ?? "No automatic fix is available."));
      setPolicyError(null);
    });

  const applyPolicy = (target: Policy) =>
    guard("apply", async () => {
      setPolicyBusy(true);
      try {
        const result = await api.applyPolicy(target.policy_id);
        setPolicy(result.policy);
        // The header shows the enforced stack, so it has to be refetched or it
        // keeps reporting "no policy" after a successful apply.
        setHealth(await api.health());
        setNotice(
          `Applied ${result.policy.type} as policy v${result.policy.version}. Replay to verify.`,
        );
      } finally {
        setPolicyBusy(false);
      }
    });

  const runReplay = (trialId: string) =>
    guard("replay", async () => {
      const result = await api.replay(trialId, 3);
      setReplay(result);
      // FR-RP-03: the receipt is a separate read; a missing one must not fail
      // the replay the operator just ran.
      try {
        setReceipt((await api.receipt(result.replay_run.run_id)).receipt);
      } catch {
        setReceipt(null);
      }
      setComparison(await api.comparison(trialId, result.replay_run.run_id));
      await loadRuns();
    });

  const buildReport = (runId: string) =>
    guard("report", async () => {
      const result = await api.createReport([runId]);
      setReport(result.report);
    });

  const resetSandbox = () =>
    guard("reset", async () => {
      await api.resetSandbox();
      const h = await api.health();
      setHealth(h);
      setNotice("Sandbox restored to known initial state. Report history was kept.");
    });

  if (fatal) {
    return (
      <div className="mx-auto max-w-xl p-8">
        <Panel title="Backend unavailable">
          <ErrorNote error={fatal} />
          <p className="mt-2 text-[12px] text-muted">
            Start the API with <span className="mono">uvicorn agentcrash.api.app:app</span> and
            reload.
          </p>
        </Panel>
      </div>
    );
  }

  const exploits = activeTrials.filter((t) => t.verdict === "EXPLOIT_SUCCEEDED").length;
  const blocked = activeTrials.filter((t) => t.verdict === "ATTEMPT_BLOCKED").length;
  const errors = activeTrials.filter((t) => t.verdict === "TEST_ERROR").length;

  return (
    <div className="mx-auto max-w-[1400px] p-4">
      <Header
        health={health}
        busy={busy}
        onReset={resetSandbox}
      />

      {notice && (
        <div className="mt-3 rounded border border-edge bg-white/5 px-3 py-2 text-[12px] text-ink/85">
          {notice}
        </div>
      )}

      <div className="mt-3 grid gap-3 lg:grid-cols-[20rem_1fr]">
        <ScanControls
          agents={agents}
          attacks={attacks}
          agentId={agentId}
          setAgentId={setAgentId}
          selected={selectedAttacks}
          setSelected={setSelectedAttacks}
          repeatCount={repeatCount}
          setRepeatCount={setRepeatCount}
          onStart={startScan}
          running={busy === "scan"}
        />

        <div className="space-y-3">
          <div className="grid gap-2 sm:grid-cols-4">
            <Stat label="Attacks completed" value={activeTrials.length} hint={`of ${plannedTrials} planned`} />
            <Stat label="Exploits verified" value={exploits} tone="text-exploit" />
            <Stat label="Policy blocks" value={blocked} tone="text-signal" />
            <Stat
              label="Test errors"
              value={errors}
              tone={errors ? "text-policy" : "text-ink"}
              hint="infrastructure, not security"
            />
          </div>

          <Panel
            title="Trials"
            actions={
              activeRunId && (
                <button
                  type="button"
                  className="btn"
                  disabled={busy === "report"}
                  onClick={() => buildReport(activeRunId)}
                >
                  {busy === "report" ? "Building…" : "Generate report"}
                </button>
              )
            }
          >
            {!activeRunId ? (
              <Empty>No scan running. Choose a suite and run a security test.</Empty>
            ) : (
              <TrialsTable
                trials={activeTrials}
                planned={plannedTrials}
                selectedId={selectedTrialId}
                onSelect={setSelectedTrialId}
                attackFor={attackFor}
                onPropose={proposePolicy}
                onReplay={runReplay}
                busy={busy}
              />
            )}
          </Panel>

          <AttackGraph
            run={selectedTrial}
            attack={attackFor(selectedTrial?.attack_id ?? null)}
            events={events.data ?? []}
            onSelect={() => undefined}
            selectedId={null}
          />

          <div className="grid gap-3 xl:grid-cols-2">
            <Panel title="Live attack timeline">
              <AttackTimeline events={events.data ?? []} />
            </Panel>

            <PolicyLab
              policy={policy}
              unsupportedMessage={policyNote}
              template={templateFor(policy?.type)}
              activeVersions={health?.active_policy_versions ?? []}
              busy={policyBusy || busy === "apply"}
              error={policyError}
              onApply={applyPolicy}
              onCancel={() => {
                setPolicy(null);
                setPolicyNote(null);
                setPolicyError(null);
              }}
            />
          </div>

          <ReplayArena
            original={selectedTrial}
            comparison={comparison}
            replay={replay}
            receipt={receipt}
          />

          <ProofReport report={report} />

          <RecentRuns
            runs={runs}
            onSelect={(runId) => {
              setActiveRunId(runId);
              setSelectedTrialId(null);
              setReplay(null);
              setReceipt(null);
              setComparison(null);
              setPolicy(null);
              setPolicyNote(null);
              setReport(null);
            }}
          />
        </div>
      </div>
    </div>
  );
}

function Header({
  health,
  busy,
  onReset,
}: {
  health: Health | null;
  busy: string | null;
  onReset: () => void;
}) {
  const sandboxOk = health?.status === "ok";
  return (
    <header className="panel flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <div className="flex items-center gap-3">
        <span className="inline-block h-2.5 w-2.5 rounded-full bg-signal" />
        <div>
          <h1 className="text-sm font-semibold tracking-wide text-ink">AgentCrash Replay</h1>
          <p className="text-[11px] text-muted">
            AI-agent security regression testing · sandbox only
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Chip
          tone={
            sandboxOk
              ? "text-signal border-signal/40 bg-signal/10"
              : "text-exploit border-exploit/40 bg-exploit/10"
          }
        >
          sandbox {sandboxOk ? "healthy" : "unavailable"}
        </Chip>
        {health && (
          <>
            <Chip title="Chain identity">
              chain {health.sandbox.chain_id} · block {health.sandbox.block_number}
            </Chip>
            <Chip title="Test token contract">
              <Copyable
                value={health.sandbox.token_contract}
                display={`token ${shortAddress(health.sandbox.token_contract)}`}
              />
            </Chip>
            <Chip
              tone={
                health.active_policy_count
                  ? "text-signal border-signal/40 bg-signal/10"
                  : "text-muted border-edge bg-white/5"
              }
            >
              {health.active_policy_count
                ? `policy v${health.active_policy_versions.join(", v")}`
                : "no policy"}
            </Chip>
          </>
        )}
        <button
          type="button"
          className="btn"
          disabled={busy === "reset"}
          onClick={onReset}
          title="Restore known balances. Historical reports are kept (FR-UI-07)."
        >
          {busy === "reset" ? "Resetting…" : "Reset sandbox"}
        </button>
      </div>
    </header>
  );
}

function ScanControls({
  agents,
  attacks,
  agentId,
  setAgentId,
  selected,
  setSelected,
  repeatCount,
  setRepeatCount,
  onStart,
  running,
}: {
  agents: AgentConfiguration[];
  attacks: AttackDefinition[];
  agentId: string;
  setAgentId: (value: string) => void;
  selected: string[];
  setSelected: (value: string[]) => void;
  repeatCount: number;
  setRepeatCount: (value: number) => void;
  onStart: () => void;
  running: boolean;
}) {
  const toggle = (attackId: string) =>
    setSelected(
      selected.includes(attackId)
        ? selected.filter((x) => x !== attackId)
        : [...selected, attackId],
    );

  const agent = agents.find((a) => a.agent_id === agentId);

  return (
    <div className="space-y-3">
      <Panel title="Agent configuration">
        <select
          className="w-full rounded border border-edge bg-canvas px-2 py-1.5 text-[12px] text-ink"
          value={agentId}
          onChange={(event) => setAgentId(event.target.value)}
        >
          {agents.map((option) => (
            <option key={option.agent_id} value={option.agent_id}>
              {option.name}
            </option>
          ))}
        </select>

        {agent && (
          <div className="mt-2 space-y-1.5">
            <p className="text-[11px] text-muted">{agent.description}</p>
            <div className="flex flex-wrap gap-1">
              <Chip
                tone={
                  agent.guardrail === "none"
                    ? "text-exploit border-exploit/40 bg-exploit/10"
                    : "text-signal border-signal/40 bg-signal/10"
                }
              >
                guardrail: {agent.guardrail}
              </Chip>
              <Chip>config v{agent.configuration_version}</Chip>
            </div>
            <div>
              <div className="label mt-1">Registered tools</div>
              <div className="mono mt-0.5 space-y-0.5 text-[11px] text-ink/80">
                {agent.tool_set.map((tool) => (
                  <div key={tool}>{tool}</div>
                ))}
              </div>
            </div>
          </div>
        )}
      </Panel>

      <Panel
        title="Attack suite"
        actions={
          <button
            type="button"
            className="text-[11px] text-muted hover:text-signal"
            onClick={() =>
              setSelected(
                selected.length === attacks.length ? [] : attacks.map((a) => a.attack_id),
              )
            }
          >
            {selected.length === attacks.length ? "clear" : "all"}
          </button>
        }
      >
        <div className="space-y-1">
          {attacks.map((attack) => (
            <label
              key={attack.attack_id}
              className="flex cursor-pointer items-start gap-2 rounded border border-edge/60 px-2 py-1.5 hover:border-signal/40"
            >
              <input
                type="checkbox"
                className="mt-0.5 accent-[#B7FF4A]"
                checked={selected.includes(attack.attack_id)}
                onChange={() => toggle(attack.attack_id)}
              />
              <span className="min-w-0">
                <span className="flex items-center gap-1.5">
                  <span className="mono text-[11px] text-muted">{attack.attack_id}</span>
                  <span className="text-[12px] text-ink/90">{attack.name}</span>
                </span>
                <span className="mt-0.5 block text-[10px] text-muted">
                  {attack.category} · {attack.severity} · {attack.test_status}
                </span>
              </span>
            </label>
          ))}
        </div>

        <div className="mt-3 flex items-end gap-2">
          <label className="flex-1">
            <span className="label">Trial repeats</span>
            <input
              type="number"
              min={1}
              max={10}
              className="mt-1 w-full rounded border border-edge bg-canvas px-2 py-1.5 text-[12px] text-ink"
              value={repeatCount}
              onChange={(event) =>
                setRepeatCount(Math.max(1, Math.min(10, Number(event.target.value) || 1)))
              }
            />
          </label>
        </div>

        <button
          type="button"
          className="btn-primary mt-3 w-full"
          disabled={running || !agentId || selected.length === 0}
          onClick={onStart}
        >
          {running ? "Starting…" : "Run security test"}
        </button>
        <p className="mt-1.5 text-[10px] text-muted">
          Test accounts and test tokens only. No production keys are used.
        </p>
      </Panel>
    </div>
  );
}

function TrialsTable({
  trials,
  planned,
  selectedId,
  onSelect,
  attackFor,
  onPropose,
  onReplay,
  busy,
}: {
  trials: ScanRun[];
  planned: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
  attackFor: (id: string | null) => AttackDefinition | null;
  onPropose: (id: string) => void;
  onReplay: (id: string) => void;
  busy: string | null;
}) {
  if (!trials.length) {
    return <Spinner label={`Running… 0 of ${planned} trials complete`} />;
  }

  return (
    <div className="scroll overflow-x-auto">
      <table className="w-full text-[12px]">
        <thead>
          <tr className="border-b border-edge text-left">
            <th className="label py-1 pr-2">Attack</th>
            <th className="label py-1 pr-2">Outcome</th>
            <th className="label py-1 pr-2">Evidence</th>
            <th className="label py-1 pr-2">Policy</th>
            <th className="label py-1 pr-2"></th>
          </tr>
        </thead>
        <tbody>
          {trials.map((trial) => {
            const attack = attackFor(trial.attack_id);
            const meta = trial.verdict ? VERDICT_META[trial.verdict] : null;
            const canFix = trial.verdict === "EXPLOIT_SUCCEEDED";
            return (
              <tr
                key={trial.run_id}
                className={`cursor-pointer border-b border-edge/50 hover:bg-white/[0.03] ${
                  selectedId === trial.run_id ? "bg-white/[0.04]" : ""
                }`}
                onClick={() => onSelect(trial.run_id)}
              >
                <td className="py-1.5 pr-2">
                  <div className="mono text-[11px] text-muted">{trial.attack_id}</div>
                  <div className="text-ink/85">{attack?.name ?? "—"}</div>
                  {trial.repeat_count > 1 && (
                    <div className="text-[10px] text-muted">
                      trial {(trial.trial_index ?? 0) + 1}/{trial.repeat_count}
                    </div>
                  )}
                </td>
                <td className="py-1.5 pr-2">
                  {meta ? (
                    <Chip tone={meta.tone} title={meta.blurb}>
                      {meta.label}
                    </Chip>
                  ) : (
                    <Chip>{trial.status}</Chip>
                  )}
                </td>
                <td className="py-1.5 pr-2">
                  {trial.transaction_hashes.length ? (
                    <Copyable
                      value={trial.transaction_hashes[0]}
                      display={shortAddress(trial.transaction_hashes[0], 8, 6)}
                    />
                  ) : (
                    <span className="text-[11px] text-muted">no transaction</span>
                  )}
                </td>
                <td className="py-1.5 pr-2">
                  <span className="mono text-[11px] text-muted">
                    {trial.policy_version ? `v${trial.policy_version}` : "none"}
                  </span>
                </td>
                <td className="py-1.5 pr-2 text-right">
                  {canFix && (
                    <div className="flex justify-end gap-1">
                      <button
                        type="button"
                        className="btn"
                        disabled={busy === "propose"}
                        onClick={(event) => {
                          event.stopPropagation();
                          onPropose(trial.run_id);
                        }}
                      >
                        Propose fix
                      </button>
                      <button
                        type="button"
                        className="btn"
                        disabled={busy === "replay"}
                        onClick={(event) => {
                          event.stopPropagation();
                          onReplay(trial.run_id);
                        }}
                      >
                        Replay ×3
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function RecentRuns({
  runs,
  onSelect,
}: {
  runs: ScanRun[];
  onSelect: (id: string) => void;
}) {
  const parents = runs.filter((run) => !run.parent_run_id).slice(0, 8);
  return (
    <Panel title="Recent runs">
      {parents.length === 0 ? (
        <Empty>No runs recorded yet.</Empty>
      ) : (
        <div className="space-y-1">
          {parents.map((run) => (
            <button
              key={run.run_id}
              type="button"
              onClick={() => onSelect(run.run_id)}
              className="flex w-full items-center justify-between gap-2 rounded border border-edge/60 px-2 py-1.5 text-left hover:border-signal/40"
            >
              <span className="mono text-[11px] text-muted">{run.run_id}</span>
              <span className="text-[11px] text-ink/80">{run.agent_id}</span>
              <span className="mono text-[11px] text-muted">
                {run.repeat_count}× · {formatTime(run.started_at)}
              </span>
              <Chip>{run.status}</Chip>
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}
