import { FIX_META, VERDICT_META, formatDelta, formatPercent, shortAddress } from "../format";
import type { Comparison, RegressionResult, ReplayResult, ScanRun } from "../types";
import { Chip, Copyable, Empty, Panel } from "./primitives";

/**
 * FR-UI-05 / FR-RP-02 / FR-RE-07: the before/after view.
 *
 * Every value is read from persisted runs. The proof stamp is the backend's
 * `proof_status`, which is derived from verifier results — the UI never decides
 * that a fix worked.
 */
export function ReplayArena({
  original,
  comparison,
  replay,
  receipt,
}: {
  original: ScanRun | null;
  comparison: Comparison | null;
  replay: ReplayResult | null;
  receipt: Record<string, unknown> | null;
}) {
  if (!original) {
    return (
      <Panel title="Replay arena">
        <Empty>Select a trial with a verified exploit to replay it.</Empty>
      </Panel>
    );
  }

  const replayRun = replay?.replay_run ?? comparison?.replay ?? null;
  const regression: RegressionResult | null = replay?.regression ?? comparison?.regression ?? null;
  const proof = replay?.proof_status ?? comparison?.proof_status ?? null;
  const equivalence = comparison?.state_equivalence ?? null;

  return (
    <Panel
      title="Replay arena"
      actions={proof && <ProofBadge label={proof.label} verified={proof.verified} />}
    >
      <div className="grid gap-2 sm:grid-cols-2">
        <RunColumn title="Original run" run={original} />
        <RunColumn title="Replay run" run={replayRun} />
      </div>

      <div className="mt-3 space-y-2 border-t border-edge pt-3">
        <Row label="State equivalence">
          {equivalence ? (
            <>
              <Chip
                tone={
                  equivalence.equivalent
                    ? "text-signal border-signal/40 bg-signal/10"
                    : "text-exploit border-exploit/40 bg-exploit/10"
                }
              >
                {equivalence.equivalent ? "equivalent" : "mismatched"}
              </Chip>
              <span className="text-[11px] text-muted">{equivalence.detail}</span>
            </>
          ) : (
            <span className="text-[11px] text-muted">
              Fingerprints are compared by the backend during replay (FR-RP-06).
            </span>
          )}
        </Row>

        {regression && (
          <>
            <Row label="Fix status">
              <Chip tone={FIX_META[regression.fix_status].tone}>
                {FIX_META[regression.fix_status].label}
              </Chip>
              <span className="text-[11px] text-muted">
                {FIX_META[regression.fix_status].blurb}
              </span>
            </Row>
            <Row label="Legitimate transfer">
              <Chip
                tone={
                  regression.legitimate_task_passed
                    ? "text-signal border-signal/40 bg-signal/10"
                    : "text-exploit border-exploit/40 bg-exploit/10"
                }
              >
                {regression.legitimate_task_passed ? "passed" : "failed"}
              </Chip>
              {typeof regression.details.before_rate === "number" && (
                <span className="text-[11px] text-muted">
                  attack before {formatPercent(regression.details.before_rate as number)} → after{" "}
                  {formatPercent(regression.details.after_rate as number)}
                </span>
              )}
            </Row>
            {regression.aggregate && typeof regression.details.repeat_count === "number" && (
              <Row label="Repeats">
                <span className="mono text-[11px] text-ink/80">
                  {String(regression.details.blocked_trials)}/{String(regression.details.repeat_count)}{" "}
                  blocked ·{" "}
                  {String(regression.details.legitimate_passed_trials)}/
                  {String(regression.details.repeat_count)} legitimate passed
                </span>
              </Row>
            )}
          </>
        )}

        {!regression && (
          <Row label="Fix status">
            <span className="text-[11px] text-muted">No replay recorded for this trial yet.</span>
          </Row>
        )}
      </div>

      {receipt && (
        <details className="mt-3 border-t border-edge pt-2">
          <summary className="flex cursor-pointer items-center gap-2 text-[11px] text-muted hover:text-signal">
            Replay receipt (JSON)
            <Copyable
              value={JSON.stringify(receipt, null, 2)}
              display="copy"
              className="text-muted"
            />
          </summary>
          <pre className="mono scroll mt-2 max-h-72 overflow-auto rounded bg-canvas/70 p-2 text-[11px] text-ink/80">
            {JSON.stringify(receipt, null, 2)}
          </pre>
        </details>
      )}
    </Panel>
  );
}

function ProofBadge({ label, verified }: { label: string; verified: boolean }) {
  return (
    <span
      className={`chip ${
        verified
          ? "text-signal border-signal/60 bg-signal/15"
          : "text-muted border-edge bg-white/5"
      }`}
    >
      {verified ? "◆" : "◇"} {label}
    </span>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="label w-32 shrink-0">{label}</span>
      {children}
    </div>
  );
}

function RunColumn({ title, run }: { title: string; run: ScanRun | null }) {
  return (
    <div className="rounded border border-edge bg-white/[0.02] p-2">
      <div className="label mb-1.5">{title}</div>
      {!run ? (
        <div className="text-[12px] text-muted">Not run yet.</div>
      ) : (
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <Chip tone={run.verdict ? VERDICT_META[run.verdict].tone : "text-muted border-edge"}>
              {run.verdict ? VERDICT_META[run.verdict].label : run.status}
            </Chip>
            <span className="mono text-[10px] text-muted">{run.run_id}</span>
          </div>
          <div className="text-[11px] text-muted">
            policy{" "}
            <span className="mono text-ink/80">
              {run.policy_version ? `v${run.policy_version}` : "none"}
            </span>
          </div>
          {run.transaction_hashes.length > 0 ? (
            <div className="space-y-0.5">
              {run.transaction_hashes.map((hash) => (
                <div key={hash} className="flex items-center gap-1">
                  <span className="label">tx</span>
                  <Copyable value={hash} display={shortAddress(hash, 12, 8)} />
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[11px] text-muted">No transaction was submitted.</div>
          )}
          {run.balance_deltas.length > 0 && (
            <div className="space-y-0.5">
              {run.balance_deltas.map((delta) => (
                <div key={delta.address} className="flex items-center gap-2">
                  <span className="mono text-[10px] text-muted">
                    {shortAddress(delta.address, 8, 4)}
                  </span>
                  <span
                    className={`mono text-[11px] ${
                      delta.delta > 0 ? "text-exploit" : "text-muted"
                    }`}
                  >
                    {formatDelta(delta.delta)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
