import { formatPercent, formatTimestamp } from "../format";
import type { Rate, Report } from "../types";
import { Copyable, Empty, Panel } from "./primitives";

/**
 * FR-RE-06 / SRS 23.6: the report as displayed.
 *
 * Rates always carry their numerator and denominator, because a percentage on
 * its own hides how much evidence stands behind it (NFR-11). Limitations are
 * shown alongside the metrics rather than buried at the end.
 */
/** The metrics map is loosely typed on the wire; narrow before rendering. */
function asRate(value: unknown): Rate | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.numerator === "number" &&
    typeof candidate.denominator === "number" &&
    "value" in candidate
    ? (value as Rate)
    : undefined;
}

export function ProofReport({ report }: { report: Report | null }) {
  if (!report) {
    return (
      <Panel title="Proof report">
        <Empty>No report generated yet. Run a scan, then generate a report.</Empty>
      </Panel>
    );
  }

  const coverage = (report.sections.coverage ?? {}) as Record<string, unknown>;
  const score = report.metrics.indicative_score as unknown as
    | { available: boolean; value?: number | null; label?: string; reason?: string }
    | undefined;
  const exposure = report.metrics.estimated_exposure as unknown as
    | {
        unprotected_worst_case?: number;
        largest_observed_loss?: number;
        assumptions?: string[];
      }
    | undefined;

  return (
    <Panel
      title="Proof report"
      actions={
        <Copyable
          value={JSON.stringify(report, null, 2)}
          display="copy JSON"
          className="text-[11px] text-muted"
        />
      }
    >
      <div className="space-y-3">
        <div className="grid gap-2 sm:grid-cols-3">
          <MetricCard
            label="Attack success rate"
            rate={asRate(report.metrics.attack_success_rate)}
            tone="text-exploit"
            hint="exploits ÷ unprotected trials"
          />
          <MetricCard
            label="Defense blocking rate"
            rate={asRate(report.metrics.defense_blocking_rate)}
            tone="text-signal"
            hint="blocked ÷ protected trials"
          />
          <MetricCard
            label="Legitimate task success"
            rate={asRate(report.metrics.legitimate_task_success_rate)}
            tone="text-ink"
            hint="passed ÷ regressions run"
          />
        </div>

        <div className="grid gap-2 sm:grid-cols-3">
          <div className="rounded border border-edge bg-white/[0.02] p-2">
            <div className="label">Indicative score</div>
            {score?.available ? (
              <>
                <div className="mt-0.5 text-lg font-semibold text-signal">{score.value}</div>
                <div className="text-[11px] text-muted">{score.label}</div>
              </>
            ) : (
              <>
                <div className="mt-0.5 text-lg font-semibold text-muted">—</div>
                <div className="text-[11px] text-muted">{score?.reason ?? "Not available."}</div>
              </>
            )}
          </div>

          <div className="rounded border border-edge bg-white/[0.02] p-2">
            <div className="label">Coverage</div>
            <div className="mono mt-0.5 text-[12px] text-ink/85">
              {String(coverage.trials_valid ?? "—")} valid of {String(coverage.trials_total ?? "—")}
            </div>
            <div className="text-[11px] text-muted">
              {String(coverage.baseline_trials ?? "—")} baseline ·{" "}
              {String(coverage.protected_trials ?? "—")} protected
            </div>
          </div>

          <div className="rounded border border-edge bg-white/[0.02] p-2">
            <div className="label">Estimated exposure</div>
            <div className="mono mt-0.5 text-[12px] text-ink/85">
              {exposure?.unprotected_worst_case !== undefined
                ? `${exposure.unprotected_worst_case / 1e18} TST`
                : "—"}
            </div>
            <div className="text-[11px] text-muted">scenario, not a prediction</div>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-3">
          <Count label="Exploits verified" value={asRate(report.metrics.attack_success_rate)} pick="numerator" tone="text-exploit" />
          <Count label="Policy blocks" value={asRate(report.metrics.defense_blocking_rate)} pick="numerator" tone="text-signal" />
          <Count
            label="Test errors"
            value={
              typeof report.metrics.test_errors === "number"
                ? report.metrics.test_errors
                : undefined
            }
            tone="text-policy"
          />
        </div>

        <div className="rounded border border-edge bg-white/[0.02] p-2">
          <div className="label mb-1">Limitations</div>
          <ul className="space-y-0.5">
            {report.limitations.map((item) => (
              <li key={item} className="text-[11px] text-muted">
                • {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-edge pt-2 text-[10px] text-muted">
          <span className="mono">report {report.report_id}</span>
          <span>{formatTimestamp(report.created_at)}</span>
          <Copyable
            value={report.integrity_hash}
            display={`sha256 ${report.integrity_hash.slice(0, 14)}…`}
            className="text-muted"
          />
        </div>
      </div>
    </Panel>
  );
}

function MetricCard({
  label,
  rate,
  tone,
  hint,
}: {
  label: string;
  rate: Rate | undefined;
  tone: string;
  hint: string;
}) {
  return (
    <div className="rounded border border-edge bg-white/[0.02] p-2">
      <div className="label">{label}</div>
      <div className={`mt-0.5 text-lg font-semibold tabular-nums ${tone}`}>
        {rate ? formatPercent(rate.value) : "—"}
      </div>
      <div className="mono text-[10px] text-muted">
        {rate ? `${rate.numerator}/${rate.denominator}` : "—"} · {hint}
      </div>
    </div>
  );
}

function Count({
  label,
  value,
  pick,
  tone,
}: {
  label: string;
  value: Rate | number | undefined;
  pick?: "numerator";
  tone: string;
}) {
  const shown =
    typeof value === "number" ? value : value && pick ? value[pick] : undefined;
  return (
    <div className="rounded border border-edge bg-white/[0.02] p-2">
      <div className="label">{label}</div>
      <div className={`mt-0.5 text-base font-semibold tabular-nums ${tone}`}>
        {shown ?? "—"}
      </div>
    </div>
  );
}
