import { useState } from "react";

import { Chip, Empty, ErrorNote, Panel, Spinner } from "./primitives";
import type { AdapterResult, IntegrationState, IntegrationStatus } from "../types";

/**
 * Optional ecosystem adapters (SRS 20.6, FR-INT-01..05).
 *
 * The panel's job is honesty, not polish. An adapter that is off must read as
 * "not run", never as a clean result, so every state maps to an explicit label
 * and tone. Nothing here fabricates a finding: the only data shown is what the
 * adapter returned, and `ran` is what decides whether that data exists.
 */

const STATE_LABEL: Record<IntegrationState, string> = {
  disabled: "off",
  not_configured: "needs config",
  ok: "ready",
  error: "error",
  unsupported: "no API",
};

const STATE_TONE: Record<IntegrationState, string> = {
  disabled: "text-muted border-edge bg-white/5",
  not_configured: "text-policy border-policy/40 bg-policy/10",
  ok: "text-signal border-signal/40 bg-signal/10",
  error: "text-danger border-danger/40 bg-danger/10",
  unsupported: "text-analysis border-analysis/40 bg-analysis/10",
};

function stateLabel(state: IntegrationState): string {
  return STATE_LABEL[state] ?? state;
}

function tone(state: IntegrationState): string {
  return STATE_TONE[state] ?? "text-muted border-edge bg-white/5";
}

export function IntegrationPanel({
  summary,
  loading,
  error,
  onRun,
  busyAdapter,
  result,
  activeRunId,
}: {
  summary: { integrations: IntegrationStatus[]; note: string } | null;
  loading: boolean;
  error: string | null;
  onRun: (adapter: string, arg?: string) => void;
  busyAdapter: string | null;
  result: AdapterResult | null;
  activeRunId: string | null;
}) {
  return (
    <Panel
      title="Optional integrations"
      actions={
        summary && (
          <span className="text-[11px] text-muted">
            {summary.integrations.filter((i) => i.enabled).length} of{" "}
            {summary.integrations.length} enabled
          </span>
        )
      }
    >
      <p className="mb-3 text-[11px] leading-relaxed text-muted">
        {summary?.note ??
          "Optional adapters. The core attack → policy → replay proof runs with every adapter disabled."}
      </p>

      {loading && !summary && <Spinner label="Reading adapter status…" />}
      <ErrorNote error={error} />

      {summary && (
        <ul className="space-y-2">
          {summary.integrations.map((item) => (
            <IntegrationRow
              key={item.adapter}
              item={item}
              onRun={onRun}
              busy={busyAdapter === item.adapter}
              canRun={canRun(item, activeRunId)}
              runLabel={runLabel(item)}
            />
          ))}
        </ul>
      )}

      {result && <ResultBlock result={result} />}
    </Panel>
  );
}

function canRun(item: IntegrationStatus, activeRunId: string | null): boolean {
  // TigerGraph ingests a run, so it needs one selected. Others are standalone.
  if (item.adapter === "tigergraph") return Boolean(activeRunId);
  return true;
}

function runLabel(item: IntegrationStatus): string {
  switch (item.adapter) {
    case "socket":
      return "Run preflight";
    case "tigergraph":
      return "Ingest run";
    case "dodo":
      return "Read summary";
    case "wisprflow":
      return "Recognise";
    default:
      return "Run";
  }
}

function IntegrationRow({
  item,
  onRun,
  busy,
  canRun,
  runLabel: label,
}: {
  item: IntegrationStatus;
  onRun: (adapter: string, arg?: string) => void;
  busy: boolean;
  canRun: boolean;
  runLabel: string;
}) {
  const [open, setOpen] = useState(false);
  // Wispr Flow has no API to call; the recognised text comes from dictation, so
  // it needs a transcript field rather than a fire-and-forget button.
  const [transcript, setTranscript] = useState("");
  const isVoice = item.adapter === "wisprflow";
  return (
    <li className="rounded border border-edge bg-black/20 px-3 py-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="text-[13px] font-medium text-ink">{item.adapter}</span>
          <Chip tone={tone(item.state)}>{stateLabel(item.state)}</Chip>
          <Chip tone="text-muted border-edge bg-white/5" title="SRS section 25 priority">
            {item.priority}
          </Chip>
        </div>
        <div className="flex items-center gap-2">
          {isVoice && (
            <input
              className="input w-56"
              placeholder="Dictated command…"
              value={transcript}
              onChange={(e) => setTranscript(e.target.value)}
              aria-label="Voice command transcript"
            />
          )}
          <button
            type="button"
            className="btn"
            disabled={!item.enabled || !canRun || busy || (isVoice && !transcript.trim())}
            title={
              !item.enabled
                ? `Set ${item.flag}=1 to enable`
                : !canRun
                  ? "Select a run first"
                  : isVoice && !transcript.trim()
                    ? "Enter or dictate a command first"
                    : undefined
            }
            onClick={() => onRun(item.adapter, transcript)}
          >
            {busy ? "Running…" : label}
          </button>
          <button type="button" className="btn" onClick={() => setOpen((v) => !v)}>
            {open ? "Hide" : "Setup"}
          </button>
        </div>
      </div>

      <p className="mt-1 text-[11px] text-muted">{item.detail}</p>

      {isVoice && (
        <p className="mt-1 text-[11px] text-muted">
          Voice composes a command only. It cannot approve a policy or authorise a
          transfer, and every recognised command needs confirmation.
        </p>
      )}

      {open && (
        <div className="mt-2 space-y-2 border-t border-edge pt-2">
          <div className="text-[11px] text-muted">
            <span className="text-ink">Role:</span> {item.role}
          </div>
          <div className="text-[11px] text-muted">
            <span className="text-ink">Acceptance:</span> {item.acceptance}
          </div>
          {item.missing_config.length > 0 && (
            <div className="text-[11px] text-policy">
              Missing: {item.missing_config.join(", ")}
            </div>
          )}
          <ol className="list-decimal space-y-1 pl-4 text-[11px] text-muted">
            {item.setup.map((step, i) => (
              <li key={i}>
                {step.description}
                {step.env_var && (
                  <code className="mono ml-1 text-analysis">{step.env_var}</code>
                )}
                {step.example && (
                  <span className="text-muted"> (e.g. {step.example})</span>
                )}
              </li>
            ))}
          </ol>
          {item.docs_url && (
            <a
              className="text-[11px] text-signal underline"
              href={item.docs_url}
              target="_blank"
              rel="noreferrer"
            >
              {item.docs_url}
            </a>
          )}
        </div>
      )}
    </li>
  );
}

function ResultBlock({ result }: { result: AdapterResult }) {
  return (
    <div className="mt-3 rounded border border-edge bg-black/30 p-3">
      <div className="flex items-center gap-2">
        <span className="label">{result.adapter} result</span>
        <Chip tone={tone(result.state)}>{stateLabel(result.state)}</Chip>
        {!result.ran && (
          <Chip tone="text-muted border-edge bg-white/5">not run</Chip>
        )}
      </div>
      <p className="mt-1 text-[12px] text-ink">{result.detail}</p>

      {result.error_code && (
        <p className="mt-1 text-[11px] text-danger">code: {result.error_code}</p>
      )}

      {/* A refusal or a zero-finding result is stated plainly. "No findings" is
          only meaningful when the adapter actually ran and produced nothing;
          a refusal is not an empty scan. */}
      {result.error_code && result.findings.length === 0 && (
        <p className="mt-1 text-[11px] text-muted">
          Nothing was run. This is a refusal, not a clean result.
        </p>
      )}

      {result.ran && !result.error_code && result.findings.length === 0 && (
        <Empty>No findings returned.</Empty>
      )}

      {result.ran && result.findings.length > 0 && (
        <ul className="mt-2 space-y-1">
          {result.findings.map((finding, i) => (
            <li
              key={i}
              className="rounded border border-edge bg-black/20 px-2 py-1 text-[11px]"
            >
              <FindingRow finding={finding} />
            </li>
          ))}
        </ul>
      )}

      {Object.keys(result.meta).length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-[11px] text-muted">
            Provenance
          </summary>
          <pre className="mono mt-1 overflow-x-auto text-[10px] text-muted">
            {JSON.stringify(result.meta, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

function FindingRow({ finding }: { finding: Record<string, unknown> }) {
  const severity = typeof finding.severity === "string" ? finding.severity : null;
  const label =
    (finding.purl as string) ||
    (finding.package as string) ||
    (finding.kind as string) ||
    "finding";
  const type = typeof finding.type === "string" ? finding.type : null;
  const sevTone =
    severity === "critical" || severity === "high"
      ? "text-danger border-danger/40 bg-danger/10"
      : severity === "middle" || severity === "medium"
        ? "text-policy border-policy/40 bg-policy/10"
        : "text-muted border-edge bg-white/5";
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="mono text-ink">{label}</span>
      {severity && <Chip tone={sevTone}>{severity}</Chip>}
      {type && <Chip tone="text-analysis border-analysis/40 bg-analysis/10">{type}</Chip>}
      {typeof finding.operation === "string" && (
        <Chip tone="text-signal border-signal/40 bg-signal/10">
          {finding.operation}
        </Chip>
      )}
      {finding.confirm_required === true && (
        <Chip tone="text-policy border-policy/40 bg-policy/10">
          confirmation required
        </Chip>
      )}
    </div>
  );
}
