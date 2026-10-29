import { formatUnits } from "../format";
import type { Policy, PolicyTemplate } from "../types";
import { Chip, Empty, Panel } from "./primitives";

/**
 * FR-PL-04 / FR-PL-07 / FR-UI-04: review a proposed policy before it is applied.
 *
 * The exact parameters are shown as the structured values that will be
 * enforced. There is no silent apply path: `onApply` is the only way through,
 * and Cancel leaves the sandbox untouched.
 */
export function PolicyLab({
  policy,
  template,
  unsupportedMessage,
  activeVersions,
  busy,
  error,
  onApply,
  onCancel,
}: {
  policy: Policy | null;
  template: PolicyTemplate | null;
  unsupportedMessage: string | null;
  activeVersions: string[];
  busy: boolean;
  error: string | null;
  onApply: (policy: Policy) => void;
  onCancel: () => void;
}) {
  if (!policy) {
    return (
      <Panel title="Policy lab">
        {unsupportedMessage ? (
          // FR-PL-06: an unmappable attack is reported as unsupported.
          <div className="rounded border border-policy/40 bg-policy/10 px-2 py-2 text-[12px] text-policy">
            {unsupportedMessage}
          </div>
        ) : (
          <Empty>
            No policy proposed. Run a scan with a verified exploit, then generate a fix.
          </Empty>
        )}
      </Panel>
    );
  }

  const unsupported = !template;

  return (
    <Panel
      title="Policy lab"
      actions={
        <Chip tone="text-policy border-policy/40 bg-policy/10">proposed · v{policy.version}</Chip>
      }
    >
      <div className="space-y-3">
        <div>
          <div className="text-sm font-semibold text-ink">
            {template?.label ?? policy.type}
          </div>
          <p className="mt-0.5 text-[12px] text-muted">
            {template?.summary ?? "No automatic fix is available for this attack."}
          </p>
        </div>

        {unsupported ? (
          // FR-PL-06: an unsupported fix is reported as unsupported, not
          // silently replaced with a generic rule.
          <div className="rounded border border-policy/40 bg-policy/10 px-2 py-2 text-[12px] text-policy">
            This attack does not map to an implemented policy template. No automatic
            fix is available, and none will be applied.
          </div>
        ) : (
          <>
            <ParamTable policy={policy} />

            {policy.diff.length > 0 && (
              <div className="rounded border border-edge">
                <div className="label border-b border-edge px-2 py-1">
                  Parameter changes
                </div>
                <table className="w-full text-[12px]">
                  <tbody>
                    {policy.diff.map((entry) => (
                      <tr key={entry.parameter} className="border-b border-edge/60 last:border-0">
                        <td className="w-40 px-2 py-1 align-top text-muted">
                          {entry.parameter}
                        </td>
                        <td className="px-2 py-1">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="mono text-[11px] text-muted line-through">
                              {renderDiffValue(entry.before)}
                            </span>
                            <span className="text-muted">→</span>
                            <span className="mono text-[11px] text-signal">
                              {renderDiffValue(entry.after)}
                            </span>
                          </div>
                          {entry.note && (
                            <div className="mt-0.5 text-[10px] text-muted">{entry.note}</div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="space-y-1.5 rounded border border-edge bg-white/[0.02] p-2">
              <Line label="Why" value={policy.rationale} />
              <Line label="Expected effect" value={policy.expected_effect} />
              <Line label="Legitimate impact" value={policy.legitimate_task_impact} />
              <Line label="Source" value={policy.source_attack_id ?? "—"} />
            </div>

            <div className="rounded border border-edge bg-white/[0.02] p-2">
              <div className="label mb-1">What will be blocked</div>
              <p className="text-[12px] text-ink/85">{template?.blocks}</p>
            </div>

            {activeVersions.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="label">Active now</span>
                {activeVersions.map((version) => (
                  <Chip key={version} tone="text-signal border-signal/40 bg-signal/10">
                    v{version}
                  </Chip>
                ))}
              </div>
            )}

            {error && (
              <div className="rounded border border-exploit/40 bg-exploit/10 px-2 py-1.5 text-[12px] text-exploit">
                {error}
              </div>
            )}

            <div className="flex items-center gap-2 border-t border-edge pt-3">
              <button
                type="button"
                className="btn-primary"
                disabled={busy}
                onClick={() => onApply(policy)}
              >
                {busy ? "Applying…" : "Apply fix"}
              </button>
              <button type="button" className="btn" disabled={busy} onClick={onCancel}>
                Cancel
              </button>
              <span className="text-[11px] text-muted">
                Applies to the sandbox wallet path only. A new immutable version is recorded.
              </span>
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

function ParamTable({ policy }: { policy: Policy }) {
  const entries = Object.entries(policy.parameters ?? {});
  if (!entries.length) {
    return <div className="text-[12px] text-muted">No parameters.</div>;
  }
  return (
    <div className="rounded border border-edge">
      <div className="label border-b border-edge px-2 py-1">Exact parameters</div>
      <table className="w-full text-[12px]">
        <tbody>
          {entries.map(([key, value]) => (
            <tr key={key} className="border-b border-edge/60 last:border-0">
              <td className="w-40 px-2 py-1 align-top text-muted">{key}</td>
              <td className="px-2 py-1">
                <ParamValue name={key} value={value} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ParamValue({ name, value }: { name: string; value: unknown }) {
  if (Array.isArray(value)) {
    return (
      <div className="space-y-0.5">
        {value.map((item) => (
          <div key={String(item)} className="mono break-all text-ink/85">
            {String(item)}
          </div>
        ))}
      </div>
    );
  }
  if (name === "max_amount" && typeof value === "number") {
    // FR-PL-02: amounts are base units; show the token figure the operator
    // recognises as well as the raw value that is enforced.
    return (
      <div>
        <div className="mono text-ink/85">{formatUnits(value)} TST</div>
        <div className="mono text-[10px] text-muted">{value} base units</div>
      </div>
    );
  }
  return <span className="mono break-all text-ink/85">{String(value)}</span>;
}

function renderDiffValue(value: unknown): string {
  if (Array.isArray(value)) return value.length ? value.map(String).join(", ") : "(none)";
  if (value === null || value === undefined || value === "") return "(none)";
  return String(value);
}

function Line({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="label w-28 shrink-0">{label}</span>
      <span className="text-[12px] text-ink/85">{value}</span>
    </div>
  );
}
