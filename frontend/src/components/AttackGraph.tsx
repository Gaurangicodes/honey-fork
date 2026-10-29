import { formatDelta, shortAddress } from "../format";
import type { AttackDefinition, RunEvent, ScanRun } from "../types";
import { Chip, Empty, Panel } from "./primitives";

interface Node {
  id: string;
  label: string;
  detail: string;
  tone: string;
  event?: RunEvent;
}

/**
 * FR-UX-08: the attack path is built from recorded events only.
 *
 * Each node exists because an event of that kind is present in the run. A node
 * the backend did not record is not drawn, so the graph cannot show a path that
 * was never observed. Clicking a node opens its event payload.
 */
export function AttackGraph({
  run,
  attack,
  events,
  onSelect,
  selectedId,
}: {
  run: ScanRun | null;
  attack: AttackDefinition | null;
  events: RunEvent[];
  onSelect: (node: Node) => void;
  selectedId: string | null;
}) {
  if (!run) {
    return (
      <Panel title="Attack path">
        <Empty>Select a trial to see its observed path.</Empty>
      </Panel>
    );
  }

  const find = (type: string) => events.find((e) => e.event_type === type);

  const payload = find("payload_received");
  const toolCall = find("tool_call");
  const decision = find("policy_decision");
  const receipt = find("transaction_receipt");
  const verdict = find("verifier_verdict");

  const transfer = run.tool_calls?.find((c) => c.tool === "wallet.transfer");
  const args = (transfer?.arguments ?? {}) as Record<string, unknown>;
  const recipient = typeof args.recipient === "string" ? args.recipient : null;
  const amount = typeof args.amount === "number" ? args.amount : null;

  const nodes: Node[] = [
    {
      id: "input",
      label: "Untrusted input",
      detail: attack ? `${attack.attack_id} · ${attack.category}` : "attack payload",
      tone: "border-accent/50 bg-accent/10 text-accent",
      event: payload,
    },
    {
      id: "agent",
      label: "Sandbox agent",
      detail: run.agent_id,
      tone: "border-evidence/50 bg-evidence/10 text-evidence",
    },
  ];

  if (toolCall) {
    nodes.push({
      id: "tool",
      label: "Proposed action",
      detail: transfer ? `wallet.transfer → ${shortAddress(recipient ?? "")}` : "tool call",
      tone: "border-evidence/50 bg-evidence/10 text-evidence",
      event: toolCall,
    });
  }

  if (decision) {
    const allowed = Boolean((decision.data ?? {}).allowed);
    const enforce = Boolean((decision.data ?? {}).enforce);
    nodes.push({
      id: "policy",
      label: "Policy proxy",
      detail: !enforce ? "not enforced" : allowed ? "allowed" : "denied before submission",
      tone: !enforce
        ? "border-edge bg-white/5 text-muted"
        : allowed
          ? "border-signal/50 bg-signal/10 text-signal"
          : "border-exploit/50 bg-exploit/10 text-exploit",
      event: decision,
    });
  }

  if (receipt) {
    nodes.push({
      id: "chain",
      label: "Sandbox chain",
      detail: "transaction receipt",
      tone: "border-exploit/50 bg-exploit/10 text-exploit",
      event: receipt,
    });
  }

  if (recipient) {
    nodes.push({
      id: "recipient",
      label: "Recipient",
      detail: shortAddress(recipient),
      tone: "border-edge bg-white/5 text-muted",
    });
  }

  if (verdict) {
    const blocked = run.verdict === "ATTEMPT_BLOCKED";
    nodes.push({
      id: "verdict",
      label: "Independent verdict",
      detail: run.verdict ?? "pending",
      tone: blocked
        ? "border-signal/50 bg-signal/10 text-signal"
        : run.verdict === "EXPLOIT_SUCCEEDED"
          ? "border-exploit/50 bg-exploit/10 text-exploit"
          : "border-edge bg-white/5 text-muted",
      event: verdict,
    });
  }

  if (!events.length) {
    return (
      <Panel title="Attack path">
        <Empty>No events recorded. The path appears as the run progresses.</Empty>
      </Panel>
    );
  }

  return (
    <Panel
      title="Attack path"
      actions={<span className="text-[11px] text-muted">{nodes.length} observed nodes</span>}
    >
      <div className="flex flex-wrap items-stretch gap-1">
        {nodes.map((node, index) => (
          <div key={node.id} className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => onSelect(node)}
              disabled={!node.event}
              className={`w-[9.5rem] rounded border px-2 py-1.5 text-left transition-colors ${node.tone} ${
                selectedId === node.id ? "ring-1 ring-signal/60" : ""
              } ${node.event ? "hover:brightness-125" : "cursor-default opacity-90"}`}
              title={node.event ? "Show the recorded event" : "No event for this node"}
            >
              <div className="text-[11px] font-semibold leading-tight">{node.label}</div>
              <div className="mono mt-0.5 break-all text-[10px] opacity-80">{node.detail}</div>
            </button>
            {index < nodes.length - 1 && <span className="text-muted">→</span>}
          </div>
        ))}
      </div>

      {amount !== null && (
        <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-edge pt-2">
          <span className="label">Proposed transfer</span>
          <Chip tone="text-ink border-edge bg-white/5">
            {formatDelta(amount, typeof args.decimals === "number" ? args.decimals : 18)} TST
          </Chip>
          <span className="text-[11px] text-muted">to</span>
          <span className="mono text-[11px] text-ink/80">{recipient}</span>
        </div>
      )}

      {run.balance_deltas?.length > 0 && (
        <div className="mt-2 border-t border-edge pt-2">
          <div className="label mb-1">Observed balance deltas</div>
          <div className="space-y-0.5">
            {run.balance_deltas.map((delta) => (
              <div key={delta.address} className="flex items-center gap-2">
                <span className="mono text-[11px] text-muted">{shortAddress(delta.address, 10, 6)}</span>
                <span
                  className={`mono text-[11px] ${delta.delta > 0 ? "text-exploit" : "text-muted"}`}
                >
                  {formatDelta(delta.delta)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
