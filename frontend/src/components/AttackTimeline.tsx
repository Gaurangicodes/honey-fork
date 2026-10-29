import { EVENT_META, formatTime, shortAddress } from "../format";
import type { RunEvent } from "../types";
import { Chip, Empty } from "./primitives";

/**
 * FR-UX-09 / FR-UI-03: the ordered event timeline.
 *
 * Every row comes from a persisted `RunEvent`. Nothing is generated client-side,
 * so what the operator reads here is what the backend recorded.
 */
export function AttackTimeline({ events }: { events: RunEvent[] }) {
  if (!events.length) {
    return <Empty>No events recorded for this run yet.</Empty>;
  }

  return (
    <ol className="scroll max-h-[26rem] space-y-1 overflow-y-auto pr-1">
      {events.map((event) => {
        const meta = EVENT_META[event.event_type] ?? {
          label: event.event_type,
          tone: "text-muted",
        };
        return (
          <li
            key={event.event_id}
            className="animate-slidein rounded border border-edge/60 bg-white/[0.02] px-2 py-1.5"
          >
            <div className="flex items-baseline gap-2">
              <span className="mono shrink-0 text-muted">{formatTime(event.timestamp)}</span>
              <span className={`shrink-0 text-[11px] font-semibold ${meta.tone}`}>
                {meta.label}
              </span>
              <span className="min-w-0 flex-1 truncate text-[12px] text-ink/90" title={event.message}>
                {event.message}
              </span>
              <span className="mono shrink-0 text-[10px] text-muted">#{event.seq}</span>
            </div>
            {event.data && <EventData event={event} />}
          </li>
        );
      })}
    </ol>
  );
}

function EventData({ event }: { event: RunEvent }) {
  const data = event.data ?? {};

  if (event.event_type === "policy_decision") {
    const allowed = Boolean(data.allowed);
    const enforce = Boolean(data.enforce);
    return (
      <div className="mt-1 flex flex-wrap items-center gap-1.5 pl-[3.6rem]">
        <Chip
          tone={
            !enforce
              ? "text-muted border-edge bg-white/5"
              : allowed
                ? "text-signal border-signal/40 bg-signal/10"
                : "text-exploit border-exploit/40 bg-exploit/10"
          }
        >
          {!enforce ? "not enforced" : allowed ? "ALLOW" : "DENY"}
        </Chip>
        {typeof data.reason_code === "string" && (
          <span className="mono text-[11px] text-muted">{data.reason_code}</span>
        )}
        {typeof data.reason === "string" && (
          <span className="text-[11px] text-ink/70">{data.reason}</span>
        )}
      </div>
    );
  }

  if (event.event_type === "transaction_receipt") {
    return (
      <div className="mt-1 flex flex-wrap items-center gap-2 pl-[3.6rem]">
        {typeof data.transaction_hash === "string" && (
          <span className="mono text-[11px] text-evidence">{shortAddress(data.transaction_hash, 12, 8)}</span>
        )}
        {typeof data.status === "string" && (
          <Chip tone="text-exploit border-exploit/40 bg-exploit/10">{data.status}</Chip>
        )}
      </div>
    );
  }

  const entries = Object.entries(data).filter(([, value]) => value !== null && value !== undefined);
  if (!entries.length) return null;

  return (
    <details className="mt-1 pl-[3.6rem]">
      <summary className="cursor-pointer text-[11px] text-muted hover:text-signal">
        {entries.length} field{entries.length === 1 ? "" : "s"}
      </summary>
      <pre className="mono scroll mt-1 max-h-40 overflow-auto rounded bg-canvas/70 p-2 text-[11px] text-ink/80">
        {JSON.stringify(data, null, 2)}
      </pre>
    </details>
  );
}
