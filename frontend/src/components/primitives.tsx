import { useState, type ReactNode } from "react";

export function Panel({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-edge px-3 py-2">
          <div className="label">{title}</div>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-3">{children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone = "text-ink",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: string;
}) {
  return (
    <div className="panel px-3 py-2">
      <div className="label">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${tone}`}>{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-muted">{hint}</div>}
    </div>
  );
}

export function Chip({
  children,
  tone = "text-muted border-edge bg-white/5",
  title,
}: {
  children: ReactNode;
  tone?: string;
  title?: string;
}) {
  return (
    <span className={`chip ${tone}`} title={title}>
      {children}
    </span>
  );
}

/** Copy affordance for hashes, addresses and JSON (SRS 24). */
export function Copyable({
  value,
  display,
  className = "",
}: {
  value: string;
  display?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={`Copy ${value}`}
      className={`mono group inline-flex items-center gap-1 text-left hover:text-signal ${className}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        } catch {
          /* clipboard unavailable (insecure context); the value stays visible */
        }
      }}
    >
      <span>{display ?? value}</span>
      <span className="text-muted opacity-0 transition-opacity group-hover:opacity-100">
        {copied ? "✓" : "⧉"}
      </span>
    </button>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-6 text-center text-[12px] text-muted">{children}</div>;
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  // FR-UI-06: errors are shown as errors, never dressed up as an outcome.
  return (
    <div className="rounded border border-policy/40 bg-policy/10 px-2 py-1.5 text-[12px] text-policy">
      {error}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-[12px] text-muted">
      <span className="inline-block h-2 w-2 animate-pulseglow rounded-full bg-signal" />
      {label}
    </span>
  );
}
