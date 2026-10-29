import type {
  AdapterResult,
  AgentConfiguration,
  AttackDefinition,
  Comparison,
  Health,
  IntegrationSummary,
  Policy,
  PolicyTemplate,
  ReplayResult,
  Report,
  RunEvent,
  ScanAccepted,
  ScanRun,
} from "./types";

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    // SRS 7.4: errors carry a stable code. Surface it rather than a bare status
    // so the UI can distinguish a policy rejection from an infrastructure fault.
    let code = `HTTP_${response.status}`;
    let message = response.statusText;
    try {
      const body = await response.json();
      code = body?.error?.code ?? code;
      message = body?.error?.message ?? message;
    } catch {
      /* non-JSON error body; keep the status-derived values */
    }
    throw new ApiError(response.status, code, message);
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<Health>("/health"),

  agents: () => request<AgentConfiguration[]>("/agents"),
  attacks: () => request<AttackDefinition[]>("/attacks"),
  policyTemplates: () => request<PolicyTemplate[]>("/policies/templates"),

  scans: (limit = 50) => request<ScanRun[]>(`/scans?limit=${limit}`),
  scan: (runId: string) =>
    request<{ run: ScanRun; child_runs: ScanRun[]; evidence: unknown[] }>(
      `/scans/${runId}`,
    ),
  trials: (runId: string) => request<ScanRun[]>(`/scans/${runId}/trials`),
  events: (runId: string) => request<RunEvent[]>(`/scans/${runId}/events`),

  /** FR-UI-02: queues the scan; poll trials/events for progress. */
  startScan: (body: {
    agent_id: string;
    attack_ids: string[];
    repeat_count: number;
  }) =>
    request<ScanAccepted>("/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  /** `policy` is null when no template matches (FR-PL-06). */
  proposePolicy: (runId: string) =>
    request<{ policy: Policy | null; policies: Policy[]; message?: string }>(
      `/scans/${runId}/policies`,
      { method: "POST" },
    ),
  applyPolicy: (policyId: string) =>
    request<{ policy: Policy; active_stack: Policy[] }>(
      `/policies/${policyId}/apply`,
      { method: "POST" },
    ),
  policies: () => request<Policy[]>("/policies"),
  activePolicies: () =>
    request<{ active_policies: Policy[]; versions: string[]; count: number }>(
      "/policies/active",
    ),

  replay: (runId: string, repeatCount = 1) =>
    request<ReplayResult>(`/scans/${runId}/replay`, {
      method: "POST",
      body: JSON.stringify({ repeat_count: repeatCount }),
    }),
  comparison: (originalRunId: string, replayRunId: string) =>
    request<Comparison>(
      `/scans/${originalRunId}/comparison?replay_run_id=${replayRunId}`,
    ),
  receipt: (runId: string) =>
    request<{ receipt: Record<string, unknown> }>(`/scans/${runId}/receipt`),

  createReport: (runIds: string[]) =>
    request<{ report: Report }>("/reports", {
      method: "POST",
      body: JSON.stringify({ run_ids: runIds }),
    }),

  resetSandbox: () =>
    request<{ snapshot: unknown }>("/sandbox/reset", { method: "POST" }),
  sandboxState: () => request<Record<string, unknown>>("/sandbox/state"),

  // -- optional ecosystem adapters (SRS 20.6) -------------------------------
  // Each of these answers honestly when its adapter is off: the result says it
  // did not run rather than returning an empty success. The UI must render that
  // as "not run", never as a clean result.
  integrations: () => request<IntegrationSummary>("/integrations"),
  socketPreflight: (purls?: string[]) =>
    request<AdapterResult>("/integrations/socket/preflight", {
      method: "POST",
      body: JSON.stringify(purls ? { purls } : {}),
    }),
  tigergraphIngest: (runId: string) =>
    request<AdapterResult>(`/integrations/tigergraph/ingest/${runId}`, {
      method: "POST",
    }),
  dodoSummary: () => request<AdapterResult>("/integrations/dodo/summary"),
  wisprParse: (transcript: string) =>
    request<AdapterResult>("/integrations/wisprflow/parse", {
      method: "POST",
      body: JSON.stringify({ transcript }),
    }),
};
