# AgentCrash Replay

A security regression-testing platform for AI agents that can move funds.

It tests an agent in a sandbox, detects dangerous actions by observing real
transaction outcomes, proposes an enforceable wallet policy, then replays the
original attack to prove the policy works and that legitimate transfers still
succeed.

Built for Hacker House Goa 2026 (AI x Crypto).

## Repository layout

```
backend/          Python API, agent runtime, sandbox and evidence store
frontend/         React + TypeScript command center dashboard
```

See `backend/README` in the module branch for build and run instructions.

## Modules

The SRS is implemented as a modular monolith. Modules land on their own
branches and are merged to `main` as they pass their acceptance gate.

| Module | Scope | Status |
| --- | --- | --- |
| 1 | Agent & attack management (registration, capability restriction, attack library) | done |
| 2 | Sandbox & transaction verification (state, resets, fingerprints, verifier) | done |
| 3 | Policy generation & enforcement (allowlist, max amount, proxy) | done |
| 4 | Replay, regression, scoring & reporting | done |
| 5 | Dashboard & scan orchestration | done |
| 6 | Persistence & evidence management | done |
| 7 | Optional ecosystem adapters (Socket, TigerGraph, Wispr Flow, Dodo Payments) | done |

Every module implements its SRS acceptance criteria. The optional adapters in
Module 7 are off by default and the core proof runs without them; see
[Optional integrations](#optional-integrations).

## Optional integrations

SRS 20.6 allows optional ecosystem adapters as long as they cannot weaken the
core proof. They are implemented in `backend/agentcrash/integrations/` under
three structural rules:

1. **Opt-in.** An adapter only calls out when its feature flag is set. A
   credential on its own does nothing.
2. **Honest states.** Every adapter reports `disabled`, `not_configured`, `ok`,
   `error` or `unsupported`. `AdapterResult` refuses to carry findings unless the
   state is `ok`, so a "not run" adapter can never be presented as a clean scan.
3. **No control.** Adapters return data. They cannot approve a policy, sign a
   transaction or change a verdict.

| Adapter | Priority | What it does | Requires |
| --- | --- | --- | --- |
| Socket.dev | P1 | Dependency/supply-chain preflight over the project's own manifests | `SOCKET_API_TOKEN`, `SOCKET_ORG_SLUG` |
| TigerGraph | P1 | Ingest observed run events for cross-run graph queries | `TIGERGRAPH_HOST`, `TIGERGRAPH_USERNAME`, `TIGERGRAPH_PASSWORD` |
| Wispr Flow | P1 | Voice-to-command input, with mandatory confirmation | none (dictation arrives as text) |
| Dodo Payments | P2 | Read-only usage metering for future billing | `DODO_PAYMENTS_API_KEY` |

Enable one with its flag, e.g. `AGENTCRASH_INTEGRATION_SOCKET=1`, plus its
credentials. `AGENTCRASH_INTEGRATIONS_ENABLED=0` forces all of them off.

Two adapter-specific notes:

- **Wispr Flow has no public API.** It is a dictation product, so the integration
  is a guarded input: `POST /api/integrations/wisprflow/parse` recognises the
  command and returns it unconfirmed. Voice cannot approve a policy, sign a
  transaction or move funds — those transcripts are refused with an explanation,
  and no such operation exists in the allowlist.
- **Dodo Payments is read-only.** SRS 25 puts billing at P2 with no live payment
  flow required, so the adapter reads a payment summary and never charges.

Endpoints: `GET /api/integrations` (all statuses and setup steps),
`GET /api/integrations/{adapter}`, `POST /api/integrations/socket/preflight`,
`POST /api/integrations/tigergraph/ingest/{run_id}`,
`GET /api/integrations/dodo/summary`,
`POST /api/integrations/wisprflow/parse`. The dashboard shows the same data in
its Optional integrations panel.

## Running the dashboard

Two processes: the API, then the Vite dev server (which proxies `/api` to it).

```bash
cd backend
pip install -r requirements.txt
uvicorn agentcrash.api.app:app --port 8000

cd ../frontend
npm install
npm run dev            # http://localhost:12000
```

`AGENTCRASH_API` overrides the proxy target if the API is not on port 8000.
Checks: `npm run typecheck`, `npm test` (vitest), `npm run build`.

The dashboard reads every status, metric and verdict from the API. It never
generates an outcome locally, and a run that errored is shown as an error
rather than as a security result.

## Security boundary

All accounts are disposable local test accounts. No production private keys,
seed phrases or real funds are used.
