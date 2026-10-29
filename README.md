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

Every module implements its SRS acceptance criteria. Scope that the SRS marks
P1/P2 (partner integrations, hosted reports, billing) is deliberately absent;
`GET /api/evidence/integrity` is an integrity check over stored records, not a
signature or an audit.

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
