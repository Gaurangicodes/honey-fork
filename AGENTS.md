# AGENTS.md

Repository-specific knowledge for AgentCrash Replay.

## What this repo is

A hackathon MVP (Hacker House Goa 2026) implementing the AgentCrash Replay SRS
v1.0 + v1.1 addendum: an AI-agent security regression loop
(attack → enforceable policy → replay → legitimate regression).

## Working repository

- Canonical repo is `Gaurangicodes/honey-fork`, default branch `main`. Land work
  as a branch + PR against that `main`.
- `GITHUB_TOKEN` is a GitHub App user-to-server token scoped to this repo only.
  Writes to any other repo fail with 403 "Resource not accessible by
  integration", and `git push` reports "Permission ... denied".
- `vanshikayadav404/Honey-Fork` is a separate repo with unrelated history and is
  not writable with this token. Do not try to push or cross-PR into it.

## Layout

- `backend/agentcrash/core/` — models, SQLite store, attack library, agent
  runtime, policy proxy/compiler, wallet tool, orchestrator.
- `backend/agentcrash/sandbox/` — chain adapters, sandbox manager, independent
  verifier.
- `backend/agentcrash/api/` — FastAPI app (SRS section 7 endpoints).
- `backend/tests/` — pytest suite.

## Commands

```bash
cd backend
pip install -r requirements.txt
python -m pytest                                  # 40 tests
uvicorn agentcrash.api.app:app --port 8123        # run API
python scripts/demo_flow.py                       # live end-to-end proof (needs API running)
python -m pyflakes agentcrash tests scripts       # lint
```

## Invariants — do not break these

These are enforced in code and covered by tests. Breaking one is a product bug,
not a style issue.

1. **A verdict never comes from model text.** Only `OutcomeVerifier` produces a
   verdict, and only from receipts and verified balance deltas.
2. **An attack that did not trigger is never labelled blocked.** See
   `OutcomeVerifier.verify` and the `attack_triggered` flag.
3. **A fix is Verified only when all hold:** original exploit verified, replay
   state fingerprint matches, prohibited transaction did not execute, and the
   legitimate regression transaction succeeded.
4. **A policy that would block the known legitimate transfer is refused at
   apply time** (`Orchestrator._assert_no_p0_regression`).
5. **`TEST_ERROR` is excluded from rate denominators** and counted separately.
6. **Secrets are redacted at the serialization boundary**
   (`evidence/redaction.py`).

## Gotchas

- `SimulatedChain` is the default sandbox; `AnvilChain` is optional and only
  implements reads. Do not assume a real node is available.
- Test addresses live in `core/constants.py` and are validated to be exactly 40
  hex chars at import. Attack payloads interpolate them, so payloads, sandbox
  accounts and policy templates can never drift apart.
- Amounts are integers in the token's smallest unit. Never use floats.
- The `environment` pytest fixture is already initialized to its known initial
  state (`default_demo_environment` calls `SandboxManager`), so tests can
  transfer immediately.
- A scan (parent) run carries no verdict; its trials do. Use
  `Orchestrator._trials_for` / `_resolve_original_run` to go from a scan id to
  the runs that actually hold verdicts and snapshots.
- Run IDs are UUID-suffixed and must stay unique; policy versions are
  append-only.

## Conventions

- Python 3.13, `from __future__ import annotations`, type hints everywhere.
- Comments explain non-obvious invariants and ordering. Do not narrate the diff.
- SRS requirement IDs (FR-SB-03, FR-PL-05, NFR-07, …) are cited in docstrings so
  code can be traced back to the spec.
