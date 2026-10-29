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
  registry, agent runtime, tool registry, policy proxy/compiler, wallet tool,
  orchestrator.
- `backend/agentcrash/sandbox/` — chain adapters, sandbox manager, independent
  verifier.
- `backend/agentcrash/api/` — FastAPI app (SRS section 7 endpoints).
- `backend/tests/` — pytest suite (`test_agent_module1.py`,
  `test_sandbox_module2.py`, `test_pipeline_e2e.py`).

## Commands

```bash
cd backend
pip install -r requirements.txt
python -m pytest                                  # 104 tests
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
7. **An agent can only invoke a tool that is both registered and in its own
   `tool_set`.** `ToolRegistry.invoke` and `SandboxAgent.gather_observations`
   return a recorded `ToolCallResult(rejected=True)`; they never raise and never
   fall through to the tool body. An unregistered-tool attempt is evidence, not
   a security outcome.
8. **Tool output is untrusted input.** The agent's instruction channel is the
   attack payload *plus* the rendered tool observations, which is why AT-01/AT-02
   can steer the agent through a mock tool. Never treat a tool response as
   trusted.

## Module 1 notes (agent & attack management)

- Two configurations live in `core/agent_registry.py` and are seeded into the
  `agent_configs` table by `api/app.py::build_state` (FR-AG-01, FR-AG-02). They
  are identical except for `guardrail`, which is the documented differentiator.
- `AgentRegistry.register` rejects a `tool_set` naming a tool the sandbox does
  not expose, so a stored configuration's tool list is always true at runtime.
- Attack `tools_used` / `tool_outputs` are how a tool-channel scenario carries
  its injection (FR-AT-05). AT-01 drives `token.read_metadata`, AT-02 drives
  `oracle.get_price`; AT-03/AT-04 are text-only.
- Tool ids are constants in `core/tools.py`. Add a tool there *and* to a
  configuration's `tool_set` before referencing it in an attack.

## Module 3 notes (policy generation & enforcement)

- `PolicyProxy` is the enforcement boundary. It holds an applied *stack*, not a
  single policy: an action must satisfy **every** active policy (FR-PL-03), one
  effective policy per type. Applying an amount cap must never silently drop an
  earlier recipient allowlist — that regression is covered by
  `test_stack_blocks_unknown_recipient_even_when_amount_is_fine`.
- Chain identity is checked *before* any rule, including when no policy is
  active (SR-06). A transaction aimed at the wrong chain is never submitted.
- `PolicyRegistry` (`core/policy_registry.py`) owns per-type version numbers and
  append-only history. Version numbers are per type, so "allowlist v2" is
  unambiguous alongside "amount v1".
- `Orchestrator.apply_policy` validates parameters, then dry-runs a legitimate
  probe against the *resulting stack* before applying. A rule that would block
  the known legitimate transfer is refused (FR-PL-05, Guardrail B).
- Only `template_for()`-backed types can be applied. An attack with no supported
  template returns `None` from the compiler and the API reports "no automatic
  fix" (FR-PL-06) rather than inventing a generic rule.
- Replay deliberately runs under the *currently applied* stack. A cap alone does
  not block AT-01, and the verifier correctly reports `EXPLOIT_SUCCEEDED` /
  `FAILED` in that case — do not "fix" this into a block.

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
