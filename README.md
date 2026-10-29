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
```

See `backend/README` in the module branch for build and run instructions.

## Security boundary

All accounts are disposable local test accounts. No production private keys,
seed phrases or real funds are used.
