#!/usr/bin/env python3
"""Live smoke test of the full Module 2 proof loop against a running server.

Run the API first:
    uvicorn agentcrash.api.app:app --port 8123
then:
    python scripts/demo_flow.py
"""

from __future__ import annotations

import json
import sys

import httpx

BASE = "http://localhost:8123/api"


def show(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    client = httpx.Client(timeout=30.0)

    show("health")
    health = client.get(f"{BASE}/health").json()
    print(json.dumps(health["sandbox"], indent=2))

    show("scan (vulnerable configuration, all four attacks)")
    scan = client.post(
        f"{BASE}/scans",
        json={
            "agent_id": "agent-vulnerable-01",
            "attack_ids": ["AT-01", "AT-02", "AT-03", "AT-04"],
            "repeat_count": 1,
        },
    ).json()
    run_id = scan["run_id"]
    print(f"run_id={run_id} status={scan['status']} trials={scan['completed_trials']}")

    trials = client.get(f"{BASE}/scans/{run_id}/trials").json()
    for trial in trials:
        moved = [(d["address"][:12], d["delta"]) for d in trial["balance_deltas"] if d["delta"]]
        print(f"  {trial['attack_id']}: {trial['verdict']} tx={trial['transaction_hashes']} {moved}")

    show("proposed policies (from verified exploits only)")
    proposals = client.post(f"{BASE}/scans/{run_id}/policies").json()["policies"]
    for policy in proposals:
        print(f"  {policy['policy_id']} {policy['type']} {policy['parameters']}")

    if not proposals:
        print("no policies proposed; nothing to replay")
        return 1

    show("apply the allowlist policy")
    allowlist = next(p for p in proposals if p["type"] == "recipient_allowlist")
    applied = client.post(f"{BASE}/policies/{allowlist['policy_id']}/apply").json()["policy"]
    print(f"  applied {applied['policy_id']} v{applied['version']} status={applied['status']}")

    show("replay the original attack under the policy")
    replay = client.post(f"{BASE}/scans/{run_id}/replay", json={}).json()
    print(f"  replay verdict: {replay['replay_run']['verdict']}")
    print(f"  tx hashes:      {replay['replay_run']['transaction_hashes']}")
    print(f"  legitimate:     {replay['regression']['legitimate_task_passed']}")
    print(f"  fix status:     {replay['proof_status']['fix_status']}")
    print(f"  proof:          {replay['proof_status']['label']}")

    show("report")
    report = client.post(f"{BASE}/reports", json={"run_ids": [run_id]}).json()["report"]
    print(json.dumps(report["metrics"], indent=2))

    ok = (
        replay["replay_run"]["verdict"] == "ATTEMPT_BLOCKED"
        and replay["regression"]["legitimate_task_passed"]
        and replay["proof_status"]["fix_status"] == "VERIFIED"
    )
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
