"""TigerGraph attack-path graph adapter (FR-INT-03, SRS section 25).

The local interactive attack graph (FR-UX-08) is the baseline and always works.
This adapter is the optional second path: it ingests the *same observed run
events* into TigerGraph so a reviewer can run cross-run graph queries, e.g.
"which tool calls appear on every path that ends in a policy denial".

Guardrail from FR-UX-08 carries over: only events that were actually recorded
are ingested. Nothing here invents a node or an edge, and if TigerGraph is not
configured the local graph is unaffected.

Contract (verified against TigerGraph REST docs, 4.x):

* ``POST {base}/restpp/requesttoken`` with ``{"secret": ...}`` returns a token.
  GSQL-server endpoints on port 14240 accept basic auth instead; a token is
  preferred because it avoids sending the password on every call.
* ``POST {base}/restpp/graph/{graph}`` upserts vertices/edges using the
  ``{"vertices": {"VertexType": {"id": {...}}}, "edges": {...}}`` shape.
* ``POST {base}/restpp/query/{graph}/{query}`` runs an installed query.

Only vertices and edges derived from recorded events are sent.
"""

from __future__ import annotations

from typing import Any, Iterable

from .base import AdapterResult, Integration, IntegrationState, SetupStep

# The vertex/edge types this adapter writes. Kept in one place so the schema the
# operator must create and the payload we send cannot drift apart.
VERTEX_TYPES = ("Run", "Attack", "ToolCall", "PolicyDecision", "Transaction", "Recipient")
EDGE_TYPES = (
    "RUN_EXECUTED_ATTACK",
    "RUN_MADE_TOOLCALL",
    "RUN_HAS_POLICY_DECISION",
    "TOOLCALL_DECIDED_BY_POLICY",
    "TOOLCALL_PRODUCED_TRANSACTION",
    "TRANSACTION_SENT_TO_RECIPIENT",
)


class TigerGraphIntegration(Integration):
    name = "tigergraph"
    priority = "P1"
    docs_url = "https://docs.tigergraph.com/tigergraph-server/current/api/"
    required_config = ("TIGERGRAPH_HOST", "TIGERGRAPH_USERNAME", "TIGERGRAPH_PASSWORD")
    role = "Optional attack-path/evidence graph backend"
    acceptance = (
        "Actual graph ingestion/query demonstrated; local graph remains the fallback."
    )

    @property
    def base_url(self) -> str:
        return self._environ["TIGERGRAPH_HOST"].rstrip("/")

    @property
    def graph(self) -> str:
        return self._environ.get("TIGERGRAPH_GRAPH", "agentcrash")

    @property
    def token(self) -> str | None:
        return self._environ.get("TIGERGRAPH_TOKEN")

    def setup(self) -> list[SetupStep]:
        return [
            SetupStep("Provide the TigerGraph host URL", "TIGERGRAPH_HOST", "http://localhost:14240"),
            SetupStep("Provide a TigerGraph username", "TIGERGRAPH_USERNAME"),
            SetupStep("Provide the matching password", "TIGERGRAPH_PASSWORD"),
            SetupStep("Enable the adapter", self.flag_name, "1"),
            SetupStep(
                "Create the graph and install the vertex/edge types this adapter writes",
                "TIGERGRAPH_GRAPH",
                "agentcrash",
            ),
            SetupStep(
                "Optional: supply a pre-issued token to skip the token exchange",
                "TIGERGRAPH_TOKEN",
            ),
        ]

    # -- auth ----------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Prefer a supplied token; otherwise fetch one with basic auth."""
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _ensure_token(self, client: Any) -> str:
        """Return a usable token, exchanging credentials if none was supplied."""
        if self.token:
            return self.token
        response = client.post(
            "/restpp/requesttoken",
            json={"secret": self._environ["TIGERGRAPH_PASSWORD"]},
            auth=(self._environ["TIGERGRAPH_USERNAME"], self._environ["TIGERGRAPH_PASSWORD"]),
        )
        if response.status_code == 401:
            raise _TigerError("TIGERGRAPH_UNAUTHORIZED", "TigerGraph rejected the credentials.")
        if response.status_code >= 400:
            raise _TigerError(
                "TIGERGRAPH_BAD_RESPONSE", f"Token request returned HTTP {response.status_code}."
            )
        try:
            return response.json()["token"]
        except (KeyError, ValueError) as exc:
            raise _TigerError("TIGERGRAPH_BAD_RESPONSE", f"No token in response: {exc}") from exc

    # -- capabilities --------------------------------------------------------

    def health(self) -> AdapterResult:
        """Confirm the host answers and the configured graph exists."""
        if self.state() is not IntegrationState.OK:
            return self.unavailable()
        import httpx

        try:
            with self._client(self.base_url) as client:
                token = self._ensure_token(client)
                response = client.get(
                    f"/restpp/graph/{self.graph}/vertices/Run",
                    headers={"Authorization": f"Bearer {token}"},
                )
        except _TigerError as exc:
            return self._error(exc.code, exc.detail)
        except httpx.HTTPError as exc:
            return self._error("TIGERGRAPH_UNREACHABLE", f"TigerGraph unreachable: {exc}")

        if response.status_code >= 400:
            return self._error(
                "TIGERGRAPH_BAD_RESPONSE",
                f"Graph '{self.graph}' not queryable (HTTP {response.status_code}).",
                status=response.status_code,
            )
        return AdapterResult(
            adapter=self.name,
            state=IntegrationState.OK,
            detail=f"Graph '{self.graph}' is reachable.",
            meta={"graph": self.graph, "host": self.base_url},
        )

    def ingest_events(
        self, events: Iterable[dict[str, Any]], *, agent_id: str | None = None
    ) -> AdapterResult:
        """FR-INT-03: upsert vertices/edges derived from recorded run events.

        ``events`` are the persisted run events. Only what they contain is sent;
        the adapter never synthesises a path that was not observed.
        """
        if self.state() is not IntegrationState.OK:
            return self.unavailable()
        payload = build_upsert_payload(events, agent_id=agent_id)
        counts = payload["meta"]
        if not counts["vertices"] and not counts["edges"]:
            return AdapterResult(
                adapter=self.name,
                state=IntegrationState.OK,
                detail="No graphable events in the supplied run.",
                meta=counts,
            )

        import httpx

        body = {"vertices": payload["vertices"], "edges": payload["edges"]}
        try:
            with self._client(self.base_url) as client:
                token = self._ensure_token(client)
                response = client.post(
                    f"/restpp/graph/{self.graph}",
                    headers={"Authorization": f"Bearer {token}"},
                    json=body,
                )
        except _TigerError as exc:
            return self._error(exc.code, exc.detail)
        except httpx.HTTPError as exc:
            return self._error("TIGERGRAPH_UNREACHABLE", f"TigerGraph unreachable: {exc}")

        if response.status_code >= 400:
            return self._error(
                "TIGERGRAPH_INGEST_FAILED",
                f"Upsert returned HTTP {response.status_code}.",
                status=response.status_code,
            )

        try:
            result = response.json()
        except ValueError as exc:
            return self._error("TIGERGRAPH_BAD_RESPONSE", f"Unparseable response: {exc}")
        # TigerGraph reports per-vertex/edge errors inside a 200 body.
        body_errors = result.get("error") if isinstance(result, dict) else None
        if body_errors:
            return self._error("TIGERGRAPH_INGEST_FAILED", f"Upsert reported errors: {body_errors}")
        return AdapterResult(
            adapter=self.name,
            state=IntegrationState.OK,
            detail=(
                f"Ingested {counts['vertices']} vertex/vertices and "
                f"{counts['edges']} edge(s)."
            ),
            findings=[
                {"kind": "graph_ingest", "vertex_counts": counts["vertex_types"],
                 "edge_counts": counts["edge_types"], "source": "tigergraph"}
            ],
            meta={**counts, "graph": self.graph},
        )

    def _error(self, code: str, detail: str, *, status: int | None = None) -> AdapterResult:
        meta = {"status": status} if status is not None else {}
        return AdapterResult(
            adapter=self.name,
            state=IntegrationState.ERROR,
            detail=detail,
            reason=detail,
            error_code=code,
            meta=meta,
        )


class _TigerError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# -- event -> graph projection ----------------------------------------------


def build_upsert_payload(
    events: Iterable[dict[str, Any]], agent_id: str | None = None
) -> dict[str, Any]:
    """Project persisted run events into TigerGraph vertices and edges.

    The projection mirrors the local attack graph: input -> tool call -> policy
    decision -> transaction -> recipient. Only fields present in the events
    become properties, so an event stream that never reached a receipt yields no
    Transaction vertex rather than a placeholder.

    Events are the persisted :class:`RunEvent` shape: a flat envelope
    (``run_id``, ``event_id``, ``event_type``, ``seq``) with the detail nested
    under ``data``. Ordering within a run is the only link the events carry, so
    a decision or receipt is attached to the most recent tool call in that run,
    which is the order the orchestrator emitted them in.
    """
    vertices: dict[str, dict[str, dict[str, Any]]] = {t: {} for t in VERTEX_TYPES}
    edges: dict[str, dict[str, dict[str, dict[str, Any]]]] = {t: {} for t in EDGE_TYPES}
    vertex_counts: dict[str, int] = {}
    edge_counts: dict[str, int] = {}

    def add_vertex(vtype: str, vid: str, props: dict[str, Any] | None = None) -> None:
        if not vid:
            return
        if vid not in vertices[vtype]:
            vertices[vtype][vid] = {k: v for k, v in (props or {}).items() if v is not None}
            vertex_counts[vtype] = vertex_counts.get(vtype, 0) + 1

    def add_edge(etype: str, src_type: str, src: str, tgt_type: str, tgt: str) -> None:
        if not (src and tgt):
            return
        edges[etype].setdefault(src, {})[tgt] = {"from_type": src_type, "to_type": tgt_type}
        edge_counts[etype] = edge_counts.get(etype, 0) + 1

    run_ids: set[str] = set()
    last_tool_call: dict[str, str] = {}

    for event in sorted(events, key=lambda e: (str(e.get("run_id") or ""), e.get("seq") or 0)):
        run_id = str(event.get("run_id") or "")
        if not run_id:
            continue
        run_ids.add(run_id)
        add_vertex("Run", run_id, {"agent_id": agent_id})
        data = event.get("data") or {}
        etype = event.get("event_type") or ""
        event_id = str(event.get("event_id") or f"{run_id}:{event.get('seq') or 0}")

        if etype == "payload_received":
            attack_id = str(data.get("attack_id") or "")
            add_vertex("Attack", attack_id, {"version": data.get("attack_version")})
            add_edge("RUN_EXECUTED_ATTACK", "Run", run_id, "Attack", attack_id)

        elif etype == "tool_call":
            args = data.get("arguments") or {}
            tool = str(args.get("action_type") or "")
            add_vertex(
                "ToolCall",
                event_id,
                {"tool": tool, "amount": args.get("amount"), "chain_id": args.get("chain_id")},
            )
            add_edge("RUN_MADE_TOOLCALL", "Run", run_id, "ToolCall", event_id)
            last_tool_call[run_id] = event_id
            # A proposed recipient is only drawn as a transfer once a receipt
            # confirms movement, so the Recipient vertex is added at receipt time.

        elif etype == "policy_decision":
            # A denial is emitted by the proxy before submission, so a blocked
            # trial may have no preceding tool_call event. Attach the decision to
            # the tool call when one was observed, otherwise to the run, so the
            # edge's source type always matches the vertex it points from.
            source = last_tool_call.get(run_id)
            decision_id = f"{source or run_id}:{event_id}"
            add_vertex(
                "PolicyDecision",
                decision_id,
                {
                    "allowed": data.get("allowed"),
                    "enforce": data.get("enforce"),
                    "reason_code": data.get("reason_code"),
                    "policy_version": data.get("policy_version"),
                },
            )
            if source:
                add_edge(
                    "TOOLCALL_DECIDED_BY_POLICY",
                    "ToolCall",
                    source,
                    "PolicyDecision",
                    decision_id,
                )
            else:
                add_edge(
                    "RUN_HAS_POLICY_DECISION",
                    "Run",
                    run_id,
                    "PolicyDecision",
                    decision_id,
                )

        elif etype == "transaction_receipt":
            tx_hash = str(data.get("transaction_hash") or "")
            source = last_tool_call.get(run_id)
            add_vertex(
                "Transaction",
                tx_hash,
                {
                    "status": data.get("status"),
                    "block_number": data.get("block_number"),
                    "sender": data.get("sender"),
                    "token": data.get("token"),
                    "amount": data.get("amount"),
                },
            )
            add_edge("TOOLCALL_PRODUCED_TRANSACTION", "ToolCall", source or run_id, "Transaction", tx_hash)
            recipient = data.get("recipient")
            if recipient:
                add_vertex("Recipient", str(recipient))
                add_edge(
                    "TRANSACTION_SENT_TO_RECIPIENT",
                    "Transaction",
                    tx_hash,
                    "Recipient",
                    str(recipient),
                )

    total_vertices = sum(len(v) for v in vertices.values())
    total_edges = sum(len(dst) for e in edges.values() for dst in e.values())
    return {
        "vertices": {t: v for t, v in vertices.items() if v},
        "edges": {t: {src: dst for src, dst in e.items() if dst} for t, e in edges.items() if e},
        "meta": {
            "runs": len(run_ids),
            "vertices": total_vertices,
            "edges": total_edges,
            "vertex_types": vertex_counts,
            "edge_types": edge_counts,
        },
    }
