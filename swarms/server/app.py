"""The SWARMS gateway: a policy decision point over HTTP, plus the console.

Any agent framework in any language can ask this service whether a tool call
should happen. The Python SDK is the fast path for Python applications; this
is the one for everything else, and it is also where the audit trail, the
approval queue and the operator console live.

    POST /v1/sessions              open a session for one unit of work
    POST /v1/sessions/{id}/ingest  register content that came from outside
    POST /v1/sessions/{id}/trust   register a value the human supplied
    POST /v1/authorize             decide a tool call

Everything under /api is the console's read and admin surface. OpenAPI at
/docs describes all of it.
"""
from __future__ import annotations

import json
import logging
import os
import time
from threading import Lock

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from swarms import __version__, llm
from swarms.config import Policy, PolicyError
from swarms.guard import Guard, Session
from swarms.policy import Effect
from swarms.server.auth import ApiKey, KeyRing, make_dependencies, startup_check
from swarms.store import AuditStore

log = logging.getLogger("swarms.server")

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(ROOT, "web")

MAX_CONTENT_CHARS = 200_000
SESSION_TTL_SECONDS = float(os.environ.get("SWARMS_SESSION_TTL", "3600"))
MAX_SESSIONS = int(os.environ.get("SWARMS_MAX_SESSIONS", "10000"))


# ---------------------------------------------------------------------------
# Session registry
# ---------------------------------------------------------------------------

class SessionRegistry:
    """Server-side sessions, with a TTL so ingested content does not
    accumulate for the lifetime of the process.

    ponytail: in-memory, so sessions are per-worker. Run one worker, or put a
    session-affinity hash in front of several. The swap point is this class
    backed by Redis; the interface is four methods.
    """

    def __init__(self, ttl: float = SESSION_TTL_SECONDS, limit: int = MAX_SESSIONS):
        self._sessions: dict[str, tuple[Session, float]] = {}
        self._lock = Lock()
        self.ttl = ttl
        self.limit = limit

    def put(self, session: Session) -> Session:
        with self._lock:
            self._reap()
            if len(self._sessions) >= self.limit:
                raise HTTPException(503, "session limit reached; sessions expire after "
                                         f"{int(self.ttl)}s or can be closed explicitly")
            self._sessions[session.id] = (session, time.monotonic())
        return session

    def get(self, session_id: str) -> Session:
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None:
                raise HTTPException(404, f"no open session '{session_id}' (unknown, or expired)")
            session, created = entry
            if time.monotonic() - created > self.ttl:
                del self._sessions[session_id]
                raise HTTPException(410, f"session '{session_id}' expired")
            return session

    def close(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def _reap(self) -> None:
        now = time.monotonic()
        for sid in [s for s, (_, t) in self._sessions.items() if now - t > self.ttl]:
            del self._sessions[sid]

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SessionRequest(BaseModel):
    principal: str = Field(..., max_length=128, description="Which principal in the policy is acting")
    user: str = Field("", max_length=256, description="End user this work is on behalf of")
    authority: list[str] | None = Field(
        None, description="Capability ceiling for this request. [] means this task authorizes nothing.")
    metadata: dict = Field(default_factory=dict)


class IngestRequest(BaseModel):
    content: str = Field(..., max_length=MAX_CONTENT_CHARS)
    source: str = Field(..., max_length=512, description="Where it came from, e.g. web:example.com/page")


class TrustRequest(BaseModel):
    value: str = Field(..., max_length=4096)
    source: str = Field("user_request", max_length=256)


class AuthorizeRequest(BaseModel):
    session_id: str | None = Field(None, description="Session to decide within. Omit for a stateless check.")
    action: str = Field(..., max_length=128)
    arguments: dict = Field(default_factory=dict)
    principal: str = Field("", max_length=128, description="Required when session_id is omitted")
    approval_id: str | None = None
    # Model-emitted calls are fail-closed: an argument that matches neither
    # ingested content nor a trusted value is untrusted. Set false only for
    # arguments your own code constructed.
    from_model: bool = True


class ApprovalDecision(BaseModel):
    approved: bool
    by: str = Field(..., max_length=256)
    note: str = Field("", max_length=2048)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def create_app(guard: Guard | None = None, ring: KeyRing | None = None) -> FastAPI:
    ring = ring if ring is not None else KeyRing.from_env()
    startup_check(ring)

    if guard is None:
        try:
            policy = Policy.discover()
        except PolicyError as exc:
            raise RuntimeError(f"cannot start: {exc}") from exc
        guard = Guard(policy, AuditStore(os.environ.get("SWARMS_DB", "swarms.db")),
                      enforce=os.environ.get("SWARMS_ENFORCE", "1") not in ("0", "false", "False"))

    sessions = SessionRegistry()
    require_key, _, _ = make_dependencies(ring)

    def require_writer(key: ApiKey = Depends(require_key)) -> ApiKey:
        if not key.can_write:
            raise HTTPException(403, f"key '{key.name}' is read-only")
        return key

    def require_admin(key: ApiKey = Depends(require_key)) -> ApiKey:
        if not key.can_admin:
            raise HTTPException(403, f"key '{key.name}' is not an admin key")
        return key

    app = FastAPI(
        title="SWARMS",
        version=__version__,
        description="Policy enforcement for AI agent tool calls: decisions, audit, approvals.",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.state.guard = guard
    app.state.sessions = sessions
    app.state.ring = ring

    origins = [o for o in os.environ.get("SWARMS_CORS_ORIGINS", "").split(",") if o.strip()]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins,
                           allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"])

    # -- health and metrics --------------------------------------------------

    @app.get("/api/health", tags=["ops"])
    def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "policy": {"name": guard.policy.name, "path": guard.policy.source_path,
                       "actions": len(guard.policy.actions), "principals": len(guard.policy.principals)},
            "enforcing": guard.enforcing,
            "auth": "enabled" if ring.enabled else "disabled",
            "open_sessions": len(sessions),
            "llm": llm.describe(),
        }

    @app.get("/metrics", response_class=PlainTextResponse, tags=["ops"])
    def metrics(key: ApiKey = Depends(require_key)) -> str:
        """Prometheus text format. Hand-rolled rather than pulling in a client
        library for six counters."""
        s = guard.store.stats(24)
        lines = [
            "# HELP swarms_decisions_total Decisions in the last 24h",
            "# TYPE swarms_decisions_total counter",
            f"swarms_decisions_total {s['total']}",
            "# HELP swarms_denied_total Denied decisions in the last 24h",
            "# TYPE swarms_denied_total counter",
            f"swarms_denied_total {s['denied']}",
            "# HELP swarms_decision_latency_microseconds Average decision latency",
            "# TYPE swarms_decision_latency_microseconds gauge",
            f"swarms_decision_latency_microseconds {s['avg_latency_us']}",
            "# HELP swarms_pending_approvals Approvals awaiting a human",
            "# TYPE swarms_pending_approvals gauge",
            f"swarms_pending_approvals {s['pending_approvals']}",
            "# HELP swarms_open_sessions Sessions held in memory",
            "# TYPE swarms_open_sessions gauge",
            f"swarms_open_sessions {len(sessions)}",
            "# HELP swarms_enforcing Whether decisions are enforced (1) or observed (0)",
            "# TYPE swarms_enforcing gauge",
            f"swarms_enforcing {int(guard.enforcing)}",
        ]
        for rule, count in s["denials_by_rule"].items():
            lines.append(f'swarms_denials_by_rule{{rule="{rule}"}} {count}')
        return "\n".join(lines) + "\n"

    # -- the enforcement API -------------------------------------------------

    @app.post("/v1/sessions", tags=["enforcement"], status_code=201)
    def open_session(req: SessionRequest, key: ApiKey = Depends(require_writer)) -> dict:
        session = guard.session(req.principal, user=req.user, authority=req.authority,
                                api_key=key.name, **req.metadata)
        sessions.put(session)
        return {"session_id": session.id, "principal": session.principal,
                "authority": session.authority.to_list() if session.authority else None,
                "expires_in": int(sessions.ttl)}

    @app.post("/v1/sessions/{session_id}/ingest", tags=["enforcement"])
    def ingest(session_id: str, req: IngestRequest, key: ApiKey = Depends(require_writer)) -> dict:
        session = sessions.get(session_id)
        session.ingest(req.content, source=req.source)
        return {"session_id": session_id, "source": req.source, "chars": len(req.content),
                "sources": len(session.sources)}

    @app.post("/v1/sessions/{session_id}/trust", tags=["enforcement"])
    def trust(session_id: str, req: TrustRequest, key: ApiKey = Depends(require_writer)) -> dict:
        session = sessions.get(session_id)
        session.trust(req.value, source=req.source)
        return {"session_id": session_id, "source": req.source}

    @app.get("/v1/sessions/{session_id}", tags=["enforcement"])
    def get_session(session_id: str, key: ApiKey = Depends(require_key)) -> dict:
        return sessions.get(session_id).to_dict()

    @app.delete("/v1/sessions/{session_id}", tags=["enforcement"])
    def close_session(session_id: str, key: ApiKey = Depends(require_writer)) -> dict:
        return {"closed": sessions.close(session_id)}

    @app.post("/v1/authorize", tags=["enforcement"])
    def authorize_call(req: AuthorizeRequest, key: ApiKey = Depends(require_writer)) -> dict:
        """Decide one tool call. This is the endpoint that matters."""
        if req.session_id:
            session = sessions.get(req.session_id)
        else:
            if not req.principal:
                raise HTTPException(422, "principal is required when no session_id is given")
            # A stateless check has no ingested content to trace against, so
            # it can only apply the authority rules. Say so in the response
            # rather than letting it look like a full grounding check.
            session = guard.session(req.principal, api_key=key.name)

        decision = session.check(req.action, req.arguments,
                                 unlabeled="untrusted" if req.from_model else "trusted")
        body = decision.to_dict()
        body["session_id"] = req.session_id
        body["grounding_available"] = bool(req.session_id and session.sources)
        if not body["grounding_available"]:
            body["note"] = ("no ingested content in this session, so provenance could not be checked; "
                            "only the authority rules were applied")

        if decision.needs_approval:
            if req.approval_id:
                spent, why = guard.store.consume_approval(req.approval_id, req.action, req.arguments)
                body["approval"] = {"id": req.approval_id, "accepted": spent, "reason": why}
                body["allowed"] = spent
                body["effect"] = Effect.ALLOW.value if spent else Effect.DENY.value
            else:
                approval = guard.store.open_approval(session.id, session.principal, req.action,
                                                     req.arguments, decision.reason)
                body["approval"] = {"id": approval.id, "status": "pending"}
        return body

    # -- console: audit, stats, approvals, policy ----------------------------

    @app.get("/api/decisions", tags=["console"])
    def decisions(
        limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
        effect: str | None = None, action: str | None = None, principal: str | None = None,
        session_id: str | None = None, search: str | None = None,
        key: ApiKey = Depends(require_key),
    ) -> dict:
        rows = guard.store.decisions(limit=limit, offset=offset, effect=effect, action=action,
                                     principal=principal, session_id=session_id, search=search)
        return {"count": len(rows), "decisions": rows}

    @app.get("/api/stats", tags=["console"])
    def stats(hours: int = Query(24, ge=1, le=720), key: ApiKey = Depends(require_key)) -> dict:
        return guard.store.stats(hours)

    @app.get("/api/approvals", tags=["console"])
    def approvals(status: str | None = "pending", key: ApiKey = Depends(require_key)) -> dict:
        return {"approvals": guard.store.approvals(status)}

    @app.post("/api/approvals/{approval_id}", tags=["console"])
    def resolve(approval_id: str, req: ApprovalDecision, key: ApiKey = Depends(require_admin)) -> dict:
        approval = guard.store.get_approval(approval_id)
        if approval is None:
            raise HTTPException(404, f"no approval '{approval_id}'")
        if approval.status != "pending":
            raise HTTPException(409, f"approval is already {approval.status}")
        resolved = guard.store.resolve_approval(approval_id, req.approved, req.by, req.note)
        return resolved.to_dict() if resolved else {}

    @app.get("/api/policy", tags=["console"])
    def get_policy(key: ApiKey = Depends(require_key)) -> dict:
        return {**guard.policy.to_dict(), "lint": guard.policy.lint(), "enforcing": guard.enforcing}

    @app.post("/api/policy/reload", tags=["console"])
    def reload_policy(key: ApiKey = Depends(require_admin)) -> dict:
        try:
            policy = guard.reload()
        except (PolicyError, ValueError) as exc:
            # The old policy stays loaded: a bad edit must not disarm the gateway.
            raise HTTPException(400, f"reload refused, keeping the policy already loaded: {exc}")
        return {"reloaded": True, "policy": policy.name, "actions": len(policy.actions),
                "lint": policy.lint()}

    @app.get("/api/redteam", tags=["console"])
    def redteam_report(key: ApiKey = Depends(require_key)) -> dict:
        path = os.path.join(WEB_DIR, "data", "redteam.json")
        if not os.path.exists(path):
            raise HTTPException(404, "no red-team report yet; run: swarms redteam")
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    @app.post("/api/redteam/run", tags=["console"])
    def redteam_run(key: ApiKey = Depends(require_admin)) -> dict:
        """Run the attack corpus against the loaded policy, now.

        Synchronous: the suite takes well under a second, and a job queue for
        something that fast would be machinery with nothing to do.
        """
        from swarms.redteam.runner import run_suite, write_report
        report = run_suite(Guard(guard.policy, AuditStore(
            os.environ.get("SWARMS_REDTEAM_DB", "redteam.db"))))
        write_report(report, os.path.join(ROOT, "redteam-report.json"),
                     web_dir=os.path.join(WEB_DIR, "data"))
        return report["summary"]

    # -- console static files ------------------------------------------------

    if os.path.isdir(WEB_DIR):
        @app.get("/", include_in_schema=False)
        def console() -> FileResponse:
            return FileResponse(os.path.join(WEB_DIR, "index.html"))

        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="console")

    return app


def __getattr__(name: str):
    """Build the default app only when something actually asks for it.

    `uvicorn swarms.server.app:app` does a getattr, so this still works as an
    ASGI target, while `from swarms.server.app import create_app` no longer
    opens a database and binds a policy as a side effect of importing.
    """
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
