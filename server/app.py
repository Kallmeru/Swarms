"""SWARMS HTTP API and static host.

The demo used to be a folder of pre-generated JSON: honest about what it
showed, but it could only ever replay runs someone had already done. This
serves the same frontend and runs the pipeline live, so a visitor can paste
their own poisoned document and watch the policy engine decide about text
nobody wrote a fixture for. Being able to try to break it yourself is the
difference between a claim and a demonstration.

    uvicorn server.app:app --reload
    python -m server                     # same thing, reads PORT

Endpoints:
    GET  /api/health        build info, whether a live model is wired up
    GET  /api/attacks       the fixture corpus
    GET  /api/benchmark     last benchmark aggregates
    POST /api/run           run one fixture, or arbitrary text, both modes
    GET  /                  the frontend
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from collections import deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from core import __version__, llm_client
from swarm.fixtures import (
    DEFAULT_TASK_RECIPIENT,
    categories,
    custom_fixture,
    load_fixture,
    load_fixtures,
)
from swarm.run_swarm import run_both
from swarm.tools import MAX_DOCUMENT_CHARS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(ROOT, "web")
BENCHMARK_SUMMARY = os.path.join(WEB_DIR, "data", "benchmark_summary.json")

MAX_TASK_CHARS = 2_000
RATE_LIMIT_RUNS = int(os.environ.get("SWARMS_RATE_LIMIT", "30"))
RATE_LIMIT_WINDOW = 60.0

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")

app = FastAPI(
    title="SWARMS",
    version=__version__,
    description="Taint tracking and capability attenuation for multi-agent LLM pipelines.",
)

# Open CORS on purpose: every endpoint is read-only with respect to the
# server, takes no credentials and returns nobody's data. It is what lets the
# static GitHub Pages build talk to a deployed API instead of only replaying
# canned traces. Narrow it with SWARMS_CORS_ORIGINS if you host something
# that does hold state.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in os.environ.get("SWARMS_CORS_ORIGINS", "*").split(",") if o],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class _RateLimiter:
    """Per-client sliding window over the one endpoint that does real work.

    ponytail: in-process, so it limits per worker rather than per cluster.
    That is the right size for one container; put a shared counter behind it
    only when there is more than one.
    """

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            # Drop idle clients so a long-lived process does not accumulate
            # an entry per IP that ever visited.
            if len(self._hits) > 4096:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True


_limiter = _RateLimiter(RATE_LIMIT_RUNS, RATE_LIMIT_WINDOW)


class RunRequest(BaseModel):
    """Either name a fixture, or supply your own document. Not both."""

    attack_id: str | None = Field(None, max_length=64)
    document_text: str | None = Field(None, max_length=MAX_DOCUMENT_CHARS)
    user_task: str | None = Field(None, max_length=MAX_TASK_CHARS)
    task_recipient: str = Field(DEFAULT_TASK_RECIPIENT, max_length=254)
    authorize_send: bool = True

    @model_validator(mode="after")
    def _exactly_one_source(self) -> "RunRequest":
        has_doc = bool(self.document_text and self.document_text.strip())
        if bool(self.attack_id) == has_doc:
            raise ValueError("provide exactly one of attack_id or document_text")
        if not EMAIL_RE.match(self.task_recipient):
            raise ValueError("task_recipient must be an email address")
        return self


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "llm": llm_client.describe(),
        "fixtures": len(load_fixtures()),
        "enforcement": "deterministic: taint labels + capability lookup, no model call on the enforcement path",
    }


@app.get("/api/attacks")
def attacks() -> dict:
    fixtures = load_fixtures()
    return {
        "count": len(fixtures),
        "categories": categories(fixtures),
        "fixtures": [f.summary() for f in fixtures],
    }


@app.get("/api/benchmark")
def benchmark() -> dict:
    if not os.path.exists(BENCHMARK_SUMMARY):
        raise HTTPException(404, "no benchmark results yet, run: python -m benchmark.run_benchmark")
    with open(BENCHMARK_SUMMARY, encoding="utf-8") as f:
        return json.load(f)


@app.post("/api/run")
def run(req: RunRequest, request: Request) -> dict:
    """Run the pipeline twice on the same input, unprotected then protected.

    Declared `def`, not `async def`, so FastAPI runs it in the threadpool: the
    pipeline is synchronous and would otherwise block the event loop for every
    other request. It is safe there because run state lives in contextvars,
    which are per-task and copied into the worker thread.
    """
    if not _limiter.check(request.client.host if request.client else "unknown"):
        raise HTTPException(429, f"rate limit: {RATE_LIMIT_RUNS} runs per minute")

    if req.attack_id:
        try:
            fixture = load_fixture(req.attack_id)
        except KeyError:
            raise HTTPException(404, f"unknown attack_id: {req.attack_id}")
    else:
        try:
            fixture = custom_fixture(
                document_text=req.document_text or "",
                user_task=req.user_task or "",
                task_recipient=req.task_recipient,
                authorized_actions=("send_email",) if req.authorize_send else (),
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    # persist=False: an API that wrote runs/<uuid>/events.jsonl per request
    # would fill the disk with traces nobody reads. The events come back in
    # the response instead.
    result = run_both(fixture, run_prefix=f"api_{uuid.uuid4().hex[:8]}", persist=False)
    result["live_llm"] = llm_client.available()
    return result


# Mounted last so it never shadows /api/*. html=True serves index.html at /
# and gives the two-page site (dashboard, then os.html) working URLs.
if os.path.isdir(WEB_DIR):
    @app.get("/os")
    def os_page() -> FileResponse:
        return FileResponse(os.path.join(WEB_DIR, "os.html"))

    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
