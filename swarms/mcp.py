"""MCP gateway: grounding enforcement at the tool-call boundary.

The Model Context Protocol defines how a server authenticates a client. It
does not define which tools an identity may call, or whether a particular
call should execute — the spec's own authorization section covers authN, and
the gap it leaves is the confused-deputy one: an agent with legitimate,
broadly-scoped credentials is talked into using them by something it read.

This gateway sits between the agent and its MCP servers and closes that gap
without touching the agent. Point the client's server URL here instead of at
the upstream, and every `tools/call` is decided before it is forwarded.

The part that makes it drop-in is the return path. **Every tool result the
gateway relays is automatically ingested as untrusted content for that
session.** So an agent that reads a web page through one tool and then calls
another tool with an argument lifted out of that page is refused, with no SDK
calls, no decorators, and no change to the agent's code. The provenance the
enforcement needs is recovered from traffic the gateway is already carrying.

Targets MCP revision 2026-07-28: stateless request/response, `Mcp-Method` and
`Mcp-Name` headers so a gateway can route and authorize without parsing the
body, and Multi Round-Trip Requests for anything needing human input.
"""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = "2026-07-28"

# JSON-RPC reserved range ends at -32000; application errors live above it.
ERROR_DENIED = -32040
ERROR_UPSTREAM = -32050

# Methods that carry a side effect worth deciding. `tools/list` and the
# various reads are disclosure, not action, and are relayed untouched.
GUARDED_METHODS = ("tools/call",)

DEFAULT_TIMEOUT = 30.0
MAX_SESSIONS = 10_000
SESSION_TTL_SECONDS = 3600.0


@dataclass
class GatewaySession:
    """Per-agent trust context, correlated across stateless MCP requests."""

    session: Any                      # swarms.Session
    created: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    calls: int = 0
    ingested: int = 0


class SessionCache:
    """Bounded, TTL'd map of correlation key -> session.

    MCP 2026-07-28 dropped `Mcp-Session-Id`, so correlation is ours to do and
    the store is ours to bound. An unbounded dict keyed by a client-supplied
    header is a memory-exhaustion primitive handed to whoever can reach the
    gateway.
    """

    def __init__(self, maxsize: int = MAX_SESSIONS, ttl: float = SESSION_TTL_SECONDS):
        self.maxsize, self.ttl = maxsize, ttl
        self._items: dict[str, GatewaySession] = {}
        self._lock = threading.Lock()

    def get_or_create(self, key: str, factory) -> GatewaySession:
        now = time.time()
        with self._lock:
            entry = self._items.get(key)
            if entry is not None and now - entry.last_used <= self.ttl:
                entry.last_used = now
                return entry

            # Expired or absent: a stale session must not keep vouching for
            # content ingested an hour ago under a key someone else now holds.
            self._evict(now)
            entry = GatewaySession(session=factory())
            self._items[key] = entry
            return entry

    def _evict(self, now: float) -> None:
        for key in [k for k, v in self._items.items() if now - v.last_used > self.ttl]:
            del self._items[key]
        if len(self._items) >= self.maxsize:
            oldest = sorted(self._items.items(), key=lambda kv: kv[1].last_used)
            for key, _ in oldest[: max(1, len(self._items) - self.maxsize + 1)]:
                del self._items[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class MCPGateway:
    """Decides, forwards, and taints. Transport-agnostic on purpose: `handle`
    takes already-parsed pieces and returns a body, so it is testable without
    standing up HTTP or an upstream server."""

    def __init__(
        self,
        guard,
        upstream: str = "",
        principal: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        console_url: str = "",
        strict: bool = False,
    ):
        self.guard = guard
        self.upstream = upstream.rstrip("/")
        self.principal = principal
        self.timeout = timeout
        self.console_url = console_url.rstrip("/")
        # How to treat an argument that matches neither ingested content nor
        # anything the human declared.
        #
        #   strict=False (default)  trusted. Only values traceable to content
        #       the agent read are refused. This is what makes the gateway
        #       genuinely drop-in: the agent's *first* call happens before
        #       anything has been ingested, so under the opposite default
        #       every session would begin by denying legitimate work, and the
        #       gateway would be removed within a day.
        #
        #   strict=True  untrusted. Nothing runs unless it traces to the
        #       human's request, so the client must declare that request with
        #       an `X-Swarms-Task` header (or the sessions API). Stronger, and
        #       it costs one header.
        self.strict = strict
        self.sessions = SessionCache()

    # -- correlation ---------------------------------------------------------

    def session_key(self, headers: dict, body: dict) -> str:
        """Which trust context this request belongs to.

        Explicit header first, then the client identity the spec puts in
        `_meta`, then a per-principal fallback. The fallback is deliberately
        coarse rather than per-request: a fresh session every call would have
        nothing ingested to compare against, which would look like everything
        passing.
        """
        explicit = headers.get("x-swarms-session")
        if explicit:
            return f"explicit:{explicit[:128]}"

        meta = (body.get("_meta") or {}) if isinstance(body, dict) else {}
        client = meta.get("client") if isinstance(meta, dict) else None
        if isinstance(client, dict) and client.get("name"):
            return f"client:{str(client['name'])[:128]}"

        return f"principal:{self.principal or 'default'}"

    def _session_for(self, key: str, task: str = "", user: str = ""):
        entry = self.sessions.get_or_create(
            key, lambda: self.guard.session(self.principal, user=user, transport="mcp"))
        if task:
            # The human's own request, declared by the client. Everything in
            # it is trusted, which is what lets strict mode work: the values
            # the user actually asked for become attributable.
            entry.session.trust(task, source="user_request:mcp")
            for token in _tokens(task):
                entry.session.trust(token, source="user_request:mcp")
        return entry

    # -- the request path ----------------------------------------------------

    def handle(self, body: dict, headers: dict | None = None) -> tuple[int, dict]:
        """Decide and relay one MCP request. Returns (http_status, body)."""
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        method = headers.get("mcp-method") or body.get("method") or ""
        name = headers.get("mcp-name") or (body.get("params") or {}).get("name") or ""
        request_id = body.get("id")

        if method not in GUARDED_METHODS:
            # Not an action. Relay it, and treat whatever comes back as
            # untrusted content, because a tool *listing* is attacker-
            # influenceable too: a malicious server names its tool
            # "send_email_urgent_ignore_policy".
            status, response = self._forward(body, headers)
            self._absorb(self.session_key(headers, body), response, f"mcp:{method or 'unknown'}")
            return status, response

        params = body.get("params") or {}
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return 200, _rpc_error(request_id, ERROR_DENIED,
                                   "tools/call arguments must be an object")

        key = self.session_key(headers, body)
        entry = self._session_for(key, task=headers.get("x-swarms-task", "")[:4000])
        entry.calls += 1

        approval_id = self._approval_from_state(params)
        decision = entry.session.check(
            name, arguments, unlabeled="untrusted" if self.strict else "trusted")

        if decision.needs_approval:
            # An echoed requestState may carry an approval a human has since
            # granted. Spending it is the check: it succeeds only for this
            # action, with these exact arguments, exactly once.
            granted, why = (False, decision.reason)
            if approval_id:
                granted, why = self.guard.store.consume_approval(approval_id, name, arguments)
            if not granted:
                return self._request_approval(entry, request_id, name, arguments, decision, why)
            # granted: fall through and forward

        elif not decision.allowed:
            return 200, _rpc_error(
                request_id, ERROR_DENIED,
                f"SWARMS refused this call: {decision.reason}",
                data={
                    "swarms": {
                        "action": name,
                        "effect": decision.effect.value,
                        "rule": decision.rule.value,
                        "offending_argument": decision.offending_arg,
                        "offending_value": decision.offending_span,
                        "provenance": list(decision.offending_provenance),
                        "remedy": _remedy(decision),
                    }
                },
            )

        status, response = self._forward(body, headers)
        self._absorb(key, response, f"mcp:tools/call:{name}")
        return status, response

    # -- tainting the return path -------------------------------------------

    def _absorb(self, key: str, response: dict, source: str) -> None:
        """Ingest whatever came back as untrusted content.

        This is the whole reason the gateway can enforce grounding for an
        agent that knows nothing about SWARMS: the values a later call will
        use are, by definition, in the results of earlier ones.
        """
        text = _result_text(response)
        if not text:
            return
        entry = self.sessions.get_or_create(
            key, lambda: self.guard.session(self.principal, transport="mcp"))
        entry.session.ingest(text, source=source)
        entry.ingested += 1

    # -- approvals, via the protocol's own input-request mechanism -----------

    def _request_approval(self, entry, request_id, name, arguments, decision, reason):
        """Ask for a human using MRTR rather than failing the call.

        The elicitation is how the person is *notified*; it is not what
        authorizes. On retry the gateway checks the approval store, so an
        agent that fabricates an affirmative answer gets nothing — the
        approval has to have been resolved by a human through the console or
        the approvals API.
        """
        approval = self.guard.store.open_approval(
            entry.session.id, entry.session.principal, name, arguments, decision.reason)

        state = base64.b64encode(json.dumps({
            "swarms_approval_id": approval.id, "action": name,
        }).encode()).decode()

        message = f"'{name}' needs human approval before it can run. {reason}"
        if self.console_url:
            message += f" Approve or refuse at {self.console_url}/#approvals (id {approval.id})."

        return 200, {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resultType": "input_required",
                "inputRequests": {
                    "swarms_approval": {
                        "type": "elicitation",
                        "message": message,
                        "schema": {"type": "boolean"},
                    }
                },
                "requestState": state,
            },
        }

    def _approval_from_state(self, params: dict) -> str | None:
        """Recover the approval id a client echoed back in `requestState`."""
        state = params.get("requestState")
        if not state:
            return None
        try:
            decoded = json.loads(base64.b64decode(state).decode())
        except (ValueError, TypeError):
            return None
        approval_id = decoded.get("swarms_approval_id")
        return approval_id if isinstance(approval_id, str) else None

    # -- upstream ------------------------------------------------------------

    def _forward(self, body: dict, headers: dict) -> tuple[int, dict]:
        if not self.upstream:
            return 200, _rpc_error(body.get("id"), ERROR_UPSTREAM,
                                   "no upstream MCP server configured on this gateway")

        payload = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.upstream, data=payload, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("MCP-Protocol-Version", headers.get("mcp-protocol-version", PROTOCOL_VERSION))
        for header in ("mcp-method", "mcp-name", "authorization"):
            if headers.get(header):
                request.add_header(header, headers[header])

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            return 200, _rpc_error(body.get("id"), ERROR_UPSTREAM,
                                   f"upstream returned {exc.code}", data={"body": detail})
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return 200, _rpc_error(body.get("id"), ERROR_UPSTREAM, f"upstream unreachable: {exc}")


def _tokens(task: str) -> list[str]:
    """Individual values worth trusting out of the user's request.

    An agent rarely passes the whole sentence as an argument; it passes the
    address or the path inside it. Only reasonably long, non-prose tokens are
    taken, so that trusting a request does not trust every common word in it.
    """
    import re
    candidates = re.findall(r"[^\s\"'<>(),;]{6,}", task)
    return [c.strip(".,;:!?") for c in candidates if any(ch in c for ch in "@:/._-")]


def _rpc_error(request_id: Any, code: int, message: str, data: dict | None = None) -> dict:
    """A JSON-RPC error, which every MCP client already knows how to surface.

    Returned with HTTP 200: a transport-level failure would make clients
    retry or fail over, and a policy refusal is a considered answer, not an
    outage.
    """
    error: dict = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _result_text(response: dict) -> str:
    """Flatten an MCP result into text for ingestion.

    Deliberately greedy: structured fields, text blocks and anything left
    over all count, because an injected instruction does not care which
    field of the response it arrives in.
    """
    if not isinstance(response, dict):
        return ""
    result = response.get("result")
    if result is None:
        return ""
    if isinstance(result, str):
        return result

    parts: list[str] = []
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("data") or ""))
            else:
                parts.append(str(block))

    if not parts:
        try:
            return json.dumps(result)[:100_000]
        except (TypeError, ValueError):
            return str(result)[:100_000]
    return "\n".join(p for p in parts if p)[:100_000]


def _remedy(decision) -> str:
    """What the operator would actually do about this refusal. A denial that
    does not say how to legitimately proceed gets worked around by disabling
    the control."""
    rule = decision.rule.value
    if rule == "grounding":
        return (f"If {decision.offending_arg!r} legitimately comes from content here, add a declassify "
                f"rule for it (allowlist or pattern) in the policy. Otherwise the agent is being "
                f"redirected by something it read.")
    if rule == "capability":
        return "Grant the principal the capability this action needs, or route it to one that holds it."
    if rule == "run_authority":
        return "The request that opened this session did not ask for this capability. Widen its authority."
    if rule == "unknown_action":
        return "Declare this tool under actions: in the policy, naming its control arguments."
    if rule == "unknown_principal":
        return "Declare this principal in the policy, or correct the name."
    return "See the policy file."
