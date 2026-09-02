"""Durable audit trail and approval queue, on SQLite.

Two things a security control has to be able to answer months later: what did
you decide, and who approved this. A JSON-lines file in a directory answers
neither without a grep, and loses both when the container restarts.

SQLite rather than Postgres because this is a sidecar next to an application,
not a platform: no server to run, no migration story to own, a single file to
back up, and it is already in the standard library. It handles the write
volume of a decision log comfortably. When an operator outgrows one file the
interface here is narrow enough to reimplement.

ponytail: one file, WAL mode, thread-local connections. Concurrent *writers*
across processes will serialize on SQLite's lock; at gateway volumes that is
fine, and the swap point is a real database behind this same class.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    session_id      TEXT,
    principal       TEXT,
    action          TEXT,
    effect          TEXT,
    rule            TEXT,
    reason          TEXT,
    allowed         INTEGER,
    enforced        INTEGER,
    offending_arg   TEXT,
    offending_span  TEXT,
    provenance      TEXT,
    arg_labels      TEXT,
    policy          TEXT,
    latency_us      INTEGER,
    metadata        TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts      ON decisions(ts DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_effect  ON decisions(effect);
CREATE INDEX IF NOT EXISTS idx_decisions_action  ON decisions(action);
CREATE INDEX IF NOT EXISTS idx_decisions_session ON decisions(session_id);

CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,
    ts           TEXT NOT NULL,
    session_id   TEXT,
    principal    TEXT,
    action       TEXT,
    args         TEXT,
    args_hash    TEXT,
    reason       TEXT,
    status       TEXT NOT NULL,
    resolved_ts  TEXT,
    resolved_by  TEXT,
    note         TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, ts DESC);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Approval:
    id: str
    ts: str
    session_id: str
    principal: str
    action: str
    args: dict
    reason: str
    # pending -> approved -> used, or pending -> denied / expired. "used" is
    # what makes an approval single-use: a human approving one charge has not
    # approved every later charge that reuses the same id.
    status: str
    args_hash: str = ""
    resolved_ts: str | None = None
    resolved_by: str | None = None
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "ts": self.ts, "session_id": self.session_id,
            "principal": self.principal, "action": self.action, "args": self.args,
            "reason": self.reason, "status": self.status, "resolved_ts": self.resolved_ts,
            "resolved_by": self.resolved_by, "note": self.note, "args_hash": self.args_hash,
        }


class AuditStore:
    def __init__(self, path: str = "swarms.db"):
        self.path = path
        if os.path.dirname(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        with self._init_lock:
            conn = self._conn()
            conn.executescript(SCHEMA)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        """One connection per thread. sqlite3 connections are not safe to
        share across threads, and the gateway serves requests on a threadpool.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            # WAL so a long-running read (the console loading the audit view)
            # does not block decision writes.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- decisions -----------------------------------------------------------

    def record(self, decision, session_id: str = "", latency_us: int = 0, metadata: dict | None = None) -> str:
        record_id = uuid.uuid4().hex
        conn = self._conn()
        conn.execute(
            "INSERT INTO decisions (id, ts, session_id, principal, action, effect, rule, reason,"
            " allowed, enforced, offending_arg, offending_span, provenance, arg_labels, policy,"
            " latency_us, metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record_id, _now(), session_id, decision.principal, decision.action,
                decision.effect.value, decision.rule.value, decision.reason,
                int(decision.allowed), int(decision.enforced),
                decision.offending_arg, decision.offending_span,
                json.dumps(list(decision.offending_provenance)),
                json.dumps(decision.arg_labels),
                (metadata or {}).get("policy", ""),
                latency_us, json.dumps(metadata or {}),
            ),
        )
        conn.commit()
        return record_id

    def decisions(
        self,
        limit: int = 100,
        offset: int = 0,
        effect: str | None = None,
        action: str | None = None,
        principal: str | None = None,
        session_id: str | None = None,
        since: str | None = None,
        search: str | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        for column, value in (("effect", effect), ("action", action),
                              ("principal", principal), ("session_id", session_id)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if search:
            # Deliberately narrow: reason and the offending value are the two
            # fields an incident actually gets searched by.
            clauses.append("(reason LIKE ? OR offending_span LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn().execute(
            f"SELECT * FROM decisions {where} ORDER BY ts DESC, rowid DESC LIMIT ? OFFSET ?",
            (*params, min(limit, 1000), offset),
        ).fetchall()
        return [_row_to_decision(r) for r in rows]

    def stats(self, hours: int = 24) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(
            timespec="milliseconds").replace("+00:00", "Z")
        conn = self._conn()

        totals = conn.execute(
            "SELECT COUNT(*) n, SUM(allowed) allowed, AVG(latency_us) avg_us,"
            " MAX(latency_us) max_us FROM decisions WHERE ts >= ?", (since,)).fetchone()
        by_effect = conn.execute(
            "SELECT effect, COUNT(*) n FROM decisions WHERE ts >= ? GROUP BY effect", (since,)).fetchall()
        by_rule = conn.execute(
            "SELECT rule, COUNT(*) n FROM decisions WHERE ts >= ? AND allowed = 0"
            " GROUP BY rule ORDER BY n DESC", (since,)).fetchall()
        by_action = conn.execute(
            "SELECT action, COUNT(*) n, SUM(1 - allowed) denied FROM decisions WHERE ts >= ?"
            " GROUP BY action ORDER BY n DESC LIMIT 20", (since,)).fetchall()
        pending = conn.execute("SELECT COUNT(*) n FROM approvals WHERE status = 'pending'").fetchone()

        total = totals["n"] or 0
        allowed = totals["allowed"] or 0
        return {
            "window_hours": hours,
            "total": total,
            "allowed": allowed,
            "denied": total - allowed,
            "deny_rate": round((total - allowed) / total, 4) if total else 0.0,
            "avg_latency_us": round(totals["avg_us"] or 0, 1),
            "max_latency_us": totals["max_us"] or 0,
            "by_effect": {r["effect"]: r["n"] for r in by_effect},
            "denials_by_rule": {r["rule"]: r["n"] for r in by_rule},
            "by_action": [{"action": r["action"], "total": r["n"], "denied": r["denied"]} for r in by_action],
            "pending_approvals": pending["n"] or 0,
        }

    # -- approvals -----------------------------------------------------------

    def open_approval(self, session_id: str, principal: str, action: str, args: dict, reason: str) -> Approval:
        approval = Approval(
            id=uuid.uuid4().hex, ts=_now(), session_id=session_id, principal=principal,
            action=action, args=args, reason=reason, status="pending",
            args_hash=args_fingerprint(args),
        )
        conn = self._conn()
        conn.execute(
            "INSERT INTO approvals (id, ts, session_id, principal, action, args, args_hash, reason, status)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (approval.id, approval.ts, session_id, principal, action,
             json.dumps(args, default=str), approval.args_hash, reason, "pending"),
        )
        conn.commit()
        return approval

    def consume_approval(self, approval_id: str, action: str, args: dict) -> tuple[bool, str]:
        """Spend an approval, once, for exactly the call it was granted for.

        Bound to the action and to a fingerprint of the arguments, because an
        approval that is not bound to its arguments approves a different call
        than the one the human read: approve a 1.00 charge, execute 10000.00.
        The UPDATE is the check, so two concurrent calls cannot both spend it.
        """
        expected = args_fingerprint(args)
        conn = self._conn()
        cursor = conn.execute(
            "UPDATE approvals SET status = 'used', resolved_ts = COALESCE(resolved_ts, ?)"
            " WHERE id = ? AND status = 'approved' AND action = ? AND args_hash = ?",
            (_now(), approval_id, action, expected),
        )
        conn.commit()
        if cursor.rowcount:
            return True, "approved"

        row = conn.execute("SELECT status, action, args_hash FROM approvals WHERE id = ?",
                           (approval_id,)).fetchone()
        if row is None:
            return False, "no such approval"
        if row["status"] == "used":
            return False, "that approval has already been used"
        if row["status"] != "approved":
            return False, f"approval is {row['status']}"
        if row["action"] != action:
            return False, f"approval was granted for '{row['action']}', not '{action}'"
        return False, "the arguments differ from the ones that were approved"

    def get_approval(self, approval_id: str) -> Approval | None:
        row = self._conn().execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return _row_to_approval(row) if row else None

    def resolve_approval(self, approval_id: str, approved: bool, by: str, note: str = "") -> Approval | None:
        conn = self._conn()
        # Guarded on status so two reviewers racing cannot both resolve it and
        # the second one silently overwrite the first.
        cursor = conn.execute(
            "UPDATE approvals SET status = ?, resolved_ts = ?, resolved_by = ?, note = ?"
            " WHERE id = ? AND status = 'pending'",
            ("approved" if approved else "denied", _now(), by, note, approval_id),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return self.get_approval(approval_id)  # already resolved, or unknown
        return self.get_approval(approval_id)

    def approvals(self, status: str | None = "pending", limit: int = 100) -> list[dict]:
        conn = self._conn()
        if status:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = ? ORDER BY ts DESC LIMIT ?",
                (status, min(limit, 1000))).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM approvals ORDER BY ts DESC LIMIT ?", (min(limit, 1000),)).fetchall()
        return [_row_to_approval(r).to_dict() for r in rows]

    def expire_approvals(self, older_than_minutes: int = 60) -> int:
        """Pending approvals do not stay pending forever: an unanswered
        request to charge a card is a denial, not an open invitation."""
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)).isoformat(
            timespec="milliseconds").replace("+00:00", "Z")
        conn = self._conn()
        cursor = conn.execute(
            "UPDATE approvals SET status = 'expired', resolved_ts = ?, resolved_by = 'system'"
            " WHERE status = 'pending' AND ts < ?", (_now(), cutoff))
        conn.commit()
        return cursor.rowcount


def _row_to_decision(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"], "ts": row["ts"], "session_id": row["session_id"],
        "principal": row["principal"], "action": row["action"], "effect": row["effect"],
        "rule": row["rule"], "reason": row["reason"], "allowed": bool(row["allowed"]),
        "enforced": bool(row["enforced"]), "offending_arg": row["offending_arg"],
        "offending_span": row["offending_span"],
        "provenance": json.loads(row["provenance"] or "[]"),
        "arg_labels": json.loads(row["arg_labels"] or "{}"),
        "latency_us": row["latency_us"],
    }


def args_fingerprint(args: dict) -> str:
    """Stable hash of the argument values an approval was granted for.
    sort_keys so key order cannot change the fingerprint, default=str so an
    unserializable value degrades to its repr rather than raising."""
    import hashlib
    payload = json.dumps(args, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _row_to_approval(row: sqlite3.Row) -> Approval:
    return Approval(
        id=row["id"], ts=row["ts"], session_id=row["session_id"], principal=row["principal"],
        action=row["action"], args=json.loads(row["args"] or "{}"), reason=row["reason"],
        status=row["status"], resolved_ts=row["resolved_ts"], resolved_by=row["resolved_by"],
        note=row["note"], args_hash=row["args_hash"] or "",
    )
