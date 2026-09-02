"""Audit persistence and the approval queue."""
from __future__ import annotations

import concurrent.futures

from swarms.policy import Decision, Effect, Rule
from swarms.store import AuditStore, args_fingerprint


def _decision(effect=Effect.DENY, action="send_email", allowed=False):
    return Decision(
        effect=effect, rule=Rule.GROUNDING, reason="because", action=action,
        principal="mailer", offending_arg="to", offending_span="attacker@evil.example",
        offending_provenance=("ingest:web",), arg_labels={"to": "UNTRUSTED"}, enforced=True,
    )


def test_decisions_round_trip(store):
    store.record(_decision(), session_id="s1", latency_us=42)
    row = store.decisions(limit=1)[0]
    assert row["action"] == "send_email"
    assert row["offending_span"] == "attacker@evil.example"
    assert row["provenance"] == ["ingest:web"]
    assert row["arg_labels"] == {"to": "UNTRUSTED"}
    assert row["latency_us"] == 42


def test_filters_narrow_the_result(store):
    store.record(_decision(action="send_email"), session_id="s1")
    store.record(_decision(effect=Effect.ALLOW, action="run_command", allowed=True), session_id="s2")

    assert len(store.decisions(action="send_email")) == 1
    assert len(store.decisions(session_id="s2")) == 1
    assert len(store.decisions(search="evil.example")) == 2
    assert len(store.decisions(search="nothing-matches-this")) == 0


def test_stats_summarize_the_window(store):
    for _ in range(3):
        store.record(_decision(), latency_us=10)
    store.record(_decision(effect=Effect.ALLOW), latency_us=20)

    stats = store.stats(24)
    assert stats["total"] == 4
    assert stats["allowed"] == 1
    # denials_by_rule counts refusals only, so the allowed one is excluded.
    assert stats["denials_by_rule"]["grounding"] == 3
    assert stats["by_action"][0]["action"] == "send_email"


def test_approval_lifecycle(store):
    approval = store.open_approval("s1", "billing", "charge_card", {"amount": "100"}, "needs a human")
    assert approval.status == "pending"
    assert store.approvals("pending")[0]["id"] == approval.id

    store.resolve_approval(approval.id, True, by="alice", note="checked")
    assert store.get_approval(approval.id).status == "approved"

    spent, why = store.consume_approval(approval.id, "charge_card", {"amount": "100"})
    assert spent and why == "approved"
    assert store.get_approval(approval.id).status == "used"


def test_consuming_twice_fails_the_second_time(store):
    approval = store.open_approval("s1", "billing", "charge_card", {"amount": "100"}, "r")
    store.resolve_approval(approval.id, True, by="alice")
    assert store.consume_approval(approval.id, "charge_card", {"amount": "100"})[0]
    assert store.consume_approval(approval.id, "charge_card", {"amount": "100"}) == (False, "that approval has already been used")


def test_two_reviewers_racing_cannot_both_resolve(store):
    approval = store.open_approval("s1", "billing", "charge_card", {"amount": "100"}, "r")
    store.resolve_approval(approval.id, True, by="alice")
    store.resolve_approval(approval.id, False, by="bob")
    assert store.get_approval(approval.id).resolved_by == "alice", "the first resolution stands"


def test_fingerprint_ignores_key_order_but_not_values():
    assert args_fingerprint({"a": 1, "b": 2}) == args_fingerprint({"b": 2, "a": 1})
    assert args_fingerprint({"amount": "100"}) != args_fingerprint({"amount": "101"})


def test_pending_approvals_expire(store):
    """An unanswered request to charge a card is a denial, not a standing
    invitation. Backdated rather than slept on, so the test exercises the
    real query without racing the clock."""
    approval = store.open_approval("s1", "billing", "charge_card", {}, "r")
    conn = store._conn()
    conn.execute("UPDATE approvals SET ts = '2020-01-01T00:00:00.000Z' WHERE id = ?", (approval.id,))
    conn.commit()

    assert store.expire_approvals(older_than_minutes=60) == 1
    assert store.approvals("pending") == []
    assert store.get_approval(approval.id).status == "expired"


def test_expiring_leaves_fresh_approvals_alone(store):
    approval = store.open_approval("s1", "billing", "charge_card", {}, "r")
    assert store.expire_approvals(older_than_minutes=60) == 0
    assert store.get_approval(approval.id).status == "pending"


def test_concurrent_writers_do_not_lose_records(tmp_path):
    """Each thread gets its own connection; a shared one raises or corrupts."""
    store = AuditStore(str(tmp_path / "concurrent.db"))

    def write(i):
        store.record(_decision(), session_id=f"s{i}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(80)))

    assert store.stats(24)["total"] == 80


def test_consume_is_atomic_under_concurrency(tmp_path):
    """Two workers spending the same approval must not both succeed: that is
    the difference between one charge and two."""
    store = AuditStore(str(tmp_path / "race.db"))
    approval = store.open_approval("s1", "billing", "charge_card", {"amount": "100"}, "r")
    store.resolve_approval(approval.id, True, by="alice")

    def spend(_):
        return store.consume_approval(approval.id, "charge_card", {"amount": "100"})[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(spend, range(8)))

    assert sum(outcomes) == 1, f"expected exactly one winner, got {sum(outcomes)}"
