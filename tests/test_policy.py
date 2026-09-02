"""Policy loading and the decision function.

Weighted toward the failures that would be silent: a policy that loads but
enforces nothing, a rule that stops firing, a value that quietly loses its
label. A test that only checks the happy path would pass against a system
that had stopped working.
"""
from __future__ import annotations

import concurrent.futures

import pytest

from swarms.capability import Capability, run_policy
from swarms.config import Policy, PolicyError
from swarms.policy import Effect, Rule, authorize, is_untrusted
from swarms.taint import TaintedValue

TRUSTED = TaintedValue.trusted("boss@corp.example", "user_request")
UNTRUSTED = TaintedValue.untrusted("attacker@evil.example", "ingest:web")
UNTRUSTED_BODY = TaintedValue.untrusted("quoted from the page", "ingest:web")


# --- loading ----------------------------------------------------------------

def test_action_without_control_args_is_rejected():
    """Forgetting the line is the mistake this catches: an action with nothing
    grounded accepts a target chosen by untrusted content."""
    with pytest.raises(PolicyError, match="control_args"):
        Policy.from_dict({
            "actions": {"send_email": {"capability": "email.send"}},
            "principals": {"m": {"capabilities": ["email.send"]}},
        })


def test_explicitly_empty_control_args_is_allowed_but_flagged():
    policy = Policy.from_dict({
        "actions": {"ping": {"capability": "net.ping", "control_args": []}},
        "principals": {"m": {"capabilities": ["net.ping"]}},
    })
    assert "nothing about this action is grounded" in " ".join(policy.lint())


def test_argument_cannot_be_both_control_and_data():
    with pytest.raises(PolicyError, match="both control and data"):
        Policy.from_dict({
            "actions": {"x": {"capability": "c", "control_args": ["to"], "data_args": ["to"]}},
            "principals": {"m": {"capabilities": ["c"]}},
        })


def test_action_no_principal_can_ever_call_is_rejected():
    """A policy that silently contains an unreachable action is a policy
    someone has misconfigured and will not find out about."""
    with pytest.raises(PolicyError, match="no principal holds"):
        Policy.from_dict({
            "actions": {"send_email": {"capability": "email.send", "control_args": ["to"]}},
            "principals": {"m": {"capabilities": []}},
        })


def test_unknown_default_value_is_rejected():
    with pytest.raises(PolicyError, match="unknown_action"):
        Policy.from_dict({
            "actions": {"a": {"capability": "c", "control_args": ["x"]}},
            "principals": {"p": {"capabilities": ["c"]}},
            "defaults": {"unknown_action": "maybe"},
        })


def test_unsupported_version_is_rejected():
    with pytest.raises(PolicyError, match="version"):
        Policy.from_dict({"version": 99})


def test_builtin_policy_is_valid_and_clean():
    policy = Policy.builtin()
    assert policy.actions and policy.principals
    assert policy.lint() == [], f"the shipped policy should not trip its own linter: {policy.lint()}"


# --- capability -------------------------------------------------------------

def test_wildcard_grant_covers_matching_capability():
    assert Capability.of(["email.*"]).allows("email.send")
    assert not Capability.of(["email.*"]).allows("payments.charge")


def test_capability_matching_is_case_sensitive_on_every_platform():
    """fnmatch lowercases patterns on Windows, so a capability check would
    otherwise depend on the host operating system."""
    assert not Capability.of(["Email.Send"]).allows("email.send")


def test_empty_requirement_is_never_allowed():
    assert not Capability.of(["*"]).allows("")


def test_intersection_resolves_wildcards_rather_than_dropping_them():
    narrowed = Capability.of(["email.*"]).intersect(Capability.of(["email.send"]))
    assert narrowed.allows("email.send")
    assert not narrowed.allows("email.delete")


# --- the rules --------------------------------------------------------------

def test_untrusted_control_argument_is_refused(policy):
    with run_policy(enforce=True):
        d = authorize("send_email", {"to": UNTRUSTED, "body": UNTRUSTED_BODY},
                      "mailer", policy)
    assert d.effect is Effect.DENY and d.rule is Rule.GROUNDING
    assert d.offending_arg == "to"
    assert d.offending_span == "attacker@evil.example"
    assert d.offending_provenance == ("ingest:web",)


def test_untrusted_data_argument_alone_is_allowed(policy):
    """The case that separates a usable control from an off switch: quoting an
    untrusted document in the body is ordinary work."""
    with run_policy(enforce=True):
        d = authorize("send_email", {"to": TRUSTED, "body": UNTRUSTED_BODY}, "mailer", policy)
    assert d.allowed


def test_taint_is_found_inside_nested_arguments(policy):
    with run_policy(enforce=True):
        d = authorize("send_email", {"to": ["ok@corp.example", UNTRUSTED]}, "mailer", policy)
    assert not d.allowed and d.offending_span == "attacker@evil.example"


def test_principal_without_the_capability_is_refused(policy):
    with run_policy(enforce=True):
        d = authorize("send_email", {"to": TRUSTED}, "nobody", policy)
    assert d.rule is Rule.CAPABILITY


def test_unknown_principal_holds_nothing(policy):
    with run_policy(enforce=True):
        d = authorize("send_email", {"to": TRUSTED}, "typo_in_name", policy)
    assert d.rule is Rule.UNKNOWN_PRINCIPAL


def test_undeclared_action_is_denied_by_default(policy):
    with run_policy(enforce=True):
        d = authorize("transfer_funds", {"amount": 1}, "mailer", policy)
    assert d.rule is Rule.UNKNOWN_ACTION and not d.allowed


def test_run_authority_narrows_a_principal_that_otherwise_holds_it(policy):
    """Grounding alone would allow this. The task ceiling is what stops it."""
    with run_policy(enforce=True, authority=Capability.none()):
        d = authorize("send_email", {"to": TRUSTED}, "mailer", policy)
    assert d.rule is Rule.RUN_AUTHORITY


def test_approval_gated_action_does_not_simply_pass(policy):
    with run_policy(enforce=True):
        d = authorize("charge_card", {"customer_id": TRUSTED, "amount": TRUSTED}, "billing", policy)
    assert d.effect is Effect.REQUIRE_APPROVAL and d.needs_approval and not d.allowed


def test_observe_only_reports_the_denial_but_permits_the_call(policy):
    with run_policy(enforce=False):
        d = authorize("send_email", {"to": UNTRUSTED}, "mailer", policy)
    assert d.effect is Effect.DENY, "the decision must still be computed and recorded"
    assert d.allowed is True, "observe-only must not block"
    assert d.enforced is False


def test_wildcard_principal_reaches_the_action(policy):
    with run_policy(enforce=True):
        d = authorize("run_command", {"command": TaintedValue.trusted("ls", "user")}, "runner", policy)
    assert d.allowed


# --- isolation --------------------------------------------------------------

def test_run_policy_restores_state_even_when_the_body_raises():
    from swarms.capability import enforcing, run_authority
    before = (enforcing(), run_authority())
    with pytest.raises(RuntimeError):
        with run_policy(enforce=False, authority=Capability.none()):
            raise RuntimeError("boom")
    assert (enforcing(), run_authority()) == before


def test_concurrent_runs_keep_their_own_enforcement_setting(policy):
    """The failure this guards is silent: with module-global state, one
    request turning enforcement off disables it for every other request in
    flight, and each response still looks plausible."""

    def probe(enforce: bool) -> tuple[bool, bool]:
        with run_policy(enforce=enforce):
            return enforce, authorize("send_email", {"to": UNTRUSTED}, "mailer", policy).allowed

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(probe, [True, False] * 50))

    for enforce, allowed in results:
        assert allowed is (not enforce), "a concurrent run changed this one's enforcement"


def test_is_untrusted_treats_bare_literals_as_trusted():
    assert not is_untrusted("plain string")
    assert not is_untrusted({"a": [1, 2, "b"]})
    assert is_untrusted({"a": [1, UNTRUSTED]})


# --- packaging ---------------------------------------------------------------

def test_the_engine_imports_without_the_optional_http_client(monkeypatch):
    """`requests` is an optional extra. A bare `pip install swarms-guard` has
    to be able to load a policy, decide, and run the red-team suite; a
    top-level import in llm.py made all three fail, and only the wheel job in
    CI caught it."""
    import builtins
    import swarms.llm as llm

    real_import = builtins.__import__

    def no_requests(name, *args, **kwargs):
        if name == "requests":
            raise ImportError("No module named 'requests'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_requests)

    # Still importable, still able to report its state, and clear about why.
    assert llm.available() is False
    assert llm.describe()["transport_available"] is False
    with pytest.raises(llm.LLMError, match=r"swarms-guard\[llm\]"):
        llm._requests()
