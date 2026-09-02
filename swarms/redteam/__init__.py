"""Adversarial validation for a policy.

A corpus of prompt-injection attacks plus benign control tasks, run through a
deliberately gullible agent pipeline that calls the real `Guard`. The point is
to answer, for *your* configuration: would this have stopped these, and would
it have let real work through.
"""
from swarms.redteam.fixtures import Fixture, load_fixture, load_fixtures
from swarms.redteam.runner import format_report, run_suite, write_report

__all__ = ["Fixture", "format_report", "load_fixture", "load_fixtures", "run_suite", "write_report"]
