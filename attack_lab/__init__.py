"""Prompt-injection scanner, sanitizer, and alerting prototype (Ablaze's
attack-lab work). The scanner core (scan_text, basic_sanitize) is wired into
swarm/agents.py as a second, independent detection signal alongside the
taint/capability model, not a replacement for it, that's why this package
only eagerly imports the pieces that need zero external dependencies.

scan_text and basic_sanitize are pure regex, no network, no API key, no
third-party package needed, safe to run on every attack in the live demo.
InputAgent/ScannerAgent/SanitizerAgent/GeminiClient pull in `requests` (for
the optional Gemini rewrite and SMTP alert), import them directly from
attack_lab.agents / attack_lab.llm_client if you need those, keeping them
out of this file's eager imports is what lets the swarm demo depend on
attack_lab without needing `requests` installed just to run the scanner.
"""
from .scanner_rules import scan_text
from .sanitizers import basic_sanitize
from .config import Config
from .logger import logger

__all__ = [
    "scan_text",
    "basic_sanitize",
    "Config",
    "logger",
]
