"""Prompt-injection scanner, sanitizer, and alerting prototype (Ablaze's
attack-lab work). Standalone from swarm/ and core/ on purpose: it's a
different detection strategy (regex-weighted scoring) than the taint/
capability model the demo runs on, not a replacement for it.

The scanner and sanitizer are pure regex, no network, no API key needed.
The optional LLM rewrite and email alert need real credentials, which
never live in this repo, see .env.example at the project root.
"""
from .agents import InputAgent, ScannerAgent, SanitizerAgent
from .scanner_rules import scan_text
from .sanitizers import basic_sanitize
from .llm_client import GeminiClient
from .config import Config
from .logger import logger

__all__ = [
    "InputAgent",
    "ScannerAgent",
    "SanitizerAgent",
    "scan_text",
    "basic_sanitize",
    "GeminiClient",
    "Config",
    "logger",
]
