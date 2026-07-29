"""
SWARNS Package Initialization

This file ensures that the 'swarns' directory is treated as a Python package.
It also exposes key classes so they can be imported directly from swarns.
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
