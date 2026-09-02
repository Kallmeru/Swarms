"""LLM access for the sanitizer's optional rewrite step.

This used to POST to `https://api.gemini.example/v1/generate`, an address
that does not exist, so the rewrite could never have worked against a real
key. Rather than fix a second HTTP client, it now delegates to
`core.llm_client`, which is the one place in the repo that knows how to talk
to a provider. Same class name and same return shape, so
`SanitizerAgent(llm_client=GeminiClient())` and the tests that mock it are
unaffected.

Configure with SWARMS_LLM plus the matching key (see .env.example). The
legacy GEMINI_API_KEY alone still works and selects Gemini.
"""
from __future__ import annotations

import os

from core import llm_client as _core_llm
from .config import Config
from .logger import logger

cfg = Config()


class GeminiClient:
    """Thin adapter over core.llm_client."""

    def __init__(self, api_key: str | None = None, endpoint: str | None = None):
        self.api_key = api_key or cfg.gemini_api_key
        self.endpoint = endpoint  # honored via SWARMS_LLM_BASE_URL if set

    def _ensure_provider(self) -> None:
        """A bare GEMINI_API_KEY with no SWARMS_LLM set is the setup this
        repo's .env has always described, so treat it as selecting Gemini
        instead of failing with 'no provider configured'."""
        if not os.environ.get("SWARMS_LLM") and self.api_key:
            os.environ["SWARMS_LLM"] = "gemini"
            os.environ.setdefault("GEMINI_API_KEY", self.api_key)
        if self.endpoint:
            os.environ.setdefault("SWARMS_LLM_BASE_URL", self.endpoint)

    def generate(self, prompt: str, max_tokens: int = 512) -> dict:
        if not self.api_key and not _core_llm.available():
            # Raising rather than returning empty text: a silent "" here
            # would look exactly like a successful sanitizer rewrite.
            raise RuntimeError("No API key configured; set SWARMS_LLM and a key, or mock this in tests")
        self._ensure_provider()
        logger.debug("LLM generate called with prompt length %d", len(prompt))
        return {"text": _core_llm.complete(prompt, max_tokens=max_tokens)}
