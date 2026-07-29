import os
import requests
from .config import Config
from .logger import logger

cfg = Config()

class GeminiClient:
    def __init__(self, api_key: str = None, endpoint: str | None = None):
        self.api_key = api_key or cfg.gemini_api_key
        self.endpoint = endpoint or "https://api.gemini.example/v1/generate"

    def generate(self, prompt: str, max_tokens: int = 512) -> dict:
        if not self.api_key:
            # In tests, we expect a mock; raising helps catch accidental calls.
            raise RuntimeError("No Gemini API key configured; use a mock in tests")
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type":"application/json"}
        payload = {"prompt": prompt, "max_tokens": max_tokens}
        logger.debug("LLM generate called with prompt length %d", len(prompt))
        resp = requests.post(self.endpoint, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
