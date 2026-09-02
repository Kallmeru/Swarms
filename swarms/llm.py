"""Optional real-model backend for the agents.

The defense does not need this. Taint tracking and capability attenuation are
deterministic code and behave identically whether an agent's reasoning comes
from a template or from a frontier model, which is the claim worth being able
to demonstrate rather than assert. So the swarm runs fully offline by default,
and this module is what you switch on to show the same containment holding
when the agents are genuinely LLM-driven and genuinely get hijacked.

Configure with environment variables (see .env.example):

    SWARMS_LLM=groq|openai|gemini|none   provider, default none (offline)
    SWARMS_LLM_MODEL=...                 model id, sensible default per provider
    GROQ_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY
    SWARMS_LLM_BASE_URL=...              override, for any OpenAI-compatible host
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import requests

log = logging.getLogger("swarms.llm")

# Any OpenAI-compatible host works through the same code path: Groq, OpenAI,
# OpenRouter, vLLM, a local Ollama. Only Gemini needs its own request shape.
DEFAULTS = {
    "groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "GROQ_API_KEY"),
    "openai": ("https://api.openai.com/v1", "gpt-4o-mini", "OPENAI_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta", "gemini-2.0-flash", "GEMINI_API_KEY"),
}


class LLMError(RuntimeError):
    """Raised instead of returning a plausible-looking empty string: an agent
    that silently gets "" behaves like a well-behaved agent, which would make
    a failed run look like a successful defense."""


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "none"
    base_url: str = ""
    model: str = ""
    api_key: str = ""
    timeout: float = 30.0

    @property
    def enabled(self) -> bool:
        return self.provider != "none" and bool(self.api_key)


def config_from_env() -> LLMConfig:
    provider = os.environ.get("SWARMS_LLM", "none").strip().lower()
    if provider in ("", "none", "off", "0", "false"):
        return LLMConfig()
    if provider not in DEFAULTS:
        raise LLMError(f"unknown SWARMS_LLM={provider!r}, expected one of {sorted(DEFAULTS)} or 'none'")
    base_url, model, key_var = DEFAULTS[provider]
    return LLMConfig(
        provider=provider,
        base_url=os.environ.get("SWARMS_LLM_BASE_URL", base_url).rstrip("/"),
        model=os.environ.get("SWARMS_LLM_MODEL", model),
        api_key=os.environ.get(key_var, "").strip(),
        timeout=float(os.environ.get("SWARMS_LLM_TIMEOUT", "30")),
    )


def available() -> bool:
    """Whether a real model is configured. Never raises: callers use this to
    pick a code path, and a misconfigured env should degrade to the offline
    agents rather than take the whole run down."""
    try:
        return config_from_env().enabled
    except LLMError:
        return False


def describe() -> dict:
    """Non-secret view of the configuration, for /api/health. Deliberately
    omits the key: health endpoints get pasted into issues."""
    try:
        cfg = config_from_env()
    except LLMError as exc:
        return {"enabled": False, "provider": "invalid", "error": str(exc)}
    return {
        "enabled": cfg.enabled,
        "provider": cfg.provider,
        "model": cfg.model if cfg.enabled else None,
        "key_present": bool(cfg.api_key),
    }


def _post(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    """One POST with a single retry on the failures that are actually worth
    retrying. Retrying a 400 just sends the same bad request twice."""
    last: Exception | None = None
    for attempt in (0, 1):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                time.sleep(1.5)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            last = exc
            if attempt == 0:
                time.sleep(1.5)
                continue
    raise LLMError(f"LLM request failed: {last}") from last


def complete(prompt: str, *, system: str | None = None, max_tokens: int = 256, temperature: float = 0.0) -> str:
    """Single-turn completion. Temperature 0 by default so a benchmark run is
    reproducible enough to compare against the offline numbers."""
    cfg = config_from_env()
    if not cfg.enabled:
        raise LLMError(
            "no LLM configured: set SWARMS_LLM and the matching API key, or use the offline agents"
        )

    if cfg.provider == "gemini":
        url = f"{cfg.base_url}/models/{cfg.model}:generateContent"
        payload: dict = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        data = _post(url, payload, {"x-goog-api-key": cfg.api_key}, cfg.timeout)
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError) as exc:
            raise LLMError(f"unexpected Gemini response shape: {data}") from exc

    messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
    data = _post(
        f"{cfg.base_url}/chat/completions",
        {"model": cfg.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens},
        {"Authorization": f"Bearer {cfg.api_key}"},
        cfg.timeout,
    )
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError) as exc:
        raise LLMError(f"unexpected response shape from {cfg.provider}: {data}") from exc


def call_llm(prompt: str) -> str:
    """Original name from the prototype, kept so nothing that imported it
    breaks. It no longer echoes the prompt back."""
    return complete(prompt)
