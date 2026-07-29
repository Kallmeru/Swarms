import re
from typing import Tuple, List

def basic_sanitize(text: str) -> Tuple[str, List[str]]:
    actions = []
    sanitized = text

    # Remove HTML tags
    cleaned = re.sub(r"<[^>]+>", " ", sanitized)
    if cleaned != sanitized:
        actions.append("removed_html_tags")
        sanitized = cleaned

    # Replace URLs
    cleaned = re.sub(r"https?://\S+", "[REMOVED_URL]", sanitized)
    if cleaned != sanitized:
        actions.append("removed_urls")
        sanitized = cleaned

    # Escape code fences
    cleaned = sanitized.replace("```", "` ` `")
    if cleaned != sanitized:
        actions.append("escaped_code_fences")
        sanitized = cleaned

    # Remove system override phrases
    cleaned = re.sub(r"(ignore (previous|prior) instructions|disregard (previous|prior) instructions|override system prompt|forget your instructions)", "[REMOVED_INSTRUCTION]", sanitized, flags=re.I)
    if cleaned != sanitized:
        actions.append("removed_system_override_phrases")
        sanitized = cleaned

    # Remove shell commands like curl/wget
    cleaned = re.sub(r"\b(curl|wget|ssh|scp|rm -rf|cat /etc/passwd)\b", "[REMOVED_CMD]", sanitized, flags=re.I)
    if cleaned != sanitized:
        actions.append("removed_shell_commands")
        sanitized = cleaned

    # Trim whitespace
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized, actions
