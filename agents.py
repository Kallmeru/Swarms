from dataclasses import dataclass
from typing import Dict, Any
from .scanner_rules import scan_text
from .sanitizers import basic_sanitize
from .logger import logger
from .llm_client import GeminiClient
from .config import Config
import smtplib
from email.message import EmailMessage

cfg = Config()

@dataclass
class InputAgent:
    source: str
    user_id: str
    prompt: str

    def normalized(self) -> Dict[str, Any]:
        p = " ".join(self.prompt.split())
        return {"source": self.source, "user_id": self.user_id, "prompt": p}

class ScannerAgent:
    def __init__(self, threshold: float = None):
        self.threshold = threshold or cfg.scanner_threshold

    def scan(self, prompt: str) -> Dict:
        result = scan_text(prompt)
        logger.debug("Scan result: %s", result)
        result["alert"] = result["score"] >= self.threshold
        return result

    def send_alert(self, findings: Dict, input_meta: Dict):
        msg = EmailMessage()
        msg["Subject"] = f"[SWARNS] Prompt Injection Alert (score {findings['score']:.2f})"
        msg["From"] = cfg.alert_from
        msg["To"] = cfg.alert_to
        body = f"Source: {input_meta.get('source')}\nUser: {input_meta.get('user_id')}\nScore: {findings['score']}\n\nFindings:\n"
        for f in findings.get("findings", []):
            body += f"- {f['id']}: {f['match']}\n"
        body += "\nOriginal prompt:\n" + input_meta.get("prompt", "")[:2000]
        msg.set_content(body)

        try:
            with smtplib.SMTP(cfg.alert_smtp_host, cfg.alert_smtp_port, timeout=10) as s:
                # If server supports TLS
                try:
                    s.starttls()
                except Exception:
                    pass
                if cfg.alert_smtp_user and cfg.alert_smtp_pass:
                    s.login(cfg.alert_smtp_user, cfg.alert_smtp_pass)
                s.send_message(msg)
            logger.info("Alert email sent to %s", cfg.alert_to)
        except Exception as e:
            logger.exception("Failed to send alert email: %s", e)

class SanitizerAgent:
    def __init__(self, llm_client: GeminiClient | None = None):
        self.llm = llm_client

    def sanitize(self, prompt: str, use_llm_rewrite: bool = False) -> Dict:
        sanitized, actions = basic_sanitize(prompt)
        if use_llm_rewrite and self.llm:
            try:
                # Keep this call optional and mockable in tests
                resp = self.llm.generate(f"Rewrite to be safe: {sanitized}", max_tokens=256)
                sanitized_text = resp.get("text") or resp.get("output") or sanitized
                actions.append("llm_rewrite")
            except Exception as e:
                logger.exception("LLM rewrite failed: %s", e)
                sanitized_text = sanitized
        else:
            sanitized_text = sanitized
        return {"sanitized_prompt": sanitized_text, "actions": actions}
