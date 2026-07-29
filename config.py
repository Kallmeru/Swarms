from dataclasses import dataclass
import os

@dataclass
class Config:
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    alert_smtp_host: str = os.getenv("ALERT_SMTP_HOST", "localhost")
    alert_smtp_port: int = int(os.getenv("ALERT_SMTP_PORT", "1025"))
    alert_smtp_user: str = os.getenv("ALERT_SMTP_USER", "")
    alert_smtp_pass: str = os.getenv("ALERT_SMTP_PASS", "")
    alert_to: str = os.getenv("ALERT_TO", "security@example.com")
    alert_from: str = os.getenv("ALERT_FROM", alert_smtp_user or "swarns@example.com")
    scanner_threshold: float = float(os.getenv("SCANNER_THRESHOLD", "0.6"))
