"""Confirms which attack_lab env vars are set, without ever printing their
values (the original version of this script printed the raw API key and
SMTP user to stdout, which is exactly how secrets end up in terminal
scrollback and CI logs). Copy .env.example to .env and fill in your own
values, never commit .env itself.
"""
import os
from dotenv import load_dotenv

load_dotenv()

REQUIRED = ["GEMINI_API_KEY", "ALERT_SMTP_HOST", "ALERT_SMTP_USER", "ALERT_SMTP_PASS"]


def check_env():
    missing = []
    for name in REQUIRED:
        is_set = bool(os.getenv(name))
        print(f"{name}: {'set' if is_set else 'MISSING'}")
        if not is_set:
            missing.append(name)
    return missing


if __name__ == "__main__":
    missing = check_env()
    if missing:
        print(f"\nMissing: {', '.join(missing)}. Copy .env.example to .env and fill in your own values.")
    else:
        print("\nAll required env vars are set.")
