from dotenv import load_dotenv
import os

print("DEBUG: Forcing .env load...")
load_dotenv(dotenv_path=".env")

print("SMTP Host:", os.getenv("ALERT_SMTP_HOST"))
print("SMTP User:", os.getenv("ALERT_SMTP_USER"))
print("Gemini Key:", os.getenv("GEMINI_API_KEY"))

