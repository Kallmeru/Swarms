import re
from typing import List, Dict

RULES = [
    {"id":"system_override","pattern":re.compile(r"(ignore (previous|prior) instructions|disregard (previous|prior) instructions|override system prompt|forget your instructions)", re.I), "weight":0.4},
    {"id":"exfiltrate","pattern":re.compile(r"(send (all|my|the) data|exfiltrate|leak|expose secret|expose credentials|steal data)", re.I), "weight":0.5},
    {"id":"url_or_html","pattern":re.compile(r"(https?://|<script|<iframe|<img|javascript:)", re.I), "weight":0.3},
    {"id":"code_block","pattern":re.compile(r"```|<code>|</code>", re.I), "weight":0.2},
    {"id":"shell_cmd","pattern":re.compile(r"(\bcurl\b|\bwget\b|\brm -rf\b|\bssh\b|\bscp\b|\bcat /etc/passwd\b)", re.I), "weight":0.4},
    {"id":"prompt_injection_phrases","pattern":re.compile(r"(you are now|from now on you will|act as an attacker|pretend you are|become an attacker)", re.I), "weight":0.35},
    {"id":"base64_or_hex","pattern":re.compile(r"\b([A-Za-z0-9+/]{40,}=*)\b"), "weight":0.25},
]

def scan_text(text: str) -> Dict:
    findings = []
    score = 0.0
    for rule in RULES:
        m = rule["pattern"].search(text)
        if m:
            findings.append({"id": rule["id"], "weight": rule["weight"], "match": m.group(0)})
            score += rule["weight"]
    score = min(score, 1.0)
    return {"score": score, "findings": findings}
