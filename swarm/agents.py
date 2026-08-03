"""Agent functions for the SWARMS demo swarm: a reader that ingests an
untrusted document, an analyst that summarizes it, and an emailer that
drafts a message from whatever it was handed. Parameterized per attack so
swarm/run_swarm.py can reuse the same three functions for every fixture in
swarm/attacks/, instead of hardcoding one document like Demo.py does.
"""
from core.taint import TaintedValue, TaintLabel
from core.logger import log_event
from attack_lab.scanner_rules import scan_text
from attack_lab.config import Config

_cfg = Config()


def make_reader_agent(document_text: str, attack_id: str = "unknown"):
    def reader_agent(input_value: TaintedValue) -> TaintedValue:
        log_event("TOOL_CALL", {
            "agent": "agent1_reader", "tool": "read_document",
            "args": {"path": "attack.txt"}, "arg_labels": {"path": "TRUSTED"},
        })
        result = TaintedValue(document_text, TaintLabel.UNTRUSTED, provenance=["tool:read_document"])
        log_event("TOOL_RESULT", {
            "agent": "agent1_reader", "tool": "read_document",
            "label": result.label.value.upper(), "preview": document_text[:200],
        })

        # a second, independent detection signal alongside taint tracking:
        # Ablaze's regex-weighted scanner scores the same document. Purely
        # informational, doesn't affect containment, that's still entirely
        # the capability model's job.
        scan = scan_text(document_text)
        flagged = scan["score"] >= _cfg.scanner_threshold
        log_event("SCANNER_RESULT", {
            "agent": "agent1_reader",
            "score": round(scan["score"], 2),
            "flagged": flagged,
            "findings": [f["id"] for f in scan["findings"]],
        })

        # When Ablaze's ScannerAgent.scan() flags a message, its send_alert()
        # would compose and SMTP-send this exact email. We build the same
        # subject/body here so the demo can show precisely what would be
        # sent, but we never call smtplib: the live site is static (no
        # backend to receive a "run attack" request and send mail from),
        # and using real credentials in a public demo isn't something to
        # depend on. See docs/swarms-status-and-directions.md.
        if flagged:
            findings_lines = "\n".join(f"- {f['id']}: {f['match']}" for f in scan["findings"])
            body = (
                f"Source: swarm_demo\n"
                f"Attack: {attack_id}\n"
                f"Score: {scan['score']:.2f}\n\n"
                f"Findings:\n{findings_lines}\n\n"
                f"Original prompt:\n{document_text[:2000]}"
            )
            log_event("SCANNER_ALERT_PREVIEW", {
                "agent": "agent1_reader",
                "to": _cfg.alert_to,
                "from": _cfg.alert_from,
                "subject": f"[SWARMS] Prompt Injection Alert (score {scan['score']:.2f})",
                "body": body,
            })

        return result
    return reader_agent


def analyst_agent(input_value: TaintedValue) -> TaintedValue:
    summary = f"Summary: {input_value.value}"
    return TaintedValue(summary, input_value.label, provenance=input_value.provenance + ["analyst_agent"])


def make_emailer_agent(target_email: str):
    def emailer_agent(input_value: TaintedValue) -> TaintedValue:
        return TaintedValue(
            f"Drafted email referencing: {input_value.value}",
            input_value.label,
            provenance=input_value.provenance + ["emailer_agent"],
        )
    return emailer_agent
