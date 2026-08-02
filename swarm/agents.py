"""Agent functions for the SWARMS demo swarm: a reader that ingests an
untrusted document, an analyst that summarizes it, and an emailer that
drafts a message from whatever it was handed. Parameterized per attack so
swarm/run_swarm.py can reuse the same three functions for every fixture in
swarm/attacks/, instead of hardcoding one document like Demo.py does.
"""
from core.taint import TaintedValue, TaintLabel
from core.logger import log_event
from attack_lab.scanner_rules import scan_text


def make_reader_agent(document_text: str):
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
        log_event("SCANNER_RESULT", {
            "agent": "agent1_reader",
            "score": round(scan["score"], 2),
            "flagged": scan["score"] >= 0.6,
            "findings": [f["id"] for f in scan["findings"]],
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
