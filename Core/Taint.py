from enum import Enum

class TaintLabel(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class TaintedValue:
    def __init__(self, value, label, provenance=None):
        self.value = value
        self.label = label
        self.provenance = provenance or []


def propagate_label(label_a: TaintLabel, label_b: TaintLabel) -> TaintLabel:
    """
    Pure function: determines the resulting taint label.
    """
    if label_a == TaintLabel.UNTRUSTED or label_b == TaintLabel.UNTRUSTED:
        return TaintLabel.UNTRUSTED
    return TaintLabel.TRUSTED


def combine_provenance(prov_a: list, prov_b: list) -> list:
    """
    Pure function: merges provenance traces.
    """
    return prov_a + prov_b


def combine_values(a: TaintedValue, b: TaintedValue) -> TaintedValue:
    """
    Pure function: merges two tainted values.
    """
    new_label = propagate_label(a.label, b.label)
    new_provenance = combine_provenance(a.provenance, b.provenance)
    new_value = f"{a.value}{b.value}"  # simple concatenation for now

    return TaintedValue(new_value, new_label, new_provenance)
