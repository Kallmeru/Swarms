class TaintLabel(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"

class TaintedValue:
    def __init__(self, value, label, provenance=None):
        self.value = value
        self.label = label
        self.provenance = provenance or []
