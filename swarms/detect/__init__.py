"""Content scanning: a second, independent signal, and never the defense.

`scan_text` scores text against weighted regex rules for the shapes prompt
injection usually takes. It is reported next to a policy decision so an
operator can see both, and it gates nothing.

That separation is deliberate and worth stating: detection has to recognize
an attack to stop it, so it can be reworded around. Every result from this
module is advisory. The engine's answer does not consult it.

`basic_sanitize` strips HTML, URLs, code fences and known override phrases.
Useful for cleaning text before showing it to a human. Not a security
boundary, for the same reason.
"""
from .config import Config
from .sanitizers import basic_sanitize
from .scanner_rules import RULES, scan_text

__all__ = ["Config", "RULES", "basic_sanitize", "scan_text"]
