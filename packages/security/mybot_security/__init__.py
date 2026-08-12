"""MyBot security package: crypto, Vault, auth, redaction, untrusted content.

Deliberately has no dependency on the LLM package, the integrations package or
any service.  The dependency arrows point *into* this package only, which is
what makes "the reasoning layer cannot reach key material" a structural fact
rather than a convention.
"""

from .crypto import CryptoError, seal, unseal
from .redaction import redact, redact_text
from .untrusted import PromptContext, UntrustedContent, scan_for_injection
from .vault import Vault, VaultAccessDenied

__all__ = [
    "CryptoError",
    "PromptContext",
    "UntrustedContent",
    "Vault",
    "VaultAccessDenied",
    "redact",
    "redact_text",
    "scan_for_injection",
    "seal",
    "unseal",
]
