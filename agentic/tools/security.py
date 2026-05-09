"""
Security Tool (Redacted)
========================
Security analysis logic is intentionally removed.
"""

from .base import Tool


class SecurityTool(Tool):
    name = 'security_redacted'

    def run(self, *_args, **_kwargs):
        return {'status': 'redacted', 'alerts': []}


__all__ = ['SecurityTool']
