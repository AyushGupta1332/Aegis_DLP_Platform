"""
Security Agent (Redacted)
=========================
AI assistant logic is intentionally removed.
"""


class SecurityAgent:
    async def chat(self, *_args, **_kwargs):
        return {
            'response': 'AI assistant functionality is redacted.',
            'tools_used': [],
            'processing_time': 0,
        }


def get_agent():
    """Return None to indicate redacted agent is unavailable."""
    return None


__all__ = ['SecurityAgent', 'get_agent']
