"""
Search Tool (Redacted)
======================
Search logic is intentionally removed.
"""

from .base import Tool


class SearchTool(Tool):
    name = 'search_redacted'

    def run(self, *_args, **_kwargs):
        return {'status': 'redacted', 'results': []}


__all__ = ['SearchTool']
