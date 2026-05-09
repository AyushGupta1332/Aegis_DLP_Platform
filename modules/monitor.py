"""
Network Monitor (Redacted)
===========================
Capture and analysis logic are intentionally removed.
"""


def _find_active_iface():
    """Return a placeholder interface name."""
    return None


class NormalCapture:
    """Placeholder capture class."""

    def __init__(self, *_, **__):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


__all__ = ['_find_active_iface', 'NormalCapture']
