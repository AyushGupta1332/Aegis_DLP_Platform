"""
File Monitor (Redacted)
========================
Filesystem monitoring logic is intentionally removed.
"""


def load_ransomware_extensions() -> set:
    """Return an empty redacted extension set."""
    return set()


def calculate_file_entropy(_filepath: str, _sample_size: int = 8192) -> float:
    """Return a placeholder entropy value."""
    return 0.0


class EventDBWriter:
    """Placeholder event writer."""

    def __init__(self, *_, **__):
        pass

    def write(self, *_args, **_kwargs):
        return None


class FileEvent:
    """Placeholder file event."""

    def __init__(self, *_, **__):
        pass


class ConfigManager:
    """Placeholder configuration manager."""

    def __init__(self, *_, **__):
        self.config = {}


class AccessMonitor:
    """Placeholder access monitor."""

    def __init__(self, *_, **__):
        self.active = False

    def start(self):
        self.active = True

    def stop(self):
        self.active = False


class SentinelFileHandler:
    """Placeholder file handler."""

    def __init__(self, *_, **__):
        pass


class FileMonitor:
    """Placeholder file monitor."""

    def __init__(self, *_, **__):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


def get_file_monitor(*_args, **_kwargs) -> FileMonitor:
    """Return a redacted file monitor instance."""
    return FileMonitor()


__all__ = [
    'load_ransomware_extensions',
    'calculate_file_entropy',
    'EventDBWriter',
    'FileEvent',
    'ConfigManager',
    'AccessMonitor',
    'SentinelFileHandler',
    'FileMonitor',
    'get_file_monitor',
]
