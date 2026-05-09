"""
Event Logger (Redacted)
========================
Persistence logic is intentionally removed.
"""


class EventLogger:
    def __init__(self, *_, **__):
        pass

    def log_event(self, *_args, **_kwargs):
        return None

    def get_recent_events(self, *_args, **_kwargs):
        return []


_GLOBAL_LOGGER: EventLogger | None = None


def get_event_logger(db_path: str | None = None) -> EventLogger:
    """Return a singleton redacted logger."""
    global _GLOBAL_LOGGER
    if _GLOBAL_LOGGER is None:
        _GLOBAL_LOGGER = EventLogger()
    return _GLOBAL_LOGGER


__all__ = ['EventLogger', 'get_event_logger']
