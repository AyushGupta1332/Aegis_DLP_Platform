"""
Event Bus (Redacted)
====================
Minimal no-op event bus implementation for public builds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class Subscription:
    subscriber: str
    pattern: str
    callback: Callable
    min_severity: object | None = None


class EventBus:
    def __init__(self, async_dispatch: bool = True):
        self.async_dispatch = async_dispatch
        self._subscriptions: dict[str, list[Subscription]] = {}
        self._recent_events = []
        self._total_published = 0

    def subscribe(self, subscriber: str, pattern: str, callback: Callable, min_severity=None) -> Subscription:
        sub = Subscription(subscriber=subscriber, pattern=pattern, callback=callback, min_severity=min_severity)
        self._subscriptions.setdefault(subscriber, []).append(sub)
        return sub

    def unsubscribe(self, subscription: Subscription) -> None:
        subs = self._subscriptions.get(subscription.subscriber, [])
        if subscription in subs:
            subs.remove(subscription)

    def unsubscribe_all(self, subscriber: str) -> None:
        self._subscriptions.pop(subscriber, None)

    def get_subscriptions(self, subscriber: str) -> list[Subscription]:
        return list(self._subscriptions.get(subscriber, []))

    def publish(self, event) -> None:
        self._total_published += 1
        self._recent_events.append(event)
        self._recent_events = self._recent_events[-100:]
        for subs in self._subscriptions.values():
            for sub in subs:
                try:
                    sub.callback(event)
                except Exception:
                    continue

    def get_stats(self) -> dict:
        return {'total_published': self._total_published}

    def get_recent_events(self, limit: int = 10):
        return list(self._recent_events[-limit:])

    def set_event_logger(self, _logger) -> None:
        return None

    def set_correlation_engine(self, _engine) -> None:
        return None

    def shutdown(self) -> None:
        return None


_GLOBAL_BUS: EventBus | None = None


def get_event_bus(socketio=None, **_kwargs) -> EventBus:
    """Return a singleton event bus."""
    global _GLOBAL_BUS
    if _GLOBAL_BUS is None:
        _GLOBAL_BUS = EventBus()
    return _GLOBAL_BUS


__all__ = ['Subscription', 'EventBus', 'get_event_bus']
