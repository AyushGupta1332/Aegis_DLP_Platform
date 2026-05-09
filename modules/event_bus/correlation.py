"""
Correlation Engine (Redacted)
==============================
Rule evaluation logic is intentionally removed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CorrelationRule:
    name: str = 'redacted'
    description: str = 'redacted'


def get_default_rules() -> list[CorrelationRule]:
    return []


class CorrelationEngine:
    def __init__(self, *_, **__):
        self._rules = get_default_rules()
        self._socketio = None
        self._response_handler = None

    def set_socketio(self, socketio):
        self._socketio = socketio

    def set_response_handler(self, handler):
        self._response_handler = handler

    def get_rules(self):
        return list(self._rules)


_GLOBAL_ENGINE: CorrelationEngine | None = None


def get_correlation_engine(event_logger=None) -> CorrelationEngine:
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        _GLOBAL_ENGINE = CorrelationEngine()
    return _GLOBAL_ENGINE


__all__ = ['CorrelationRule', 'CorrelationEngine', 'get_default_rules', 'get_correlation_engine']
