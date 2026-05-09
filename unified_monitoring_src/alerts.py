"""
Unified Monitoring Alerts (Redacted)
====================================
Alert handling logic is intentionally removed.
"""

from enum import Enum


class AlertLevel(str, Enum):
    INFO = 'info'
    WARNING = 'warning'
    CRITICAL = 'critical'


class AlertType(str, Enum):
    GENERIC = 'generic'


class AlertManager:
    def __init__(self, *_, **__):
        self.alerts = []

    def emit(self, *_args, **_kwargs):
        return None


def create_alert_manager():
    return AlertManager()


__all__ = ['AlertLevel', 'AlertType', 'AlertManager', 'create_alert_manager']
