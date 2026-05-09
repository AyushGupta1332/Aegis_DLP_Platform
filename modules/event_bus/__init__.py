"""
Aegis DLP - Event Bus Package (Redacted)
=========================================
Internal event system logic is intentionally removed.
"""

from .events import (
    SecurityEvent,
    EventType,
    Severity,
    ModuleSource,
    file_event,
    network_event,
    phishing_event,
    usb_event,
    classification_event,
    malware_event,
    encryption_event,
    alert_event,
    system_event,
)
from .bus import EventBus, get_event_bus, Subscription
from .logger import EventLogger, get_event_logger
from .correlation import CorrelationEngine, CorrelationRule, get_correlation_engine
from .responses import ResponseExecutor, get_response_executor

__all__ = [
    'SecurityEvent',
    'EventType',
    'Severity',
    'ModuleSource',
    'file_event',
    'network_event',
    'phishing_event',
    'usb_event',
    'classification_event',
    'malware_event',
    'encryption_event',
    'alert_event',
    'system_event',
    'EventBus',
    'get_event_bus',
    'Subscription',
    'EventLogger',
    'get_event_logger',
    'CorrelationEngine',
    'CorrelationRule',
    'get_correlation_engine',
    'ResponseExecutor',
    'get_response_executor',
    'init_event_system',
]


def init_event_system(socketio=None) -> EventBus:
    """Return a redacted event bus instance."""
    _ = get_event_logger()
    _ = get_correlation_engine()
    _ = get_response_executor()
    return get_event_bus(socketio=socketio)
