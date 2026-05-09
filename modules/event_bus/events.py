"""
Event Schemas (Redacted)
========================
Event definitions are reduced to minimal public-safe placeholders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'


class EventType(str, Enum):
    SYSTEM_PAGE_VISIT = 'system.page_visit'
    SYSTEM_STARTUP = 'system.startup'
    SYSTEM_SHUTDOWN = 'system.shutdown'
    GENERIC = 'generic'


class ModuleSource(str, Enum):
    SYSTEM = 'system'
    UNKNOWN = 'unknown'


@dataclass
class SecurityEvent:
    event_type: EventType
    severity: Severity = Severity.INFO
    module: str | None = None
    message: str | None = None
    metadata: dict = field(default_factory=dict)


def _build_event(event_type: EventType, severity: Severity, module: str | None, message: str | None, **metadata):
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        module=module,
        message=message,
        metadata=metadata,
    )


def file_event(event_type: EventType, path: str, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='file', message=None, path=path, **extra)


def network_event(event_type: EventType, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='network', message=None, **extra)


def phishing_event(event_type: EventType, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='phishing', message=None, **extra)


def usb_event(event_type: EventType, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='usb', message=None, **extra)


def classification_event(event_type: EventType, path: str, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='classification', message=None, path=path, **extra)


def malware_event(event_type: EventType, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='malware', message=None, **extra)


def encryption_event(event_type: EventType, path: str, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='encryption', message=None, path=path, **extra)


def alert_event(event_type: EventType, severity: Severity = Severity.INFO, **extra):
    return _build_event(event_type, severity, module='alert', message=None, **extra)


def system_event(event_type: EventType, severity: Severity = Severity.INFO, message: str | None = None, **extra):
    return _build_event(event_type, severity, module='system', message=message, **extra)


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
]
