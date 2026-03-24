"""
Aegis DLP - Event Type Definitions
===================================
Central event schema definitions for inter-module communication.
Every event flowing through the Event Bus MUST use one of these types.

Aligned with MODULE_INTERLINKING.md specification.
"""

import uuid
import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List


# =============================================================================
# SEVERITY LEVELS
# =============================================================================

class Severity(str, Enum):
    """Event severity levels, ordered by escalation priority."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def __ge__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) >= order.index(other)
    
    def __gt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) > order.index(other)
    
    def __le__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return not self.__gt__(other)
    
    def __lt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return not self.__ge__(other)


# =============================================================================
# EVENT TYPES
# =============================================================================

class EventType(str, Enum):
    """All event types that can flow through the Event Bus.
    
    Naming convention: MODULE_ACTION
    Prefixes identify the source module:
        FILE_     = File Monitoring
        NET_      = Network IDS
        PHISH_    = Phishing Detection
        USB_      = USB Device Monitor
        DATA_     = Data Classification
        MALWARE_  = Malware Scanner
        ENCRYPT_  = File Encryption
        ALERT_    = Alert Manager
        AI_       = RAG AI Assistant
        SYSTEM_   = System-wide events
    """
    
    # --- File Monitoring Events ---
    FILE_CREATED = "file.created"
    FILE_MODIFIED = "file.modified"
    FILE_DELETED = "file.deleted"
    FILE_MOVED = "file.moved"
    FILE_ACCESSED = "file.accessed"
    FILE_COPY_TO_USB = "file.copy_to_usb"
    FILE_RANSOMWARE_PATTERN = "file.ransomware_pattern"
    FILE_SUSPICIOUS_EXT = "file.suspicious_extension"
    FILE_BULK_CHANGE = "file.bulk_change"
    
    # --- Network IDS Events ---
    NET_ANOMALY = "net.anomaly"
    NET_NORMAL = "net.normal"
    NET_C2_DETECTED = "net.c2_detected"
    NET_EXFILTRATION = "net.exfiltration"
    NET_STATS_UPDATE = "net.stats_update"
    
    # --- Phishing Detection Events ---
    PHISH_DETECTED = "phish.detected"
    PHISH_SAFE = "phish.safe"
    PHISH_ATTACHMENT_SUSPICIOUS = "phish.attachment_suspicious"
    PHISH_URL_SUSPICIOUS = "phish.url_suspicious"
    PHISH_CONFIRMED = "phish.confirmed"  # Confirmed by malware scan
    
    # --- USB Device Events ---
    USB_INSERTED = "usb.inserted"
    USB_REMOVED = "usb.removed"
    USB_AUTHORIZED = "usb.authorized"
    USB_UNAUTHORIZED = "usb.unauthorized"
    USB_TRANSFER_BLOCKED = "usb.transfer_blocked"
    USB_TRANSFER_ALLOWED = "usb.transfer_allowed"
    USB_DEVICE_BANNED = "usb.device_banned"
    
    # --- Data Classification Events ---
    DATA_SENSITIVE = "data.sensitive"
    DATA_NON_SENSITIVE = "data.non_sensitive"
    DATA_BULK_SENSITIVE = "data.bulk_sensitive"
    DATA_SCAN_COMPLETE = "data.scan_complete"
    
    # --- Malware Scanner Events ---
    MALWARE_DETECTED = "malware.detected"
    MALWARE_CLEAN = "malware.clean"
    MALWARE_SCAN_STARTED = "malware.scan_started"
    MALWARE_SCAN_COMPLETE = "malware.scan_complete"
    MALWARE_QUARANTINED = "malware.quarantined"
    
    # --- File Encryption Events ---
    ENCRYPT_FILE_ENCRYPTED = "encrypt.file_encrypted"
    ENCRYPT_FILE_DECRYPTED = "encrypt.file_decrypted"
    ENCRYPT_BULK_OPERATION = "encrypt.bulk_operation"
    ENCRYPT_FAILED_DECRYPT = "encrypt.failed_decrypt"
    ENCRYPT_QUARANTINE = "encrypt.quarantine"
    
    # --- Alert Manager Events ---
    ALERT_SENT = "alert.sent"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_LOCKDOWN = "alert.lockdown"
    
    # --- RAG AI Assistant Events ---
    AI_QUERY = "ai.query"
    AI_SECURITY_REPORT = "ai.security_report"
    
    # --- System Events ---
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_MODULE_ERROR = "system.module_error"
    SYSTEM_CORRELATION_MATCH = "system.correlation_match"
    SYSTEM_PAGE_VISIT = "system.page_visit"
    SYSTEM_MODULE_STARTED = "system.module_started"
    SYSTEM_MODULE_STOPPED = "system.module_stopped"


# =============================================================================
# SOURCE MODULE IDENTIFIERS
# =============================================================================

class ModuleSource(str, Enum):
    """Identifies which module produced an event."""
    FILE_MONITOR = "file_monitor"
    NETWORK_IDS = "network_ids"
    PHISHING_DETECTION = "phishing_detection"
    USB_MONITOR = "usb_monitor"
    DATA_CLASSIFICATION = "data_classification"
    MALWARE_SCANNER = "malware_scanner"
    FILE_ENCRYPTION = "file_encryption"
    ALERT_MANAGER = "alert_manager"
    AI_ASSISTANT = "ai_assistant"
    CORRELATION_ENGINE = "correlation_engine"
    SYSTEM = "system"


# =============================================================================
# BASE EVENT
# =============================================================================

@dataclass
class SecurityEvent:
    """Base event flowing through the Event Bus.
    
    Every module publishes SecurityEvent instances. The event_type determines
    what kind of event it is, and the data dict carries type-specific payload.
    
    Attributes:
        event_id:   Unique identifier (auto-generated UUID)
        event_type: What happened (from EventType enum)
        source:     Which module produced this event
        severity:   How critical is this event
        timestamp:  When the event occurred (UTC ISO format)
        data:       Event-specific payload (varies by event_type)
        correlation_id: Optional ID to link related events across modules
        metadata:   Additional context (user_id, session_id, etc.)
    """
    event_type: EventType
    source: ModuleSource
    severity: Severity = Severity.INFO
    data: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Auto-generated fields
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: str = field(default_factory=lambda: datetime.now().strftime('%d %b %Y, %I:%M:%S %p'))
    _created_at: float = field(default_factory=time.time, repr=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize event to dictionary (for storage/transmission)."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'source': self.source.value,
            'severity': self.severity.value,
            'timestamp': self.timestamp,
            'data': self.data,
            'correlation_id': self.correlation_id,
            'metadata': self.metadata,
        }
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'SecurityEvent':
        """Deserialize event from dictionary."""
        return cls(
            event_id=d.get('event_id', str(uuid.uuid4())[:12]),
            event_type=EventType(d['event_type']),
            source=ModuleSource(d['source']),
            severity=Severity(d.get('severity', 'info')),
            timestamp=d.get('timestamp', datetime.now().strftime('%d %b %Y, %I:%M:%S %p')),
            data=d.get('data', {}),
            correlation_id=d.get('correlation_id'),
            metadata=d.get('metadata', {}),
        )
    
    def age_seconds(self) -> float:
        """How many seconds ago this event was created."""
        return time.time() - self._created_at
    
    def __str__(self) -> str:
        return (
            f"[{self.severity.value.upper():>8}] "
            f"{self.event_type.value} "
            f"from {self.source.value} "
            f"@ {self.timestamp}"
        )


# =============================================================================
# EVENT FACTORY HELPERS
# =============================================================================
# Convenience functions to create events with the correct source & defaults.
# These ensure consistency and reduce boilerplate in module code.

def file_event(event_type: EventType, path: str, severity: Severity = Severity.INFO,
               file_size: int = None, file_hash: str = None, 
               process_name: str = None, process_id: int = None,
               old_path: str = None, extension: str = None,
               correlation_id: str = None, **extra_data) -> SecurityEvent:
    """Create a File Monitoring event."""
    data = {
        'path': path,
        'filename': path.split('\\')[-1] if '\\' in path else path.split('/')[-1],
        'extension': extension,
        'file_size': file_size,
        'file_hash': file_hash,
        'process_name': process_name,
        'process_id': process_id,
        'old_path': old_path,
        **extra_data
    }
    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.FILE_MONITOR,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def network_event(event_type: EventType, severity: Severity = Severity.INFO,
                  anomaly_score: float = None, src_ip: str = None,
                  dst_ip: str = None, protocol: str = None,
                  packet_count: int = None, correlation_id: str = None,
                  **extra_data) -> SecurityEvent:
    """Create a Network IDS event."""
    data = {
        'anomaly_score': anomaly_score,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'packet_count': packet_count,
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.NETWORK_IDS,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def phishing_event(event_type: EventType, severity: Severity = Severity.INFO,
                   email_id: str = None, subject: str = None,
                   sender: str = None, confidence: float = None,
                   has_attachment: bool = False, attachment_name: str = None,
                   urls: List[str] = None, correlation_id: str = None,
                   **extra_data) -> SecurityEvent:
    """Create a Phishing Detection event."""
    data = {
        'email_id': email_id,
        'subject': subject,
        'sender': sender,
        'confidence': confidence,
        'has_attachment': has_attachment,
        'attachment_name': attachment_name,
        'urls': urls or [],
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.PHISHING_DETECTION,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def usb_event(event_type: EventType, severity: Severity = Severity.INFO,
              device_id: str = None, device_hash: str = None,
              device_name: str = None, drive_letter: str = None,
              is_registered: bool = None, user_id: str = None,
              correlation_id: str = None, **extra_data) -> SecurityEvent:
    """Create a USB Monitor event."""
    data = {
        'device_id': device_id,
        'device_hash': device_hash,
        'device_name': device_name,
        'drive_letter': drive_letter,
        'is_registered': is_registered,
        'user_id': user_id,
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.USB_MONITOR,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def classification_event(event_type: EventType, path: str,
                         severity: Severity = Severity.INFO,
                         is_sensitive: bool = False, confidence: float = None,
                         classification_label: str = None,
                         correlation_id: str = None, **extra_data) -> SecurityEvent:
    """Create a Data Classification event."""
    data = {
        'path': path,
        'filename': path.split('\\')[-1] if '\\' in path else path.split('/')[-1],
        'is_sensitive': is_sensitive,
        'confidence': confidence,
        'classification_label': classification_label,
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.DATA_CLASSIFICATION,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def malware_event(event_type: EventType, severity: Severity = Severity.INFO,
                  file_path: str = None, file_hash: str = None,
                  detection_name: str = None, malicious_count: int = None,
                  total_engines: int = None, scan_id: str = None,
                  source_module: str = None, correlation_id: str = None,
                  **extra_data) -> SecurityEvent:
    """Create a Malware Scanner event."""
    data = {
        'file_path': file_path,
        'file_hash': file_hash,
        'detection_name': detection_name,
        'malicious_count': malicious_count,
        'total_engines': total_engines,
        'scan_id': scan_id,
        'source_module': source_module,
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.MALWARE_SCANNER,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def encryption_event(event_type: EventType, path: str,
                     severity: Severity = Severity.INFO,
                     action: str = None, correlation_id: str = None,
                     **extra_data) -> SecurityEvent:
    """Create a File Encryption event."""
    data = {
        'path': path,
        'filename': path.split('\\')[-1] if '\\' in path else path.split('/')[-1],
        'action': action,
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.FILE_ENCRYPTION,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def alert_event(event_type: EventType, severity: Severity = Severity.INFO,
                alert_message: str = None, alert_recipients: List[str] = None,
                triggering_events: List[str] = None,
                correlation_id: str = None, **extra_data) -> SecurityEvent:
    """Create an Alert Manager event."""
    data = {
        'alert_message': alert_message,
        'alert_recipients': alert_recipients or [],
        'triggering_events': triggering_events or [],
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.ALERT_MANAGER,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )


def system_event(event_type: EventType, severity: Severity = Severity.INFO,
                 message: str = None, module: str = None,
                 correlation_id: str = None, **extra_data) -> SecurityEvent:
    """Create a System event."""
    data = {
        'message': message,
        'module': module,
        **extra_data
    }
    data = {k: v for k, v in data.items() if v is not None}
    
    return SecurityEvent(
        event_type=event_type,
        source=ModuleSource.SYSTEM,
        severity=severity,
        data=data,
        correlation_id=correlation_id
    )
