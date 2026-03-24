"""
Aegis DLP - Event Bus Package
================================
Central event-driven architecture for inter-module communication.

This package provides:
- EventBus:           Central pub/sub message broker
- SecurityEvent:      Base event class with type-safe schemas
- EventType:          All event type definitions
- Severity:           Event severity levels
- CorrelationEngine:  Rule-based compound threat detection
- EventLogger:        SQLite persistence for audit trail
- ResponseExecutor:   Automated security response actions

Quick Start:
    from modules.event_bus import (
        get_event_bus, EventType, Severity, 
        file_event, SecurityEvent
    )
    
    # Get the global bus
    bus = get_event_bus(socketio=my_socketio)
    
    # Subscribe to events
    bus.subscribe("my_module", "file.*", handle_file_event)
    
    # Publish events
    bus.publish(file_event(
        EventType.FILE_CREATED,
        path="/tmp/test.txt",
        severity=Severity.INFO
    ))

Full System Initialization:
    from modules.event_bus import init_event_system
    
    bus = init_event_system(socketio=socketio)
"""

import logging

# Core event types and schemas
from .events import (
    SecurityEvent,
    EventType,
    Severity,
    ModuleSource,
    # Factory functions
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

# Event Bus (central broker)
from .bus import EventBus, get_event_bus, Subscription

# Event Logger (persistence)
from .logger import EventLogger, get_event_logger

# Correlation Engine
from .correlation import CorrelationEngine, CorrelationRule, get_correlation_engine

# Response Executor
from .responses import ResponseExecutor, get_response_executor

logger = logging.getLogger(__name__)

__all__ = [
    # Events
    'SecurityEvent', 'EventType', 'Severity', 'ModuleSource',
    'file_event', 'network_event', 'phishing_event', 'usb_event',
    'classification_event', 'malware_event', 'encryption_event',
    'alert_event', 'system_event',
    
    # Bus
    'EventBus', 'get_event_bus', 'Subscription',
    
    # Logger
    'EventLogger', 'get_event_logger',
    
    # Correlation
    'CorrelationEngine', 'CorrelationRule', 'get_correlation_engine',
    
    # Responses
    'ResponseExecutor', 'get_response_executor',
    
    # Init
    'init_event_system',
]


def init_event_system(socketio=None) -> EventBus:
    """Initialize the complete event-driven system.
    
    This wires together:
    1. Event Bus (central broker)
    2. Event Logger (SQLite persistence)
    3. Correlation Engine (rule matching)
    4. Response Executor (automated actions)
    
    Call this once during app startup.
    
    Args:
        socketio: Flask-SocketIO instance for real-time updates
    
    Returns:
        Configured EventBus instance
    """
    logger.info("=" * 60)
    logger.info("🔗 Initializing Aegis DLP Event System")
    logger.info("=" * 60)
    
    # 1. Create Event Logger
    event_logger = get_event_logger()
    logger.info("  ✓ Event Logger initialized (SQLite)")
    
    # 2. Create Correlation Engine
    correlation_engine = get_correlation_engine(event_logger)
    if socketio:
        correlation_engine.set_socketio(socketio)
    logger.info("  ✓ Correlation Engine initialized (%d rules loaded)", 
                len(correlation_engine.get_rules()))
    
    # 3. Create Response Executor
    response_executor = get_response_executor()
    if socketio:
        response_executor.set_socketio(socketio)
    logger.info("  ✓ Response Executor initialized (%d handlers)", 
                len(response_executor._handlers))
    
    # 4. Wire Correlation → Response Executor
    correlation_engine.set_response_handler(response_executor.execute)
    logger.info("  ✓ Correlation → Response pipeline connected")
    
    # 5. Create Event Bus (main broker)
    bus = get_event_bus(socketio=socketio)
    bus.set_event_logger(event_logger)
    bus.set_correlation_engine(correlation_engine)
    
    # Give Response Executor access to the bus for publishing response events
    response_executor.set_event_bus(bus)
    
    logger.info("  ✓ Event Bus initialized (async dispatch)")
    
    # 6. Publish startup event
    bus.publish(system_event(
        event_type=EventType.SYSTEM_STARTUP,
        severity=Severity.INFO,
        message="Aegis DLP Event System initialized",
        module="event_bus",
    ))
    
    logger.info("=" * 60)
    logger.info("🔗 Event System READY - All modules can now publish/subscribe")
    logger.info("=" * 60)
    
    return bus
