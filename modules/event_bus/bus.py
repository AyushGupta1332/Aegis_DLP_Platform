"""
Aegis DLP - Event Bus (Central Message Broker)
===============================================
Thread-safe publish/subscribe event bus for inter-module communication.

This is the CORE of the interlinking architecture. All modules publish 
events here, and subscribers receive events they're interested in.

Features:
- Thread-safe pub/sub with priority ordering
- Wildcard subscriptions (e.g., subscribe to "file.*" for all file events)
- Async event dispatch (non-blocking for publishers)
- Event history with configurable buffer size
- Subscriber health tracking and error isolation
- Integration with Event Logger for persistence
"""

import threading
import queue
import time
import logging
from collections import defaultdict, deque
from typing import Callable, List, Optional, Set, Dict, Any
from datetime import datetime, timezone
from fnmatch import fnmatch

from .events import SecurityEvent, EventType, Severity, ModuleSource

logger = logging.getLogger(__name__)


# Type alias for event handler callbacks
EventHandler = Callable[[SecurityEvent], None]


class Subscription:
    """Represents a single event subscription."""
    
    def __init__(self, subscriber_id: str, pattern: str, handler: EventHandler,
                 source_filter: Optional[ModuleSource] = None,
                 min_severity: Severity = Severity.INFO,
                 description: str = ""):
        """
        Args:
            subscriber_id:  Unique ID for the subscriber module
            pattern:        Event type pattern (supports wildcards: "file.*", "*")
            handler:        Callback function receiving SecurityEvent
            source_filter:  Optional - only receive from this source
            min_severity:   Minimum severity to trigger this subscription
            description:    Human-readable description of what this does
        """
        self.subscriber_id = subscriber_id
        self.pattern = pattern
        self.handler = handler
        self.source_filter = source_filter
        self.min_severity = min_severity
        self.description = description
        self.created_at = datetime.now(timezone.utc)
        self.call_count = 0
        self.error_count = 0
        self.last_called = None
        self.active = True
    
    def matches(self, event: SecurityEvent) -> bool:
        """Check if an event matches this subscription's filters."""
        if not self.active:
            return False
        
        # Pattern matching (supports wildcards)
        if not fnmatch(event.event_type.value, self.pattern):
            return False
        
        # Source filter
        if self.source_filter and event.source != self.source_filter:
            return False
        
        # Severity filter
        if event.severity < self.min_severity:
            return False
        
        return True
    
    def __repr__(self):
        return (f"Subscription(id={self.subscriber_id}, pattern={self.pattern}, "
                f"calls={self.call_count}, errors={self.error_count})")


class EventBus:
    """Central Event Bus for Aegis DLP inter-module communication.
    
    Usage:
        bus = EventBus()
        
        # Subscribe to events
        bus.subscribe("data_classifier", "file.created", handle_new_file)
        bus.subscribe("alert_mgr", "*.critical", handle_critical,
                      min_severity=Severity.CRITICAL)
        
        # Publish events
        bus.publish(SecurityEvent(
            event_type=EventType.FILE_CREATED,
            source=ModuleSource.FILE_MONITOR,
            data={'path': '/tmp/test.txt'}
        ))
    """
    
    # Max errors before auto-disabling a subscription
    MAX_SUBSCRIPTION_ERRORS = 10
    
    # Default event history buffer size
    DEFAULT_HISTORY_SIZE = 5000
    
    def __init__(self, history_size: int = DEFAULT_HISTORY_SIZE, 
                 async_dispatch: bool = True,
                 socketio=None):
        """
        Args:
            history_size:    Number of recent events to keep in memory
            async_dispatch:  If True, events are dispatched in background thread
            socketio:        Optional Flask-SocketIO instance for real-time UI updates
        """
        self._subscriptions: List[Subscription] = []
        self._sub_lock = threading.RLock()
        
        # Event history (in-memory ring buffer)
        self._history: deque = deque(maxlen=history_size)
        self._history_lock = threading.Lock()
        
        # Async dispatch
        self._async = async_dispatch
        self._event_queue: queue.Queue = queue.Queue()
        self._dispatch_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Stats
        self._stats = {
            'total_published': 0,
            'total_dispatched': 0,
            'total_errors': 0,
            'events_by_type': defaultdict(int),
            'events_by_source': defaultdict(int),
            'events_by_severity': defaultdict(int),
        }
        self._stats_lock = threading.Lock()
        
        # Event logger (set externally for persistence)
        self._event_logger = None
        
        # Correlation engine (set externally)
        self._correlation_engine = None
        
        # Socket.IO for real-time UI updates
        self._socketio = socketio
        
        # Publisher authentication registry
        # Maps module_name -> set of allowed EventType values
        self._publisher_registry: Dict[str, Set[str]] = {}
        self._publisher_lock = threading.Lock()
        self._publisher_auth_enabled = True  # Can be disabled for development
        
        # Start dispatch thread if async
        if self._async:
            self._start_dispatcher()
        
        logger.info("Event Bus initialized (async=%s, history_size=%d)", 
                     async_dispatch, history_size)
    
    def register_publisher(self, module_name: str, allowed_event_types: List[str]) -> None:
        """Register a module as an authorized publisher with its declared event types.
        
        Call this at module startup so the bus knows which modules are allowed
        to publish which event types. Unregistered publishers get a warning logged.
        
        Args:
            module_name:  The ModuleSource.value of the publishing module
            allowed_event_types:  List of EventType.value strings this module can emit
        """
        with self._publisher_lock:
            self._publisher_registry[module_name] = set(allowed_event_types)
        logger.info("Publisher registered: %s (allowed: %d event types)", 
                     module_name, len(allowed_event_types))
    
    # =========================================================================
    # SUBSCRIPTION MANAGEMENT
    # =========================================================================
    
    def subscribe(self, subscriber_id: str, pattern: str, handler: EventHandler,
                  source_filter: Optional[ModuleSource] = None,
                  min_severity: Severity = Severity.INFO,
                  description: str = "") -> Subscription:
        """Register a subscription for events matching a pattern.
        
        Args:
            subscriber_id:  Module name (e.g., "data_classifier")
            pattern:        Event pattern with wildcards ("file.*", "usb.inserted", "*")
            handler:        Callback function(event: SecurityEvent) -> None
            source_filter:  Only receive events from this source module
            min_severity:   Minimum severity to forward
            description:    What this subscription does
        
        Returns:
            Subscription object (can be used to unsubscribe later)
        """
        sub = Subscription(
            subscriber_id=subscriber_id,
            pattern=pattern,
            handler=handler,
            source_filter=source_filter,
            min_severity=min_severity,
            description=description
        )
        
        with self._sub_lock:
            self._subscriptions.append(sub)
        
        logger.info("Subscription added: %s -> '%s' (%s)", 
                     subscriber_id, pattern, description or "no description")
        return sub
    
    def unsubscribe(self, subscription: Subscription) -> bool:
        """Remove a subscription."""
        with self._sub_lock:
            try:
                self._subscriptions.remove(subscription)
                logger.info("Subscription removed: %s -> '%s'", 
                             subscription.subscriber_id, subscription.pattern)
                return True
            except ValueError:
                return False
    
    def unsubscribe_all(self, subscriber_id: str) -> int:
        """Remove all subscriptions for a given subscriber."""
        with self._sub_lock:
            before = len(self._subscriptions)
            self._subscriptions = [
                s for s in self._subscriptions 
                if s.subscriber_id != subscriber_id
            ]
            removed = before - len(self._subscriptions)
        
        if removed:
            logger.info("Removed %d subscriptions for '%s'", removed, subscriber_id)
        return removed
    
    def get_subscriptions(self, subscriber_id: str = None) -> List[Dict]:
        """Get list of active subscriptions, optionally filtered by subscriber."""
        with self._sub_lock:
            subs = self._subscriptions
            if subscriber_id:
                subs = [s for s in subs if s.subscriber_id == subscriber_id]
            return [{
                'subscriber_id': s.subscriber_id,
                'pattern': s.pattern,
                'description': s.description,
                'active': s.active,
                'call_count': s.call_count,
                'error_count': s.error_count,
                'last_called': s.last_called.isoformat() if s.last_called else None,
                'min_severity': s.min_severity.value,
            } for s in subs]
    
    # =========================================================================
    # EVENT PUBLISHING
    # =========================================================================
    
    def publish(self, event: SecurityEvent) -> None:
        """Publish an event to the bus.
        
        This is the primary method modules call to emit events.
        Events are:
        1. Validated against publisher registry (if enabled)
        2. Added to in-memory history
        3. Persisted via EventLogger (if configured)
        4. Dispatched to matching subscribers
        5. Forwarded to CorrelationEngine (if configured)
        6. Emitted via Socket.IO (if configured)
        
        Args:
            event: The SecurityEvent to publish
        """
        # Publisher authentication check
        if self._publisher_auth_enabled and self._publisher_registry:
            source_name = event.source.value
            with self._publisher_lock:
                if source_name in self._publisher_registry:
                    allowed_types = self._publisher_registry[source_name]
                    if event.event_type.value not in allowed_types:
                        logger.warning(
                            "Publisher '%s' attempted to emit '%s' which is not in its declared capabilities. Event still published.",
                            source_name, event.event_type.value
                        )
        
        # Record to history
        with self._history_lock:
            self._history.append(event)
        
        # Update stats
        with self._stats_lock:
            self._stats['total_published'] += 1
            self._stats['events_by_type'][event.event_type.value] += 1
            self._stats['events_by_source'][event.source.value] += 1
            self._stats['events_by_severity'][event.severity.value] += 1
        
        # Persist event
        if self._event_logger:
            try:
                self._event_logger.log_event(event)
            except Exception as e:
                logger.error("Event logger error: %s", e)
        
        # Emit to Socket.IO for real-time dashboard updates
        if self._socketio:
            try:
                self._socketio.emit('security_event', event.to_dict())
                
                # Extra emission for critical events
                if event.severity >= Severity.HIGH:
                    self._socketio.emit('security_alert', {
                        'severity': event.severity.value,
                        'type': event.event_type.value,
                        'source': event.source.value,
                        'message': self._format_alert_message(event),
                        'timestamp': event.timestamp,
                        'event': event.to_dict()
                    })
            except Exception as e:
                logger.debug("Socket.IO emit error: %s", e)
        
        # Forward to correlation engine
        if self._correlation_engine:
            try:
                self._correlation_engine.process_event(event)
            except Exception as e:
                logger.error("Correlation engine error: %s", e)
        
        # Dispatch to subscribers
        if self._async:
            self._event_queue.put(event)
        else:
            self._dispatch_event(event)
        
        logger.debug("Event published: %s", event)
    
    def _format_alert_message(self, event: SecurityEvent) -> str:
        """Generate a human-readable alert message from an event."""
        messages = {
            EventType.FILE_RANSOMWARE_PATTERN: 
                f"🚨 Ransomware pattern detected! {event.data.get('count', 'Multiple')} files modified with suspicious extensions",
            EventType.MALWARE_DETECTED: 
                f"🦠 Malware detected in {event.data.get('file_path', 'unknown file')}",
            EventType.PHISH_DETECTED: 
                f"🎣 Phishing email detected: {event.data.get('subject', 'No subject')}",
            EventType.USB_UNAUTHORIZED: 
                f"🔌 Unauthorized USB device connected: {event.data.get('device_name', 'Unknown')}",
            EventType.USB_TRANSFER_BLOCKED: 
                f"⛔ File transfer to USB blocked",
            EventType.NET_ANOMALY: 
                f"🌐 Network anomaly detected (score: {event.data.get('anomaly_score', 'N/A')})",
            EventType.NET_C2_DETECTED: 
                f"🚨 Command & Control communication detected to {event.data.get('dst_ip', 'unknown')}",
            EventType.DATA_SENSITIVE: 
                f"📊 Sensitive data detected in {event.data.get('filename', 'unknown file')}",
            EventType.DATA_BULK_SENSITIVE: 
                f"⚠️ Bulk sensitive data detected: {event.data.get('count', 'multiple')} files",
            EventType.ENCRYPT_FAILED_DECRYPT: 
                f"🔐 Failed decryption attempt on {event.data.get('filename', 'unknown file')}",
        }
        return messages.get(event.event_type, 
                           f"{event.event_type.value}: {event.data.get('message', str(event.data))}")
    
    # =========================================================================
    # ASYNC DISPATCH
    # =========================================================================
    
    def _start_dispatcher(self):
        """Start the background event dispatch thread."""
        self._running = True
        self._dispatch_thread = threading.Thread(
            target=self._dispatch_loop,
            name="EventBus-Dispatcher",
            daemon=True
        )
        self._dispatch_thread.start()
        logger.debug("Event dispatcher thread started")
    
    def _dispatch_loop(self):
        """Background loop that processes events from the queue."""
        while self._running:
            try:
                event = self._event_queue.get(timeout=1.0)
                self._dispatch_event(event)
                self._event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Dispatch loop error: %s", e)
    
    def _dispatch_event(self, event: SecurityEvent):
        """Dispatch a single event to all matching subscribers."""
        with self._sub_lock:
            matching_subs = [s for s in self._subscriptions if s.matches(event)]
        
        for sub in matching_subs:
            try:
                sub.handler(event)
                sub.call_count += 1
                sub.last_called = datetime.now(timezone.utc)
                
                with self._stats_lock:
                    self._stats['total_dispatched'] += 1
                    
            except Exception as e:
                sub.error_count += 1
                with self._stats_lock:
                    self._stats['total_errors'] += 1
                
                logger.error(
                    "Error in subscriber '%s' (pattern: '%s'): %s",
                    sub.subscriber_id, sub.pattern, e, exc_info=True
                )
                
                # Auto-disable broken subscriptions
                if sub.error_count >= self.MAX_SUBSCRIPTION_ERRORS:
                    sub.active = False
                    logger.warning(
                        "Subscription auto-disabled after %d errors: %s -> %s",
                        sub.error_count, sub.subscriber_id, sub.pattern
                    )
    
    # =========================================================================
    # EVENT HISTORY & QUERY
    # =========================================================================
    
    def get_recent_events(self, limit: int = 50, 
                          event_type: EventType = None,
                          source: ModuleSource = None,
                          min_severity: Severity = None,
                          since_seconds: float = None) -> List[Dict]:
        """Query recent events from in-memory history.
        
        Args:
            limit:          Max events to return
            event_type:     Filter by specific event type
            source:         Filter by source module
            min_severity:   Minimum severity
            since_seconds:  Only events from the last N seconds
        
        Returns:
            List of event dicts, most recent first
        """
        with self._history_lock:
            events = list(self._history)
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if source:
            events = [e for e in events if e.source == source]
        if min_severity:
            events = [e for e in events if e.severity >= min_severity]
        if since_seconds:
            cutoff = time.time() - since_seconds
            events = [e for e in events if e._created_at >= cutoff]
        
        # Most recent first, limited
        events = sorted(events, key=lambda e: e._created_at, reverse=True)[:limit]
        
        return [e.to_dict() for e in events]
    
    def get_events_by_correlation(self, correlation_id: str) -> List[Dict]:
        """Get all events linked by a correlation ID."""
        with self._history_lock:
            events = [e for e in self._history if e.correlation_id == correlation_id]
        return [e.to_dict() for e in sorted(events, key=lambda e: e._created_at)]
    
    def count_events(self, event_type: EventType = None, 
                     since_seconds: float = None) -> int:
        """Count events matching criteria."""
        with self._history_lock:
            events = list(self._history)
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if since_seconds:
            cutoff = time.time() - since_seconds
            events = [e for e in events if e._created_at >= cutoff]
        
        return len(events)
    
    # =========================================================================
    # STATS & HEALTH
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get Event Bus statistics."""
        with self._stats_lock:
            stats = dict(self._stats)
            stats['events_by_type'] = dict(stats['events_by_type'])
            stats['events_by_source'] = dict(stats['events_by_source'])
            stats['events_by_severity'] = dict(stats['events_by_severity'])
        
        with self._sub_lock:
            stats['total_subscriptions'] = len(self._subscriptions)
            stats['active_subscriptions'] = sum(1 for s in self._subscriptions if s.active)
        
        with self._history_lock:
            stats['history_size'] = len(self._history)
        
        stats['queue_size'] = self._event_queue.qsize() if self._async else 0
        stats['dispatcher_running'] = self._running
        
        return stats
    
    def get_health(self) -> Dict[str, Any]:
        """Get health status of the Event Bus and its subscribers."""
        with self._sub_lock:
            subscriber_health = {}
            for sub in self._subscriptions:
                if sub.subscriber_id not in subscriber_health:
                    subscriber_health[sub.subscriber_id] = {
                        'subscriptions': 0,
                        'total_calls': 0,
                        'total_errors': 0,
                        'active': True
                    }
                h = subscriber_health[sub.subscriber_id]
                h['subscriptions'] += 1
                h['total_calls'] += sub.call_count
                h['total_errors'] += sub.error_count
                if not sub.active:
                    h['active'] = False
        
        return {
            'status': 'healthy' if self._running else 'stopped',
            'uptime_info': 'running' if self._running else 'not running',
            'subscribers': subscriber_health,
            'stats': self.get_stats()
        }
    
    # =========================================================================
    # CONFIGURATION
    # =========================================================================
    
    def set_event_logger(self, event_logger):
        """Attach an EventLogger for persistent event storage."""
        self._event_logger = event_logger
        logger.info("Event logger attached to bus")
    
    def set_correlation_engine(self, engine):
        """Attach a CorrelationEngine for rule-based pattern matching."""
        self._correlation_engine = engine
        logger.info("Correlation engine attached to bus")
    
    def set_socketio(self, socketio):
        """Attach Socket.IO for real-time UI updates."""
        self._socketio = socketio
        logger.info("Socket.IO attached to bus")
    
    # =========================================================================
    # LIFECYCLE
    # =========================================================================
    
    def shutdown(self):
        """Gracefully shut down the Event Bus."""
        logger.info("Event Bus shutting down...")
        self._running = False
        
        if self._dispatch_thread:
            self._dispatch_thread.join(timeout=5)
            self._dispatch_thread = None
        
        # Drain remaining events
        remaining = 0
        while not self._event_queue.empty():
            try:
                event = self._event_queue.get_nowait()
                self._dispatch_event(event)
                remaining += 1
            except queue.Empty:
                break
        
        if remaining:
            logger.info("Processed %d remaining events during shutdown", remaining)
        
        logger.info("Event Bus shut down. Total events: %d", 
                     self._stats['total_published'])


# =============================================================================
# SINGLETON
# =============================================================================

_event_bus_instance: Optional[EventBus] = None
_bus_lock = threading.Lock()


def get_event_bus(socketio=None, **kwargs) -> EventBus:
    """Get or create the global Event Bus singleton.
    
    Args:
        socketio: Optional Flask-SocketIO instance for real-time updates
        **kwargs: Passed to EventBus constructor on first call
    
    Returns:
        The global EventBus instance
    """
    global _event_bus_instance
    
    with _bus_lock:
        if _event_bus_instance is None:
            _event_bus_instance = EventBus(socketio=socketio, **kwargs)
        elif socketio and _event_bus_instance._socketio is None:
            _event_bus_instance.set_socketio(socketio)
        return _event_bus_instance
