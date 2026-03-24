"""
Aegis DLP - Correlation Engine
================================
Rule-based pattern matching across security events.
Detects compound threats by correlating events from different modules
within configurable time windows.

This implements the 8 pre-defined correlation rules from MODULE_INTERLINKING.md:
1. PHISHING_MALWARE_CHAIN
2. UNAUTHORIZED_DATA_THEFT
3. RANSOMWARE_PATTERN
4. USB_NETWORK_CORRELATION
5. MALWARE_C2_DETECTED
6. BULK_SENSITIVE_ACCESS
7. FAILED_AUTH_BRUTE_FORCE
8. PHISHING_FILE_EXEC
"""

import time
import threading
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from .events import SecurityEvent, EventType, Severity, ModuleSource

logger = logging.getLogger(__name__)


# =============================================================================
# CORRELATION RULE DEFINITION
# =============================================================================

@dataclass
class CorrelationRule:
    """Defines a compound threat detection rule.
    
    A rule matches when ALL specified trigger events occur within
    the time window. Some rules use count-based thresholds instead.
    
    Attributes:
        name:              Unique rule identifier
        description:       Human-readable description
        trigger_events:    List of EventType values that must co-occur
        time_window:       Time window in seconds for event correlation
        threat_level:      Severity assigned when rule matches
        count_threshold:   For count-based rules: min events needed (0 = all triggers must match)
        count_event_type:  For count-based rules: which event type to count
        responses:         List of response action names to execute
        cooldown:          Seconds before rule can fire again (prevent spam)
        enabled:           Whether this rule is active
    """
    name: str
    description: str
    trigger_events: List[EventType]
    time_window: int  # seconds
    threat_level: Severity
    
    # Count-based matching (for rules like "50+ FILE_MODIFIED in 60s")
    count_threshold: int = 0
    count_event_type: Optional[EventType] = None
    
    # Response actions
    responses: List[str] = field(default_factory=list)
    
    # Rate limiting
    cooldown: int = 60  # seconds
    last_fired: float = 0.0
    
    enabled: bool = True
    
    def can_fire(self) -> bool:
        """Check if enough time has passed since last firing."""
        if not self.enabled:
            return False
        return (time.time() - self.last_fired) >= self.cooldown


# =============================================================================
# PRE-DEFINED CORRELATION RULES (from MODULE_INTERLINKING.md)
# =============================================================================

def get_default_rules() -> List[CorrelationRule]:
    """Return the 8 pre-defined correlation rules.
    
    Thresholds can be overridden via data/correlation_thresholds.json
    without modifying this code.
    """
    # Load external threshold overrides (if available)
    import json as _json
    _config_path = Path(__file__).parent.parent.parent / 'data' / 'correlation_thresholds.json'
    _overrides = {}
    try:
        if _config_path.exists():
            with open(_config_path, 'r') as f:
                _overrides = _json.load(f).get('rules', {})
    except Exception:
        pass
    
    def _apply_overrides(rule: CorrelationRule) -> CorrelationRule:
        """Apply JSON overrides to a rule's configurable fields."""
        ov = _overrides.get(rule.name, {})
        if 'count_threshold' in ov:
            rule.count_threshold = int(ov['count_threshold'])
        if 'time_window' in ov:
            rule.time_window = int(ov['time_window'])
        if 'cooldown' in ov:
            rule.cooldown = int(ov['cooldown'])
        return rule
    
    rules = [
        # Rule 1: Phishing → Malware Chain
        CorrelationRule(
            name="PHISHING_MALWARE_CHAIN",
            description="Phishing email with attachment triggers malware detection",
            trigger_events=[EventType.PHISH_DETECTED, EventType.MALWARE_DETECTED],
            time_window=3600,  # 1 hour
            threat_level=Severity.CRITICAL,
            responses=["quarantine_file", "block_usb", "send_critical_alert"],
            cooldown=300,  # 5 min cooldown
        ),
        
        # Rule 2: Unauthorized Data Theft 
        CorrelationRule(
            name="UNAUTHORIZED_DATA_THEFT",
            description="Unauthorized USB device + sensitive data detected",
            trigger_events=[EventType.USB_UNAUTHORIZED, EventType.DATA_SENSITIVE],
            time_window=300,  # 5 minutes
            threat_level=Severity.CRITICAL,
            responses=["block_usb_transfer", "send_critical_alert"],
            cooldown=120,
        ),
        
        # Rule 3: Ransomware Pattern (count-based)
        CorrelationRule(
            name="RANSOMWARE_PATTERN",
            description="50+ file modifications in 1 minute (ransomware indicator)",
            trigger_events=[EventType.FILE_MODIFIED],
            time_window=60,  # 1 minute
            threat_level=Severity.CRITICAL,
            count_threshold=50,
            count_event_type=EventType.FILE_MODIFIED,
            responses=["kill_process", "block_usb", "block_network", "send_emergency_alert"],
            cooldown=60,
        ),
        
        # Rule 4: USB + Network Anomaly Correlation
        CorrelationRule(
            name="USB_NETWORK_CORRELATION",
            description="USB device inserted + network anomaly within 5 minutes",
            trigger_events=[EventType.USB_INSERTED, EventType.NET_ANOMALY],
            time_window=300,  # 5 minutes
            threat_level=Severity.HIGH,
            responses=["block_usb", "increase_monitoring"],
            cooldown=300,
        ),
        
        # Rule 5: Malware C2 Communication
        CorrelationRule(
            name="MALWARE_C2_DETECTED",
            description="Malware detected + network anomaly (potential C2 communication)",
            trigger_events=[EventType.MALWARE_DETECTED, EventType.NET_ANOMALY],
            time_window=600,  # 10 minutes
            threat_level=Severity.CRITICAL,
            responses=["isolate_host", "send_critical_alert"],
            cooldown=600,
        ),
        
        # Rule 6: Bulk Sensitive Data Access (count-based)
        CorrelationRule(
            name="BULK_SENSITIVE_ACCESS",
            description="10+ sensitive files detected within 5 minutes",
            trigger_events=[EventType.DATA_SENSITIVE],
            time_window=300,  # 5 minutes
            threat_level=Severity.HIGH,
            count_threshold=10,
            count_event_type=EventType.DATA_SENSITIVE,
            responses=["send_alert", "flag_review"],
            cooldown=300,
        ),
        
        # Rule 7: Brute Force Login (count-based)
        CorrelationRule(
            name="FAILED_AUTH_BRUTE_FORCE",
            description="5+ failed login attempts in 2 minutes",
            trigger_events=[EventType.USB_UNAUTHORIZED],  # Reusing for auth failures
            time_window=120,  # 2 minutes
            threat_level=Severity.HIGH,
            count_threshold=5,
            count_event_type=EventType.USB_UNAUTHORIZED,
            responses=["lock_account", "send_alert"],
            cooldown=300,
        ),
        
        # Rule 8: Phishing + File Execution
        CorrelationRule(
            name="PHISHING_FILE_EXEC",
            description="Phishing email detected + new executable file created",
            trigger_events=[EventType.PHISH_DETECTED, EventType.FILE_CREATED],
            time_window=1800,  # 30 minutes
            threat_level=Severity.HIGH,
            responses=["block_execution", "scan_file", "send_alert"],
            cooldown=600,
        ),
    ]
    
    # Apply external threshold overrides
    return [_apply_overrides(r) for r in rules]


# =============================================================================
# CORRELATION ENGINE
# =============================================================================

class CorrelationEngine:
    """Evaluates correlation rules against incoming events.
    
    How it works:
    1. Events flow in from the Event Bus via process_event()
    2. Each event is added to a time-windowed buffer
    3. For each active rule, check if trigger conditions are met
    4. If a rule matches, execute its response actions
    5. Log the correlation match for audit
    
    Usage:
        engine = CorrelationEngine()
        engine.add_rules(get_default_rules())
        engine.set_response_handler(my_response_handler)
        
        # Called by EventBus automatically:
        engine.process_event(event)
    """
    
    def __init__(self, event_logger=None):
        """
        Args:
            event_logger: EventLogger instance for persistence
        """
        self._rules: List[CorrelationRule] = []
        self._lock = threading.Lock()
        
        # In-memory event buffer for fast correlation queries
        # Organized by event type for efficient lookups
        self._event_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._buffer_lock = threading.Lock()
        
        # External components
        self._event_logger = event_logger
        self._response_handler: Optional[Callable] = None
        self._socketio = None
        
        # Stats
        self._stats = {
            'events_processed': 0,
            'rules_evaluated': 0,
            'rules_matched': 0,
            'responses_triggered': 0,
            'matches_by_rule': defaultdict(int),
        }
        
        # Load default rules
        self._rules = get_default_rules()
        
        logger.info("Correlation Engine initialized with %d rules", len(self._rules))
    
    # =========================================================================
    # RULE MANAGEMENT
    # =========================================================================
    
    def add_rule(self, rule: CorrelationRule):
        """Add a correlation rule."""
        with self._lock:
            # Replace if exists
            self._rules = [r for r in self._rules if r.name != rule.name]
            self._rules.append(rule)
        logger.info("Correlation rule added: %s", rule.name)
    
    def add_rules(self, rules: List[CorrelationRule]):
        """Add multiple rules at once."""
        for rule in rules:
            self.add_rule(rule)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name."""
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.name != rule_name]
            removed = before > len(self._rules)
        if removed:
            logger.info("Correlation rule removed: %s", rule_name)
        return removed
    
    def enable_rule(self, rule_name: str, enabled: bool = True) -> bool:
        """Enable or disable a rule."""
        with self._lock:
            for rule in self._rules:
                if rule.name == rule_name:
                    rule.enabled = enabled
                    logger.info("Rule %s: %s", rule_name, "enabled" if enabled else "disabled")
                    return True
        return False
    
    def get_rules(self) -> List[Dict]:
        """Get all rules and their status."""
        with self._lock:
            return [{
                'name': r.name,
                'description': r.description,
                'trigger_events': [e.value for e in r.trigger_events],
                'time_window': r.time_window,
                'threat_level': r.threat_level.value,
                'count_threshold': r.count_threshold,
                'responses': r.responses,
                'cooldown': r.cooldown,
                'enabled': r.enabled,
                'last_fired': r.last_fired,
                'matches': self._stats['matches_by_rule'].get(r.name, 0),
            } for r in self._rules]
    
    # =========================================================================
    # EVENT PROCESSING
    # =========================================================================
    
    def process_event(self, event: SecurityEvent):
        """Process an incoming event against all correlation rules.
        
        This is called by the Event Bus for every published event.
        """
        # Buffer the event
        with self._buffer_lock:
            self._event_buffer[event.event_type.value].append(event)
        
        self._stats['events_processed'] += 1
        
        # Evaluate each rule
        with self._lock:
            active_rules = [r for r in self._rules if r.enabled]
        
        for rule in active_rules:
            self._stats['rules_evaluated'] += 1
            
            # Check if this event is relevant to this rule
            if event.event_type not in rule.trigger_events:
                continue
            
            # Check cooldown
            if not rule.can_fire():
                continue
            
            # Evaluate the rule
            matched, matched_events = self._evaluate_rule(rule)
            
            if matched:
                self._handle_match(rule, matched_events)
    
    def _evaluate_rule(self, rule: CorrelationRule) -> Tuple[bool, List[SecurityEvent]]:
        """Evaluate whether a rule's conditions are met.
        
        Returns:
            Tuple of (matched: bool, matching_events: List[SecurityEvent])
        """
        now = time.time()
        cutoff = now - rule.time_window
        
        # Count-based rules
        if rule.count_threshold > 0 and rule.count_event_type:
            event_type_value = rule.count_event_type.value
            
            with self._buffer_lock:
                recent_events = [
                    e for e in self._event_buffer.get(event_type_value, [])
                    if e._created_at >= cutoff
                ]
            
            if len(recent_events) >= rule.count_threshold:
                return True, recent_events[:rule.count_threshold]
            return False, []
        
        # Multi-event correlation rules
        matched_events = []
        for required_type in rule.trigger_events:
            type_value = required_type.value
            
            with self._buffer_lock:
                recent = [
                    e for e in self._event_buffer.get(type_value, [])
                    if e._created_at >= cutoff
                ]
            
            if not recent:
                return False, []  # Missing a required event type
            
            # Take the most recent matching event
            matched_events.append(recent[-1])
        
        return True, matched_events
    
    def _handle_match(self, rule: CorrelationRule, matched_events: List[SecurityEvent]):
        """Handle a successful correlation match."""
        rule.last_fired = time.time()
        self._stats['rules_matched'] += 1
        self._stats['matches_by_rule'][rule.name] += 1
        
        # Generate correlation ID linking all matched events
        correlation_id = f"corr_{rule.name}_{int(time.time())}"
        
        event_ids = [e.event_id for e in matched_events]
        event_summaries = [
            f"{e.event_type.value} from {e.source.value}" 
            for e in matched_events
        ]
        
        logger.warning(
            "🚨 CORRELATION MATCH: %s (Threat: %s) - Events: %s",
            rule.name, rule.threat_level.value.upper(),
            ", ".join(event_summaries)
        )
        
        # Persist the match
        if self._event_logger:
            self._event_logger.log_correlation_match(
                rule_name=rule.name,
                threat_level=rule.threat_level.value,
                matched_event_ids=event_ids,
                response_actions=rule.responses
            )
        
        # Emit via Socket.IO for real-time dashboard
        if self._socketio:
            try:
                self._socketio.emit('correlation_alert', {
                    'rule': rule.name,
                    'description': rule.description,
                    'threat_level': rule.threat_level.value,
                    'matched_events': [e.to_dict() for e in matched_events[:10]],
                    'responses': rule.responses,
                    'timestamp': datetime.now().strftime('%d %b %Y, %I:%M:%S %p'),
                    'correlation_id': correlation_id,
                })
            except Exception as e:
                logger.error("Socket.IO emit error: %s", e)
        
        # Execute response actions
        if self._response_handler and rule.responses:
            for response_action in rule.responses:
                try:
                    self._response_handler(
                        action=response_action,
                        rule=rule,
                        matched_events=matched_events,
                        correlation_id=correlation_id
                    )
                    self._stats['responses_triggered'] += 1
                except Exception as e:
                    logger.error(
                        "Response action '%s' failed for rule '%s': %s",
                        response_action, rule.name, e
                    )
    
    # =========================================================================
    # CONFIGURATION
    # =========================================================================
    
    def set_response_handler(self, handler: Callable):
        """Set the response handler function.
        
        The handler will be called with:
            handler(action: str, rule: CorrelationRule, 
                    matched_events: List[SecurityEvent], 
                    correlation_id: str)
        """
        self._response_handler = handler
        logger.info("Response handler attached to Correlation Engine")
    
    def set_event_logger(self, event_logger):
        """Attach an EventLogger for persistence."""
        self._event_logger = event_logger
    
    def set_socketio(self, socketio):
        """Attach Socket.IO for real-time alerts."""
        self._socketio = socketio
    
    # =========================================================================
    # STATS & CLEANUP
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        stats = dict(self._stats)
        stats['matches_by_rule'] = dict(stats['matches_by_rule'])
        stats['total_rules'] = len(self._rules)
        stats['enabled_rules'] = sum(1 for r in self._rules if r.enabled)
        
        with self._buffer_lock:
            stats['buffer_sizes'] = {
                k: len(v) for k, v in self._event_buffer.items()
            }
        
        return stats
    
    def cleanup_buffer(self, max_age_seconds: int = 7200):
        """Remove old events from the in-memory buffer."""
        cutoff = time.time() - max_age_seconds
        cleaned = 0
        
        with self._buffer_lock:
            for event_type in list(self._event_buffer.keys()):
                buffer = self._event_buffer[event_type]
                before = len(buffer)
                self._event_buffer[event_type] = deque(
                    (e for e in buffer if e._created_at >= cutoff),
                    maxlen=1000
                )
                cleaned += before - len(self._event_buffer[event_type])
        
        if cleaned:
            logger.debug("Cleaned %d old events from correlation buffer", cleaned)
        return cleaned


# =============================================================================
# SINGLETON
# =============================================================================

_correlation_engine_instance: Optional[CorrelationEngine] = None
_engine_lock = threading.Lock()


def get_correlation_engine(event_logger=None) -> CorrelationEngine:
    """Get or create the CorrelationEngine singleton."""
    global _correlation_engine_instance
    
    with _engine_lock:
        if _correlation_engine_instance is None:
            _correlation_engine_instance = CorrelationEngine(event_logger)
        return _correlation_engine_instance
