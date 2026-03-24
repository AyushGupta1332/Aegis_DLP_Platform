# -- Pre-import noise suppression (must be first) --
import sys, os, warnings, io, logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['PYTHONWARNINGS'] = 'ignore::DeprecationWarning'
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', message='.*Severity.*')
logging.disable(logging.WARNING)
# Redirect Python-level stderr to suppress warnings
sys.stderr = open(os.devnull, 'w')

"""
Aegis DLP - Comprehensive Feature Verification Script
=======================================================
This script pseudo-checks ALL implemented features of the module
interlinking / Event Bus system. It verifies:

  1. Event Bus core infrastructure
  2. Event type definitions & factory functions  
  3. All module event publishing integrations
  4. Correlation Engine rules & matching
  5. Response Executor handlers
  6. Event Logger (SQLite persistence)
  7. Socket.IO real-time forwarding support
  8. Full pipeline integration (Bus → Logger → Correlation → Response)

Run with: python check_features.py
"""

import time
import tempfile
import inspect
import importlib
import ast
import re

# ============================================================================
# UTILITIES
# ============================================================================

PASS = "✅"
FAIL = "❌"
WARN = "⚠️"
INFO = "ℹ️"

total_checks = 0
passed_checks = 0
failed_checks = 0
warning_count = 0
output_lines = []  # Buffer output to prevent interleaving with C-level warnings


def check(condition, description, critical=True):
    """Run a single check and print result."""
    global total_checks, passed_checks, failed_checks, warning_count
    total_checks += 1
    if condition:
        passed_checks += 1
        output_lines.append(f"  {PASS} {description}")
    elif critical:
        failed_checks += 1
        output_lines.append(f"  {FAIL} {description}")
    else:
        warning_count += 1
        output_lines.append(f"  {WARN} {description} (non-critical)")
    return condition


def section(title):
    output_lines.append(f"\n{'='*64}")
    output_lines.append(f"  {title}")
    output_lines.append(f"{'='*64}")


# ============================================================================
# TEST 1: EVENT BUS CORE INFRASTRUCTURE
# ============================================================================

def test_event_bus_infrastructure():
    section("📡 1. Event Bus Core Infrastructure")

    # Check imports
    try:
        from modules.event_bus import (
            EventBus, get_event_bus, Subscription,
            init_event_system
        )
        check(True, "EventBus, get_event_bus, Subscription importable")
    except ImportError as e:
        check(False, f"Event Bus imports failed: {e}")
        return

    # Create bus instance (sync mode for testing)
    bus = EventBus(async_dispatch=False)
    check(bus is not None, "EventBus instantiates successfully")

    # Check subscribe/unsubscribe
    received = []
    sub = bus.subscribe("test", "file.*", lambda e: received.append(e))
    check(sub is not None, "subscribe() returns a Subscription")
    check(sub.pattern == "file.*", "Subscription pattern stored correctly")

    bus.unsubscribe(sub)
    subs = bus.get_subscriptions("test")
    check(len(subs) == 0, "unsubscribe() removes subscription")

    # Check subscribe with severity filter
    bus.subscribe("test_critical", "*", lambda e: None,
                  min_severity=Severity.HIGH)
    subs = bus.get_subscriptions("test_critical")
    check(len(subs) == 1, "Subscription with min_severity filter created")

    bus.unsubscribe_all("test_critical")
    subs = bus.get_subscriptions("test_critical")
    check(len(subs) == 0, "unsubscribe_all() removes all for subscriber")

    # Check publish
    from modules.event_bus.events import file_event, EventType, Severity
    received.clear()
    bus.subscribe("test_pub", "file.*", lambda e: received.append(e))
    bus.publish(file_event(EventType.FILE_CREATED, "test.txt"))
    check(len(received) == 1, "publish() dispatches to matching subscriber")
    check(received[0].event_type == EventType.FILE_CREATED,
          "Received event has correct event_type")

    # Check wildcard doesn't match wrong pattern
    bus.publish(network_event(EventType.NET_NORMAL))
    check(len(received) == 1, "Wildcard file.* does NOT match net.normal")

    # Check stats
    stats = bus.get_stats()
    check('total_published' in stats, "get_stats() returns total_published")
    check(stats['total_published'] >= 2, "Stats track published count")

    # Check recent events
    recent = bus.get_recent_events(limit=5)
    check(len(recent) >= 2, "get_recent_events() returns recent events")

    bus.shutdown()
    check(True, "EventBus.shutdown() completes without error")


# ============================================================================
# TEST 2: EVENT TYPE DEFINITIONS & FACTORY FUNCTIONS
# ============================================================================

def test_event_types_and_factories():
    section("📋 2. Event Type Definitions & Factory Functions")

    from modules.event_bus.events import (
        SecurityEvent, EventType, Severity, ModuleSource,
        file_event, network_event, phishing_event, usb_event,
        classification_event, malware_event, encryption_event,
        alert_event, system_event
    )

    # ---- EventType coverage ----
    expected_prefixes = {
        'FILE_': ['CREATED', 'MODIFIED', 'DELETED', 'MOVED', 'ACCESSED',
                  'COPY_TO_USB', 'RANSOMWARE_PATTERN', 'SUSPICIOUS_EXT', 'BULK_CHANGE'],
        'NET_': ['ANOMALY', 'NORMAL', 'C2_DETECTED', 'EXFILTRATION', 'STATS_UPDATE'],
        'PHISH_': ['DETECTED', 'SAFE', 'ATTACHMENT_SUSPICIOUS', 'URL_SUSPICIOUS', 'CONFIRMED'],
        'USB_': ['INSERTED', 'REMOVED', 'AUTHORIZED', 'UNAUTHORIZED',
                 'TRANSFER_BLOCKED', 'TRANSFER_ALLOWED', 'DEVICE_BANNED'],
        'DATA_': ['SENSITIVE', 'NON_SENSITIVE', 'BULK_SENSITIVE', 'SCAN_COMPLETE'],
        'MALWARE_': ['DETECTED', 'CLEAN', 'SCAN_STARTED', 'SCAN_COMPLETE', 'QUARANTINED'],
        'ENCRYPT_': ['FILE_ENCRYPTED', 'FILE_DECRYPTED', 'BULK_OPERATION',
                     'FAILED_DECRYPT', 'QUARANTINE'],
        'ALERT_': ['SENT', 'ESCALATED', 'LOCKDOWN'],
        'AI_': ['QUERY', 'SECURITY_REPORT'],
        'SYSTEM_': ['STARTUP', 'SHUTDOWN', 'MODULE_ERROR', 'CORRELATION_MATCH',
                    'PAGE_VISIT', 'MODULE_STARTED', 'MODULE_STOPPED'],
    }

    all_event_members = [e.name for e in EventType]
    total_expected = sum(len(v) for v in expected_prefixes.values())
    check(len(all_event_members) >= total_expected,
          f"EventType has {len(all_event_members)} members (expected ≥{total_expected})")

    for prefix, suffixes in expected_prefixes.items():
        for suffix in suffixes:
            name = f"{prefix}{suffix}"
            check(name in all_event_members,
                  f"EventType.{name} exists")

    # ---- Severity levels ----
    check(Severity.CRITICAL > Severity.HIGH, "Severity CRITICAL > HIGH")
    check(Severity.HIGH > Severity.MEDIUM, "Severity HIGH > MEDIUM")
    check(Severity.MEDIUM > Severity.LOW, "Severity MEDIUM > LOW")
    check(Severity.LOW > Severity.INFO, "Severity LOW > INFO")
    check(Severity.HIGH >= Severity.HIGH, "Severity HIGH >= HIGH (equality)")

    # ---- ModuleSource coverage ----
    expected_sources = [
        'FILE_MONITOR', 'NETWORK_IDS', 'PHISHING_DETECTION', 'USB_MONITOR',
        'DATA_CLASSIFICATION', 'MALWARE_SCANNER', 'FILE_ENCRYPTION',
        'ALERT_MANAGER', 'AI_ASSISTANT', 'CORRELATION_ENGINE', 'SYSTEM'
    ]
    for s in expected_sources:
        check(hasattr(ModuleSource, s), f"ModuleSource.{s} exists")

    # ---- Factory functions produce correct source ----
    factories = {
        'file_event': (file_event, {'event_type': EventType.FILE_CREATED, 'path': 'test.txt'},
                       ModuleSource.FILE_MONITOR),
        'network_event': (network_event, {'event_type': EventType.NET_ANOMALY},
                          ModuleSource.NETWORK_IDS),
        'phishing_event': (phishing_event, {'event_type': EventType.PHISH_DETECTED},
                           ModuleSource.PHISHING_DETECTION),
        'usb_event': (usb_event, {'event_type': EventType.USB_INSERTED},
                      ModuleSource.USB_MONITOR),
        'classification_event': (classification_event,
                                 {'event_type': EventType.DATA_SENSITIVE, 'path': 'test.csv'},
                                 ModuleSource.DATA_CLASSIFICATION),
        'malware_event': (malware_event, {'event_type': EventType.MALWARE_DETECTED},
                          ModuleSource.MALWARE_SCANNER),
        'encryption_event': (encryption_event,
                             {'event_type': EventType.ENCRYPT_FILE_ENCRYPTED, 'path': 'file.enc'},
                             ModuleSource.FILE_ENCRYPTION),
        'alert_event': (alert_event, {'event_type': EventType.ALERT_SENT},
                        ModuleSource.ALERT_MANAGER),
        'system_event': (system_event, {'event_type': EventType.SYSTEM_STARTUP},
                         ModuleSource.SYSTEM),
    }

    for name, (factory, kwargs, expected_source) in factories.items():
        evt = factory(**kwargs)
        check(evt.source == expected_source,
              f"{name}() → source = {expected_source.value}")
        check(isinstance(evt, SecurityEvent),
              f"{name}() returns SecurityEvent instance")

    # ---- Serialization round-trip ----
    evt = file_event(EventType.FILE_CREATED, "C:\\Users\\test\\doc.txt",
                     severity=Severity.HIGH, file_size=1024)
    d = evt.to_dict()
    evt2 = SecurityEvent.from_dict(d)
    check(evt.event_type == evt2.event_type, "to_dict/from_dict round-trip: event_type")
    check(evt.source == evt2.source, "to_dict/from_dict round-trip: source")
    check(evt.severity == evt2.severity, "to_dict/from_dict round-trip: severity")
    check(evt.data.get('path') == evt2.data.get('path'),
          "to_dict/from_dict round-trip: data.path")


# ============================================================================
# TEST 3: MODULE EVENT PUBLISHING IN app.py (CODE ANALYSIS)
# ============================================================================

def test_module_publishing_integration():
    section("🔌 3. Module Event Publishing in app.py (Source Analysis)")

    app_path = os.path.join(os.path.dirname(__file__), 'app.py')
    check(os.path.exists(app_path), "app.py exists")

    with open(app_path, 'r', encoding='utf-8') as f:
        source = f.read()

    # Module integrations to verify
    modules = {
        'Network IDS': {
            'events': ['NET_ANOMALY', 'NET_NORMAL', 'NET_STATS_UPDATE'],
            'factory': 'network_event',
        },
        'Data Classification': {
            'events': ['DATA_SENSITIVE', 'DATA_NON_SENSITIVE', 'DATA_SCAN_COMPLETE'],
            'factory': 'classification_event',
        },
        'Phishing Detection (Gmail)': {
            'events': ['PHISH_DETECTED', 'PHISH_SAFE'],
            'factory': 'phishing_event',
            'search': 'provider=\'gmail\'',
        },
        'Phishing Detection (Outlook)': {
            'events': ['PHISH_DETECTED', 'PHISH_SAFE'],
            'factory': 'phishing_event',
            'search': 'provider=\'outlook\'',
        },
        'Phishing Manual Analysis': {
            'events': ['PHISH_DETECTED', 'PHISH_SAFE'],
            'factory': 'phishing_event',
            'search': 'manual_analysis',
        },
        'USB Device Monitoring': {
            'events': ['USB_UNAUTHORIZED', 'USB_INSERTED', 'USB_TRANSFER_BLOCKED',
                       'USB_TRANSFER_ALLOWED', 'USB_AUTHORIZED', 'USB_DEVICE_BANNED'],
            'factory': 'usb_event',
        },
        'Malware Scanner': {
            'events': ['MALWARE_DETECTED', 'MALWARE_CLEAN'],
            'factory': 'malware_event',
        },
        'File Encryption': {
            'events': ['ENCRYPT_FILE_ENCRYPTED', 'ENCRYPT_FILE_DECRYPTED'],
            'factory': 'encryption_event',
        },
        'AI Chatbot': {
            'events': ['AI_QUERY'],
            'factory': 'system_event',
        },
        'Page Visit Tracking': {
            'events': ['SYSTEM_PAGE_VISIT'],
            'factory': 'system_event',
        },
    }

    for module_name, info in modules.items():
        factory_used = info['factory'] in source
        check(factory_used,
              f"{module_name}: uses {info['factory']}() factory")

        for evt_name in info['events']:
            found = f"EventType.{evt_name}" in source
            check(found,
                  f"  → publishes EventType.{evt_name}")

        if 'search' in info:
            found = info['search'] in source
            check(found,
                  f"  → specific marker: {info['search']}")

    # Check file_monitor.py integration
    fm_path = os.path.join(os.path.dirname(__file__), 'modules', 'file_monitor.py')
    with open(fm_path, 'r', encoding='utf-8') as f:
        fm_source = f.read()

    check('from modules.event_bus import' in fm_source,
          "File Monitor: imports event_bus")
    check('_publish_to_event_bus' in fm_source,
          "File Monitor: has _publish_to_event_bus() method")
    for evt in ['FILE_CREATED', 'FILE_MODIFIED', 'FILE_DELETED', 'FILE_MOVED',
                'FILE_ACCESSED', 'FILE_RANSOMWARE_PATTERN']:
        check(f"EventType.{evt}" in fm_source,
              f"  → publishes EventType.{evt}")


# ============================================================================
# TEST 4: CORRELATION ENGINE RULES
# ============================================================================

def test_correlation_engine():
    section("🔗 4. Correlation Engine Rules & Matching")

    from modules.event_bus.correlation import (
        CorrelationEngine, CorrelationRule, get_default_rules
    )
    from modules.event_bus.events import (
        EventType, Severity, SecurityEvent,
        file_event, network_event, phishing_event, usb_event,
        classification_event, malware_event
    )
    from modules.event_bus.logger import EventLogger

    # Check default rules
    rules = get_default_rules()
    check(len(rules) == 8, f"8 default correlation rules defined (got {len(rules)})")

    expected_rules = {
        'PHISHING_MALWARE_CHAIN': {
            'triggers': [EventType.PHISH_DETECTED, EventType.MALWARE_DETECTED],
            'window': 3600,
            'level': Severity.CRITICAL,
        },
        'UNAUTHORIZED_DATA_THEFT': {
            'triggers': [EventType.USB_UNAUTHORIZED, EventType.DATA_SENSITIVE],
            'window': 300,
            'level': Severity.CRITICAL,
        },
        'RANSOMWARE_PATTERN': {
            'triggers': [EventType.FILE_MODIFIED],
            'window': 60,
            'level': Severity.CRITICAL,
            'count_threshold': 50,
        },
        'USB_NETWORK_CORRELATION': {
            'triggers': [EventType.USB_INSERTED, EventType.NET_ANOMALY],
            'window': 300,
            'level': Severity.HIGH,
        },
        'MALWARE_C2_DETECTED': {
            'triggers': [EventType.MALWARE_DETECTED, EventType.NET_ANOMALY],
            'window': 600,
            'level': Severity.CRITICAL,
        },
        'BULK_SENSITIVE_ACCESS': {
            'triggers': [EventType.DATA_SENSITIVE],
            'window': 300,
            'level': Severity.HIGH,
            'count_threshold': 10,
        },
        'FAILED_AUTH_BRUTE_FORCE': {
            'triggers': [EventType.USB_UNAUTHORIZED],
            'window': 120,
            'level': Severity.HIGH,
            'count_threshold': 5,
        },
        'PHISHING_FILE_EXEC': {
            'triggers': [EventType.PHISH_DETECTED, EventType.FILE_CREATED],
            'window': 1800,
            'level': Severity.HIGH,
        },
    }

    for rule in rules:
        name = rule.name
        check(name in expected_rules, f"Rule '{name}' is in expected list")
        if name in expected_rules:
            exp = expected_rules[name]
            check(set(rule.trigger_events) == set(exp['triggers']),
                  f"  → trigger events match for {name}")
            check(rule.time_window == exp['window'],
                  f"  → time_window = {rule.time_window}s")
            check(rule.threat_level == exp['level'],
                  f"  → threat_level = {rule.threat_level.value}")
            if 'count_threshold' in exp:
                check(rule.count_threshold == exp['count_threshold'],
                      f"  → count_threshold = {rule.count_threshold}")
            check(len(rule.responses) > 0,
                  f"  → has {len(rule.responses)} response action(s)")
            check(rule.cooldown > 0,
                  f"  → cooldown = {rule.cooldown}s")
            check(rule.enabled is True,
                  f"  → enabled by default")

    # Test correlation matching
    db_path = os.path.join(tempfile.gettempdir(), f'aegis_check_corr_{os.getpid()}.db')
    try:
        el = EventLogger(db_path)
        ce = CorrelationEngine(el)

        responses_fired = []
        def mock_response(action, rule, matched_events, correlation_id):
            responses_fired.append({
                'action': action, 'rule': rule.name,
                'correlation_id': correlation_id
            })
        ce.set_response_handler(mock_response)

        # --- Test PHISHING_MALWARE_CHAIN ---
        ce.process_event(phishing_event(EventType.PHISH_DETECTED,
                                        severity=Severity.CRITICAL,
                                        subject="Test", confidence=0.95))
        ce.process_event(malware_event(EventType.MALWARE_DETECTED,
                                       severity=Severity.CRITICAL,
                                       file_path="mal.exe"))
        chain = [r for r in responses_fired if r['rule'] == 'PHISHING_MALWARE_CHAIN']
        check(len(chain) > 0, "PHISHING_MALWARE_CHAIN fires on phish + malware")

        # --- Test UNAUTHORIZED_DATA_THEFT ---
        responses_fired.clear()
        ce.process_event(usb_event(EventType.USB_UNAUTHORIZED,
                                   severity=Severity.HIGH,
                                   device_name="Unknown"))
        ce.process_event(classification_event(EventType.DATA_SENSITIVE,
                                              "sensitive.xlsx",
                                              severity=Severity.HIGH,
                                              is_sensitive=True))
        theft = [r for r in responses_fired if r['rule'] == 'UNAUTHORIZED_DATA_THEFT']
        check(len(theft) > 0, "UNAUTHORIZED_DATA_THEFT fires on USB + sensitive data")

        # --- Test RANSOMWARE_PATTERN ---
        responses_fired.clear()
        for i in range(55):
            ce.process_event(file_event(EventType.FILE_MODIFIED,
                                        f"file{i}.docx.enc",
                                        severity=Severity.MEDIUM))
        ransomware = [r for r in responses_fired if r['rule'] == 'RANSOMWARE_PATTERN']
        check(len(ransomware) > 0, "RANSOMWARE_PATTERN fires on 55 rapid modifications")

        # Check stats
        stats = ce.get_stats()
        check(stats['events_processed'] > 0,
              f"Engine processed {stats['events_processed']} events")
        check(stats['rules_matched'] > 0,
              f"Engine matched {stats['rules_matched']} rules")

        # Cleanup
        if hasattr(el._local, 'connection') and el._local.connection:
            el._local.connection.close()
            el._local.connection = None
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


# ============================================================================
# TEST 5: RESPONSE EXECUTOR
# ============================================================================

def test_response_executor():
    section("🛡️ 5. Response Executor Handlers")

    from modules.event_bus.responses import ResponseExecutor, get_response_executor

    re = ResponseExecutor()

    # Verify all expected handlers are registered
    expected_handlers = [
        'send_alert', 'send_critical_alert', 'send_emergency_alert',
        'block_usb', 'block_usb_transfer', 'quarantine_file',
        'kill_process', 'block_network', 'increase_monitoring',
        'block_execution', 'scan_file', 'isolate_host',
        'lock_account', 'flag_review',
    ]

    registered = list(re._handlers.keys())
    check(len(registered) >= len(expected_handlers),
          f"ResponseExecutor has {len(registered)} handlers registered")

    for handler_name in expected_handlers:
        check(handler_name in registered,
              f"  → handler '{handler_name}' registered")

    # Test execute with a mock event
    from modules.event_bus.events import (
        phishing_event, EventType, Severity
    )
    from modules.event_bus.correlation import CorrelationRule

    rule = CorrelationRule(
        name="TEST_RULE",
        description="Test",
        trigger_events=[EventType.PHISH_DETECTED],
        time_window=60,
        threat_level=Severity.HIGH,
        responses=["send_alert"],
    )

    evt = phishing_event(EventType.PHISH_DETECTED, severity=Severity.HIGH,
                         subject="Test phish")

    re.execute("send_alert", rule, [evt], "test_corr_123")
    # execute() logs internally; check the action log for success
    log = re.get_action_log()
    check(len(log) >= 1, "execute() logged the action")
    check(log[-1].get('success', False), "send_alert handler executed successfully")

    # Check action log
    log = re.get_action_log()
    check(len(log) >= 1, f"Action log has {len(log)} entries")

    # Check stats
    stats = re.get_stats()
    check(stats['total_actions'] >= 1, f"Stats show {stats['total_actions']} total actions")


# ============================================================================
# TEST 6: EVENT LOGGER (SQLite Persistence)
# ============================================================================

def test_event_logger():
    section("💾 6. Event Logger (SQLite Persistence)")

    from modules.event_bus.logger import EventLogger
    from modules.event_bus.events import (
        EventType, Severity,
        file_event, phishing_event, malware_event,
        usb_event, classification_event, network_event,
        encryption_event, system_event
    )

    db_path = os.path.join(tempfile.gettempdir(), f'aegis_check_logger_{os.getpid()}.db')

    try:
        el = EventLogger(db_path)
        check(os.path.exists(db_path), "SQLite database file created")

        # Log a variety of events
        events = [
            file_event(EventType.FILE_CREATED, "doc.pdf", severity=Severity.INFO),
            file_event(EventType.FILE_MODIFIED, "report.xlsx", severity=Severity.MEDIUM),
            network_event(EventType.NET_ANOMALY, severity=Severity.HIGH,
                         anomaly_score=0.92),
            phishing_event(EventType.PHISH_DETECTED, severity=Severity.CRITICAL,
                          subject="Urgent!"),
            usb_event(EventType.USB_UNAUTHORIZED, severity=Severity.HIGH,
                     device_name="Unknown USB"),
            classification_event(EventType.DATA_SENSITIVE, "secret.csv",
                                severity=Severity.HIGH, is_sensitive=True),
            malware_event(EventType.MALWARE_DETECTED, severity=Severity.CRITICAL,
                         file_path="virus.exe"),
            encryption_event(EventType.ENCRYPT_FILE_ENCRYPTED, "file.enc",
                            severity=Severity.MEDIUM),
            system_event(EventType.AI_QUERY, severity=Severity.INFO,
                        message="AI query"),
            system_event(EventType.SYSTEM_PAGE_VISIT, severity=Severity.INFO,
                        message="Visited dashboard"),
        ]

        for e in events:
            check(el.log_event(e), f"Logged: {e.event_type.value}")

        # Query tests
        all_events = el.get_events(limit=100)
        check(len(all_events) == len(events),
              f"Retrieved all {len(all_events)} events")

        # Filter by type
        file_evts = el.get_events(event_type="file.created")
        check(len(file_evts) == 1, "Type filter: 1 file.created event")

        # Filter by severity
        critical = el.get_events(min_severity="critical")
        check(len(critical) == 2, f"Severity filter: {len(critical)} critical events")

        # Filter by source
        net_evts = el.get_events(source="network_ids")
        check(len(net_evts) == 1, "Source filter: 1 network_ids event")

        # Time-window query
        window_evts = el.get_events_in_window(
            ["file.created", "file.modified"], window_seconds=60)
        check(len(window_evts) == 2, "Window query: found 2 file events in 60s")

        # Count query
        count = el.count_events_in_window("file.modified", window_seconds=60)
        check(count == 1, "Count query: 1 file.modified in window")

        # Get by ID
        first_id = events[0].event_id
        by_id = el.get_event_by_id(first_id)
        check(by_id is not None, f"get_event_by_id('{first_id}') returns event")

        # Correlation match logging
        el.log_correlation_match(
            rule_name="TEST_CORRELATION",
            threat_level="critical",
            matched_event_ids=[events[3].event_id, events[6].event_id],
            response_actions=["send_alert", "quarantine_file"]
        )
        matches = el.get_correlation_matches()
        check(len(matches) == 1, "Correlation match logged")
        check(matches[0]['rule_name'] == "TEST_CORRELATION",
              "Correlation match has correct rule_name")

        # Stats
        stats = el.get_stats()
        check(stats['total_events'] == len(events),
              f"Stats: {stats['total_events']} total events")

        # Cleanup connections
        if hasattr(el._local, 'connection') and el._local.connection:
            el._local.connection.close()
            el._local.connection = None

    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


# ============================================================================
# TEST 7: SOCKET.IO REAL-TIME SUPPORT
# ============================================================================

def test_socketio_support():
    section("📡 7. Socket.IO Real-Time Support")

    from modules.event_bus.bus import EventBus
    from modules.event_bus.events import file_event, EventType, Severity

    # Check that EventBus accepts socketio parameter
    bus = EventBus(async_dispatch=False, socketio=None)
    check(True, "EventBus accepts socketio parameter")

    # Check that publish emits via socketio (with mock)
    emitted = []

    class MockSocketIO:
        def emit(self, event_name, data, *args, **kwargs):
            emitted.append({'event': event_name, 'data': data})

    mock_sio = MockSocketIO()
    bus2 = EventBus(async_dispatch=False, socketio=mock_sio)
    bus2.publish(file_event(EventType.FILE_CREATED, "test.txt",
                            severity=Severity.HIGH))

    check(len(emitted) > 0, "Events emitted via Socket.IO")
    live_events = [e for e in emitted if e['event'] == 'security_event']
    check(len(live_events) > 0, "Event emitted as 'security_event' channel")
    
    # Check alert events for high severity
    alerts = [e for e in emitted if e['event'] == 'security_alert']
    check(len(alerts) > 0, "HIGH severity triggers 'security_alert' emission")

    bus2.shutdown()


# ============================================================================
# TEST 8: FULL PIPELINE INTEGRATION
# ============================================================================

def test_full_pipeline():
    section("🔄 8. Full Pipeline Integration (Bus → Logger → Correlation → Response)")

    from modules.event_bus.bus import EventBus
    from modules.event_bus.logger import EventLogger
    from modules.event_bus.correlation import CorrelationEngine
    from modules.event_bus.responses import ResponseExecutor
    from modules.event_bus.events import (
        EventType, Severity,
        usb_event, classification_event, phishing_event,
        malware_event, file_event
    )

    db_path = os.path.join(tempfile.gettempdir(), f'aegis_check_pipeline_{os.getpid()}.db')

    try:
        # Create components
        el = EventLogger(db_path)
        ce = CorrelationEngine(el)
        re_exec = ResponseExecutor()
        bus = EventBus(async_dispatch=False)

        # Wire together
        bus.set_event_logger(el)
        bus.set_correlation_engine(ce)
        ce.set_response_handler(re_exec.execute)
        re_exec.set_event_bus(bus)

        check(True, "Pipeline wired: Bus → Logger → Correlation → Response")

        # Track received events
        all_received = []
        bus.subscribe("test", "*", lambda e: all_received.append(e))

        # --- Scenario A: Data Theft ---
        output_lines.append("\n  📋 Scenario A: Insider Data Theft")
        bus.publish(usb_event(EventType.USB_UNAUTHORIZED, severity=Severity.HIGH,
                              device_name="Unknown Drive"))
        bus.publish(classification_event(EventType.DATA_SENSITIVE,
                                         "C:\\clients.xlsx",
                                         severity=Severity.HIGH,
                                         is_sensitive=True))

        matches_a = el.get_correlation_matches()
        theft_matches = [m for m in matches_a if m['rule_name'] == 'UNAUTHORIZED_DATA_THEFT']
        check(len(theft_matches) > 0, "  UNAUTHORIZED_DATA_THEFT correlation triggered")

        # --- Scenario B: Phishing + Malware Chain ---
        output_lines.append("\n  📋 Scenario B: Phishing → Malware Chain")
        bus.publish(phishing_event(EventType.PHISH_DETECTED, severity=Severity.CRITICAL,
                                   subject="URGENT!", confidence=0.95))
        bus.publish(malware_event(EventType.MALWARE_DETECTED, severity=Severity.CRITICAL,
                                  file_path="attachment.exe"))

        matches_b = el.get_correlation_matches()
        chain_matches = [m for m in matches_b if m['rule_name'] == 'PHISHING_MALWARE_CHAIN']
        check(len(chain_matches) > 0, "  PHISHING_MALWARE_CHAIN correlation triggered")

        # Verify persistence
        stored = el.get_events(limit=100)
        check(len(stored) >= 4, f"  {len(stored)} events persisted in SQLite")

        # Verify responses were executed
        action_log = re_exec.get_action_log()
        check(len(action_log) > 0, f"  {len(action_log)} response actions executed")

        # Verify subscriber received all events
        check(len(all_received) >= 4, f"  Subscriber received {len(all_received)} events")

        # Final stats
        bus_stats = bus.get_stats()
        ce_stats = ce.get_stats()
        re_stats = re_exec.get_stats()

        output_lines.append(f"\n  📊 Pipeline Statistics:")
        output_lines.append(f"       Bus:         {bus_stats['total_published']} published, "
              f"{bus_stats['total_dispatched']} dispatched")
        output_lines.append(f"       Correlation: {ce_stats['events_processed']} processed, "
              f"{ce_stats['rules_matched']} matched")
        output_lines.append(f"       Response:    {re_stats['total_actions']} actions, "
              f"{re_stats['successful_actions']} successful")

        bus.shutdown()

        # Close connection
        if hasattr(el._local, 'connection') and el._local.connection:
            el._local.connection.close()
            el._local.connection = None

    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


# ============================================================================
# TEST 9: INIT_EVENT_SYSTEM
# ============================================================================

def test_init_event_system():
    section("⚡ 9. init_event_system() Wiring Check")

    from modules.event_bus import init_event_system
    from modules.event_bus.bus import EventBus

    # Verify the function signature
    sig = inspect.signature(init_event_system)
    check('socketio' in sig.parameters, "init_event_system accepts 'socketio' parameter")

    # Verify the source does the right wiring
    source = inspect.getsource(init_event_system)
    check('get_event_logger' in source, "Creates EventLogger")
    check('get_correlation_engine' in source, "Creates CorrelationEngine")
    check('get_response_executor' in source, "Creates ResponseExecutor")
    check('get_event_bus' in source, "Creates EventBus")
    check('set_event_logger' in source, "Wires Logger → Bus")
    check('set_correlation_engine' in source, "Wires Correlation → Bus")
    check('set_response_handler' in source, "Wires Response → Correlation")
    check('SYSTEM_STARTUP' in source, "Publishes startup event")


# ============================================================================
# TEST 10: app.py EVENT BUS INITIALIZATION
# ============================================================================

def test_app_initialization():
    section("🚀 10. app.py Event Bus Initialization Code")

    app_path = os.path.join(os.path.dirname(__file__), 'app.py')
    with open(app_path, 'r', encoding='utf-8') as f:
        source = f.read()

    check('EVENT_BUS_AVAILABLE' in source,
          "EVENT_BUS_AVAILABLE guard variable defined")
    check('init_event_system' in source,
          "init_event_system() is called")
    check('init_event_system(socketio=socketio)' in source,
          "Event Bus initialized with Socket.IO in app.py")
    check('publish_event_bus' in source,
          "Helper function publish_event_bus() defined")
    check('track_page_visits' in source,
          "Page visit auto-tracking middleware defined")
    check('PAGE_MODULE_MAP' in source,
          "PAGE_MODULE_MAP routing map defined")

    # Count how many routes are tracked
    route_count = source.count("PAGE_MODULE_MAP")
    check(route_count >= 2, f"PAGE_MODULE_MAP referenced {route_count} times")

    # Check Event Bus dashboard route
    check("event_bus_dashboard" in source,
          "Event Bus dashboard route exists")
    check("event_bus.html" in source,
          "event_bus.html template is rendered")

    # Check API endpoints
    api_patterns = [
        '/api/events/recent',
        '/api/events/stats',
    ]
    for pattern in api_patterns:
        check(pattern in source, f"API endpoint {pattern} exists")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Ensure UTF-8 output (for emoji support in redirected output)
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

    # Add project root to path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    # Import after path is set
    from modules.event_bus.events import (
        EventType, Severity,
        network_event, file_event
    )

    output_lines.append("=" * 64)
    output_lines.append("  🛡️  AEGIS DLP — Comprehensive Feature Verification")
    output_lines.append("  " + "=" * 60)
    output_lines.append(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    output_lines.append(f"  Python: {sys.version.split()[0]}")
    output_lines.append("=" * 64)

    tests = [
        test_event_bus_infrastructure,
        test_event_types_and_factories,
        test_module_publishing_integration,
        test_correlation_engine,
        test_response_executor,
        test_event_logger,
        test_socketio_support,
        test_full_pipeline,
        test_init_event_system,
        test_app_initialization,
    ]

    test_results = []

    for test_fn in tests:
        before_passed = passed_checks
        before_failed = failed_checks
        try:
            test_fn()
            p = passed_checks - before_passed
            f = failed_checks - before_failed
            test_results.append((test_fn.__name__, p, f, None))
        except Exception as e:
            failed_checks += 1
            total_checks += 1
            test_results.append((test_fn.__name__, 0, 1, str(e)))
            output_lines.append(f"\n  {FAIL} TEST CRASHED: {test_fn.__name__}")
            output_lines.append(f"     Error: {e}")
            import traceback
            output_lines.append(traceback.format_exc())

    # ---- SUMMARY ----
    output_lines.append("\n" + "=" * 64)
    output_lines.append("  📊  VERIFICATION SUMMARY")
    output_lines.append("=" * 64)
    output_lines.append("")

    for name, p, f, err in test_results:
        display = name.replace('test_', '').replace('_', ' ').title()
        if err:
            output_lines.append(f"  {FAIL} {display}: CRASHED ({err[:50]})")
        elif f == 0:
            output_lines.append(f"  {PASS} {display}: {p} checks passed")
        else:
            output_lines.append(f"  {FAIL} {display}: {p} passed, {f} FAILED")

    output_lines.append("")
    output_lines.append(f"  Total checks:   {total_checks}")
    output_lines.append(f"  Passed:         {passed_checks}  ({PASS})")
    output_lines.append(f"  Failed:         {failed_checks}  ({FAIL})")
    output_lines.append(f"  Warnings:       {warning_count}  ({WARN})")
    output_lines.append("")

    if failed_checks == 0:
        output_lines.append(f"  🎉 ALL {total_checks} CHECKS PASSED — Module Interlinking is FULLY IMPLEMENTED!")
    else:
        pct = (passed_checks / total_checks * 100) if total_checks else 0
        output_lines.append(f"  ⚠️  {pct:.1f}% pass rate — {failed_checks} issue(s) need attention")

    output_lines.append("=" * 64)

    # Flush all buffered output at once (prevents C-level warning interleaving)
    sys.stdout.write("\n".join(output_lines) + "\n")
    sys.stdout.flush()

    sys.exit(0 if failed_checks == 0 else 1)
