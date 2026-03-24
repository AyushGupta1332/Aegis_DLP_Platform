"""
Aegis DLP - Event System Integration Test
============================================
Tests the complete event pipeline:
  Event → Bus → Logger → Correlation → Response

Run with: python -m modules.event_bus.test_integration
"""

import sys
import os
import time
import tempfile
import threading

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.event_bus.events import (
    SecurityEvent, EventType, Severity, ModuleSource,
    file_event, network_event, phishing_event, usb_event,
    classification_event, malware_event, system_event
)
from modules.event_bus.bus import EventBus
from modules.event_bus.logger import EventLogger
from modules.event_bus.correlation import CorrelationEngine, get_default_rules
from modules.event_bus.responses import ResponseExecutor


def test_event_creation():
    """Test event factory functions."""
    print("\n📋 Test 1: Event Creation")
    print("-" * 40)
    
    events = [
        file_event(EventType.FILE_CREATED, "C:\\Users\\test\\doc.pdf", 
                    severity=Severity.INFO, file_size=1024),
        network_event(EventType.NET_ANOMALY, severity=Severity.HIGH,
                      anomaly_score=0.92, src_ip="192.168.1.100"),
        phishing_event(EventType.PHISH_DETECTED, severity=Severity.CRITICAL,
                       subject="URGENT: Verify now!", confidence=0.94),
        usb_event(EventType.USB_UNAUTHORIZED, severity=Severity.HIGH,
                  device_name="Unknown Drive", drive_letter="E:"),
        classification_event(EventType.DATA_SENSITIVE, "C:\\data\\clients.xlsx",
                             severity=Severity.HIGH, confidence=0.97),
        malware_event(EventType.MALWARE_DETECTED, severity=Severity.CRITICAL,
                      file_path="invoice.exe", detection_name="Trojan.Gen"),
    ]
    
    for e in events:
        d = e.to_dict()
        # Verify round-trip
        e2 = SecurityEvent.from_dict(d)
        assert e.event_type == e2.event_type
        assert e.source == e2.source
        assert e.severity == e2.severity
        print(f"  ✅ {e.event_type.value}: {e.source.value} ({e.severity.value})")
    
    # Test severity comparison
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.INFO < Severity.MEDIUM
    assert Severity.HIGH >= Severity.HIGH
    print(f"  ✅ Severity comparison works")
    print(f"  Created {len(events)} events successfully")


def test_event_bus():
    """Test pub/sub with the Event Bus."""
    print("\n📡 Test 2: Event Bus (Pub/Sub)")
    print("-" * 40)
    
    bus = EventBus(async_dispatch=False)  # Sync for testing
    received = []
    
    def on_file_event(event):
        received.append(event)
    
    def on_critical(event):
        received.append(('critical', event))
    
    # Subscribe
    bus.subscribe("test_sub", "file.*", on_file_event, 
                  description="Test file handler")
    bus.subscribe("test_critical", "*", on_critical,
                  min_severity=Severity.CRITICAL,
                  description="Critical events only")
    
    # Publish events
    bus.publish(file_event(EventType.FILE_CREATED, "test.txt"))
    bus.publish(file_event(EventType.FILE_MODIFIED, "test.txt"))
    bus.publish(network_event(EventType.NET_NORMAL))  # Should NOT match file.*
    bus.publish(file_event(EventType.FILE_RANSOMWARE_PATTERN, "virus.encrypted",
                           severity=Severity.CRITICAL))
    
    assert len(received) == 4  # 3 file events + 1 critical
    file_events = [e for e in received if isinstance(e, SecurityEvent)]
    critical_events = [e for e in received if isinstance(e, tuple)]
    
    assert len(file_events) == 3
    assert len(critical_events) == 1
    
    print(f"  ✅ Published 4 events")
    print(f"  ✅ File subscriber received {len(file_events)} events")
    print(f"  ✅ Critical subscriber received {len(critical_events)} events")
    print(f"  ✅ Wildcard filtering works correctly")
    
    stats = bus.get_stats()
    print(f"  ✅ Stats: {stats['total_published']} published, {stats['total_dispatched']} dispatched")
    
    bus.shutdown()


def test_event_logger():
    """Test SQLite persistence."""
    print("\n💾 Test 3: Event Logger (SQLite)")
    print("-" * 40)
    
    # Use temp database
    db_path = os.path.join(tempfile.gettempdir(), f'aegis_test_logger_{os.getpid()}.db')
    
    try:
        el = EventLogger(db_path)
        
        # Log events
        events = [
            file_event(EventType.FILE_CREATED, "doc1.pdf", severity=Severity.INFO),
            file_event(EventType.FILE_MODIFIED, "doc2.xlsx", severity=Severity.MEDIUM),
            phishing_event(EventType.PHISH_DETECTED, severity=Severity.CRITICAL,
                           subject="Test Phishing"),
            malware_event(EventType.MALWARE_DETECTED, severity=Severity.CRITICAL,
                          file_path="mal.exe"),
        ]
        
        for e in events:
            assert el.log_event(e)
        
        print(f"  ✅ Logged {len(events)} events to SQLite")
        
        # Query events
        all_events = el.get_events(limit=10)
        assert len(all_events) == 4
        print(f"  ✅ Retrieved {len(all_events)} events")
        
        # Filter by type
        file_events = el.get_events(event_type="file.created")
        assert len(file_events) == 1
        print(f"  ✅ Type filter: found {len(file_events)} file.created events")
        
        # Filter by severity
        critical = el.get_events(min_severity="critical")
        assert len(critical) == 2
        print(f"  ✅ Severity filter: found {len(critical)} critical events")
        
        # Stats
        stats = el.get_stats()
        assert stats['total_events'] == 4
        print(f"  ✅ Stats: {stats['total_events']} total events")
        
        # Correlation match logging
        el.log_correlation_match(
            rule_name="PHISHING_MALWARE_CHAIN",
            threat_level="critical",
            matched_event_ids=[events[2].event_id, events[3].event_id],
            response_actions=["quarantine_file", "send_alert"]
        )
        
        matches = el.get_correlation_matches()
        assert len(matches) == 1
        assert matches[0]['rule_name'] == "PHISHING_MALWARE_CHAIN"
        print(f"  ✅ Correlation match logged and retrieved")
        
        # Close connection before cleanup
        if hasattr(el._local, 'connection') and el._local.connection:
            el._local.connection.close()
            el._local.connection = None
        
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass  # Windows may still hold the file


def test_correlation_engine():
    """Test correlation rule matching."""
    print("\n🔗 Test 4: Correlation Engine")
    print("-" * 40)
    
    db_path = os.path.join(tempfile.gettempdir(), f'aegis_test_corr_{os.getpid()}.db')
    
    try:
        el = EventLogger(db_path)
        ce = CorrelationEngine(el)
        
        # Track responses
        responses_fired = []
        def mock_response(action, rule, matched_events, correlation_id):
            responses_fired.append({
                'action': action,
                'rule': rule.name,
                'event_count': len(matched_events),
            })
        
        ce.set_response_handler(mock_response)
        
        rules = ce.get_rules()
        print(f"  ✅ Loaded {len(rules)} correlation rules:")
        for r in rules:
            print(f"       • {r['name']} ({r['threat_level']}): {r['description'][:50]}...")
        
        # Test Rule 1: PHISHING_MALWARE_CHAIN
        # Simulate: phishing email detected, then malware found
        phish = phishing_event(EventType.PHISH_DETECTED, severity=Severity.CRITICAL,
                                subject="URGENT: Verify account", confidence=0.94)
        malware = malware_event(EventType.MALWARE_DETECTED, severity=Severity.CRITICAL,
                                 file_path="invoice.pdf.exe", detection_name="Trojan.Gen")
        
        ce.process_event(phish)
        ce.process_event(malware)
        
        # Should have fired PHISHING_MALWARE_CHAIN
        chain_matches = [r for r in responses_fired if r['rule'] == 'PHISHING_MALWARE_CHAIN']
        assert len(chain_matches) > 0, "PHISHING_MALWARE_CHAIN should have fired"
        print(f"  ✅ PHISHING_MALWARE_CHAIN fired! ({len(chain_matches[0]['action'])} response)")
        
        # Test Rule 3: RANSOMWARE_PATTERN (count-based)
        responses_fired.clear()
        
        for i in range(55):
            e = file_event(EventType.FILE_MODIFIED, f"file{i}.docx.encrypted",
                           severity=Severity.MEDIUM)
            ce.process_event(e)
        
        ransomware_matches = [r for r in responses_fired if r['rule'] == 'RANSOMWARE_PATTERN']
        assert len(ransomware_matches) > 0, "RANSOMWARE_PATTERN should have fired"
        print(f"  ✅ RANSOMWARE_PATTERN fired after 55 file modifications!")
        
        stats = ce.get_stats()
        print(f"  ✅ Engine stats: {stats['events_processed']} processed, "
              f"{stats['rules_matched']} matched")
        
        # Close connection before cleanup
        if hasattr(el._local, 'connection') and el._local.connection:
            el._local.connection.close()
            el._local.connection = None
        
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


def test_full_pipeline():
    """Test the complete pipeline: Bus → Logger → Correlation → Response."""
    print("\n🔄 Test 5: Full Pipeline Integration")
    print("-" * 40)
    
    db_path = os.path.join(tempfile.gettempdir(), f'aegis_test_pipeline_{os.getpid()}.db')
    
    try:
        # Create components
        el = EventLogger(db_path)
        ce = CorrelationEngine(el)
        re = ResponseExecutor()
        bus = EventBus(async_dispatch=False)
        
        # Wire together
        bus.set_event_logger(el)
        bus.set_correlation_engine(ce)
        ce.set_response_handler(re.execute)
        re.set_event_bus(bus)
        
        # Track all events received by a test subscriber
        all_received = []
        bus.subscribe("test_monitor", "*", lambda e: all_received.append(e),
                      description="Catch-all test monitor")
        
        print("  ✅ Pipeline wired: Bus → Logger → Correlation → Response")
        
        # Simulate Scenario 2 from MODULE_INTERLINKING.md: Data Theft
        print("\n  📋 Simulating: Insider Data Theft Scenario")
        print("  " + "-" * 38)
        
        # Step 1: USB device inserted (unauthorized)
        bus.publish(usb_event(
            EventType.USB_UNAUTHORIZED,
            severity=Severity.HIGH,
            device_name="Personal USB Drive",
            drive_letter="F:",
            is_registered=False,
        ))
        print("  → USB_UNAUTHORIZED published")
        
        # Step 2: Sensitive data detected
        bus.publish(classification_event(
            EventType.DATA_SENSITIVE,
            "C:\\Work\\client_database.xlsx",
            severity=Severity.HIGH,
            is_sensitive=True,
            confidence=0.97,
        ))
        print("  → DATA_SENSITIVE published")
        
        # Verify pipeline
        assert el.get_stats()['total_events'] >= 2  # At least our 2 events
        print(f"  ✅ Events persisted: {el.get_stats()['total_events']}")
        
        # Check correlation matches
        matches = el.get_correlation_matches()
        data_theft_matches = [m for m in matches if m['rule_name'] == 'UNAUTHORIZED_DATA_THEFT']
        assert len(data_theft_matches) > 0, "UNAUTHORIZED_DATA_THEFT should have triggered"
        print(f"  ✅ UNAUTHORIZED_DATA_THEFT correlation matched!")
        
        # Check response actions
        action_log = re.get_action_log()
        assert len(action_log) > 0
        print(f"  ✅ Response actions executed: {len(action_log)}")
        for a in action_log:
            status = "✅" if a['success'] else "❌"
            print(f"       {status} {a['action']} ({a['elapsed_ms']}ms)")
        
        # Final stats
        bus_stats = bus.get_stats()
        ce_stats = ce.get_stats()
        re_stats = re.get_stats()
        
        print(f"\n  📊 Final Statistics:")
        print(f"       Bus: {bus_stats['total_published']} published, "
              f"{bus_stats['total_dispatched']} dispatched")
        print(f"       Correlation: {ce_stats['rules_matched']} rules matched")
        print(f"       Response: {re_stats['total_actions']} actions executed")
        
        bus.shutdown()
        
        # Close connection before cleanup
        if hasattr(el._local, 'connection') and el._local.connection:
            el._local.connection.close()
            el._local.connection = None
        
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


def main():
    """Run all integration tests."""
    print("=" * 60)
    print("  🛡️ AEGIS DLP - Event System Integration Tests")
    print("=" * 60)
    
    tests = [
        test_event_creation,
        test_event_bus,
        test_event_logger,
        test_correlation_engine,
        test_full_pipeline,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"\n  ❌ FAILED: {test.__name__}")
            print(f"     Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"  Results: {passed} passed, {failed} failed")
    if failed == 0:
        print("  🎉 ALL TESTS PASSED!")
    else:
        print("  ⚠️ SOME TESTS FAILED")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
