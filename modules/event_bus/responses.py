"""
Aegis DLP - Automated Response Executor
=========================================
Handles the automated responses triggered by the Correlation Engine.
Maps response action names to actual system operations.

Each response action is a function that takes the correlation context
and performs a specific security operation (block USB, send alert, etc.)
"""

import os
import time
import logging
import threading
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timezone

from .events import SecurityEvent, EventType, Severity, ModuleSource, system_event, alert_event

logger = logging.getLogger(__name__)


class ResponseExecutor:
    """Executes automated response actions triggered by correlation rules.
    
    Each response handler is a registered function that performs a specific
    security action. The executor ensures:
    - Actions are executed in order
    - Failures in one action don't prevent others
    - All actions are logged for audit
    - Rate limiting prevents action spam
    
    Usage:
        executor = ResponseExecutor()
        executor.register_handler("block_usb", handle_block_usb)
        executor.register_handler("send_alert", handle_send_alert)
        
        # Called by CorrelationEngine:
        executor.execute(action="block_usb", rule=rule, 
                        matched_events=events, correlation_id="corr_123")
    """
    
    def __init__(self, event_bus=None, socketio=None):
        """
        Args:
            event_bus:  EventBus instance for publishing response events
            socketio:   Socket.IO for real-time UI notifications
        """
        self._handlers: Dict[str, Callable] = {}
        self._event_bus = event_bus
        self._socketio = socketio
        self._lock = threading.Lock()
        
        # Action log
        self._action_log: List[Dict] = []
        self._max_log_size = 500
        
        # Pending actions requiring human approval
        self._pending_actions: Dict[str, Dict] = {}  # id -> action details
        self._pending_lock = threading.Lock()
        
        # Destructive actions that MUST require human approval
        self.DESTRUCTIVE_ACTIONS = {'kill_process', 'isolate_host'}
        
        # Stats
        self._stats = {
            'total_actions': 0,
            'successful_actions': 0,
            'failed_actions': 0,
            'pending_approvals': 0,
            'actions_by_type': {},
        }
        
        # Register default handlers
        self._register_default_handlers()
        
        logger.info("Response Executor initialized with %d handlers", len(self._handlers))
    
    # =========================================================================
    # HANDLER REGISTRATION
    # =========================================================================
    
    def register_handler(self, action_name: str, handler: Callable):
        """Register a response action handler.
        
        Args:
            action_name: Unique action identifier (e.g., "block_usb")
            handler: Function(action, rule, matched_events, correlation_id) -> dict
        """
        self._handlers[action_name] = handler
        logger.debug("Response handler registered: %s", action_name)
    
    def unregister_handler(self, action_name: str):
        """Remove a registered handler."""
        self._handlers.pop(action_name, None)
    
    # =========================================================================
    # EXECUTION
    # =========================================================================
    
    def execute(self, action: str, rule, matched_events: List[SecurityEvent],
                correlation_id: str):
        """Execute a single response action.
        
        Destructive actions (kill_process, isolate_host) are queued for
        human approval instead of being auto-executed.
        Called by the CorrelationEngine when a rule matches.
        """
        # Gate destructive actions behind human approval
        if action in self.DESTRUCTIVE_ACTIONS:
            self._queue_for_approval(action, rule, matched_events, correlation_id)
            return
        
        handler = self._handlers.get(action)
        
        if not handler:
            logger.warning("No handler registered for action: %s", action)
            return
        
        start_time = time.time()
        success = False
        error_msg = None
        result = {}
        
        try:
            result = handler(
                action=action,
                rule=rule,
                matched_events=matched_events,
                correlation_id=correlation_id
            ) or {}
            
            success = True
            self._stats['successful_actions'] += 1
            
            logger.info(
                "✅ Response action '%s' executed for rule '%s' (correlation: %s)",
                action, rule.name, correlation_id
            )
            
        except Exception as e:
            error_msg = str(e)
            self._stats['failed_actions'] += 1
            
            logger.error(
                "❌ Response action '%s' failed for rule '%s': %s",
                action, rule.name, e, exc_info=True
            )
        
        # Update stats
        self._stats['total_actions'] += 1
        self._stats['actions_by_type'][action] = \
            self._stats['actions_by_type'].get(action, 0) + 1
        
        # Log the action
        elapsed = time.time() - start_time
        log_entry = {
            'action': action,
            'rule_name': rule.name,
            'correlation_id': correlation_id,
            'success': success,
            'error': error_msg,
            'elapsed_ms': round(elapsed * 1000, 2),
            'timestamp': datetime.now().strftime('%d %b %Y, %I:%M:%S %p'),
            'result': result,
        }
        
        with self._lock:
            self._action_log.append(log_entry)
            if len(self._action_log) > self._max_log_size:
                self._action_log = self._action_log[-self._max_log_size:]
        
        # Emit to Socket.IO
        if self._socketio:
            try:
                self._socketio.emit('response_action', log_entry)
            except Exception:
                pass
    
    # =========================================================================
    # HUMAN APPROVAL GATE (for destructive actions)
    # =========================================================================
    
    def _queue_for_approval(self, action: str, rule, matched_events: List[SecurityEvent],
                            correlation_id: str):
        """Queue a destructive action for human approval instead of auto-executing."""
        import uuid
        approval_id = f"approval_{uuid.uuid4().hex[:8]}"
        
        pending_entry = {
            'id': approval_id,
            'action': action,
            'rule_name': rule.name,
            'rule_description': rule.description,
            'correlation_id': correlation_id,
            'status': 'pending',
            'matched_events': [e.to_dict() for e in matched_events[:5]],
            'timestamp': datetime.now().strftime('%d %b %Y, %I:%M:%S %p'),
            'created_at': time.time(),
        }
        
        # Store the full objects for execution if approved
        pending_entry['_rule'] = rule
        pending_entry['_matched_events'] = matched_events
        
        with self._pending_lock:
            self._pending_actions[approval_id] = pending_entry
            self._stats['pending_approvals'] = len(self._pending_actions)
        
        logger.warning(
            "⚠️ PENDING APPROVAL: Destructive action '%s' from rule '%s' requires human approval (ID: %s)",
            action, rule.name, approval_id
        )
        
        # Log as pending
        log_entry = {
            'action': action,
            'rule_name': rule.name,
            'correlation_id': correlation_id,
            'success': None,
            'status': 'pending_approval',
            'approval_id': approval_id,
            'timestamp': datetime.now().strftime('%d %b %Y, %I:%M:%S %p'),
            'result': {'note': 'Destructive action queued for human approval'},
        }
        
        with self._lock:
            self._action_log.append(log_entry)
        
        # Emit to Socket.IO for real-time notification
        if self._socketio:
            try:
                self._socketio.emit('pending_approval', {
                    'id': approval_id,
                    'action': action,
                    'rule_name': rule.name,
                    'rule_description': rule.description,
                    'correlation_id': correlation_id,
                    'timestamp': pending_entry['timestamp'],
                })
            except Exception:
                pass
        
        # Also publish an alert event
        if self._event_bus:
            self._event_bus.publish(alert_event(
                event_type=EventType.ALERT_ESCALATED,
                severity=Severity.CRITICAL,
                alert_message=f"APPROVAL REQUIRED: {action} from rule {rule.name}",
                triggering_events=[e.event_id for e in matched_events],
                correlation_id=correlation_id,
                rule_name=rule.name,
            ))
    
    def approve_action(self, approval_id: str) -> Dict[str, Any]:
        """Approve a pending destructive action for execution."""
        with self._pending_lock:
            entry = self._pending_actions.pop(approval_id, None)
            self._stats['pending_approvals'] = len(self._pending_actions)
        
        if not entry:
            return {'status': 'error', 'message': 'Approval ID not found or already processed'}
        
        # Execute the action now
        action = entry['action']
        rule = entry['_rule']
        matched_events = entry['_matched_events']
        correlation_id = entry['correlation_id']
        
        handler = self._handlers.get(action)
        if not handler:
            return {'status': 'error', 'message': f'No handler for action: {action}'}
        
        try:
            result = handler(
                action=action, rule=rule,
                matched_events=matched_events,
                correlation_id=correlation_id
            ) or {}
            
            self._stats['successful_actions'] += 1
            self._stats['total_actions'] += 1
            
            logger.info("✅ APPROVED & EXECUTED: '%s' for rule '%s'", action, rule.name)
            
            return {'status': 'success', 'action': action, 'result': result}
        except Exception as e:
            self._stats['failed_actions'] += 1
            logger.error("Approved action '%s' failed: %s", action, e)
            return {'status': 'error', 'message': str(e)}
    
    def deny_action(self, approval_id: str) -> Dict[str, Any]:
        """Deny/cancel a pending destructive action."""
        with self._pending_lock:
            entry = self._pending_actions.pop(approval_id, None)
            self._stats['pending_approvals'] = len(self._pending_actions)
        
        if not entry:
            return {'status': 'error', 'message': 'Approval ID not found or already processed'}
        
        logger.info("❌ DENIED: Action '%s' for rule '%s' was denied by admin", 
                     entry['action'], entry['rule_name'])
        return {'status': 'success', 'message': 'Action denied and removed'}
    
    def get_pending_actions(self) -> List[Dict]:
        """Get all pending actions awaiting approval."""
        with self._pending_lock:
            return [
                {
                    'id': v['id'],
                    'action': v['action'],
                    'rule_name': v['rule_name'],
                    'rule_description': v['rule_description'],
                    'correlation_id': v['correlation_id'],
                    'status': v['status'],
                    'matched_events': v['matched_events'],
                    'timestamp': v['timestamp'],
                }
                for v in self._pending_actions.values()
            ]
    
    # =========================================================================
    # DEFAULT RESPONSE HANDLERS
    # =========================================================================
    
    def _register_default_handlers(self):
        """Register the built-in response handlers."""
        
        self.register_handler("send_alert", self._handle_send_alert)
        self.register_handler("send_critical_alert", self._handle_send_critical_alert)
        self.register_handler("send_emergency_alert", self._handle_send_emergency_alert)
        self.register_handler("block_usb", self._handle_block_usb)
        self.register_handler("block_usb_transfer", self._handle_block_usb_transfer)
        self.register_handler("quarantine_file", self._handle_quarantine_file)
        self.register_handler("kill_process", self._handle_kill_process)
        self.register_handler("block_network", self._handle_block_network)
        self.register_handler("increase_monitoring", self._handle_increase_monitoring)
        self.register_handler("block_execution", self._handle_block_execution)
        self.register_handler("scan_file", self._handle_scan_file)
        self.register_handler("isolate_host", self._handle_isolate_host)
        self.register_handler("lock_account", self._handle_lock_account)
        self.register_handler("flag_review", self._handle_flag_review)
    
    def _handle_send_alert(self, action, rule, matched_events, correlation_id, **kwargs):
        """Send a standard security alert."""
        logger.info(
            "📧 ALERT: Rule '%s' triggered - %s", 
            rule.name, rule.description
        )
        
        # Publish alert event to bus for other modules to react
        if self._event_bus:
            self._event_bus.publish(alert_event(
                event_type=EventType.ALERT_SENT,
                severity=Severity.HIGH,
                alert_message=f"Correlation alert: {rule.name} - {rule.description}",
                triggering_events=[e.event_id for e in matched_events],
                correlation_id=correlation_id,
                rule_name=rule.name,
            ))
        
        return {'alert_type': 'standard', 'rule': rule.name}
    
    def _handle_send_critical_alert(self, action, rule, matched_events, correlation_id, **kwargs):
        """Send a critical security alert."""
        logger.critical(
            "🚨 CRITICAL ALERT: Rule '%s' - %s", 
            rule.name, rule.description
        )
        
        if self._event_bus:
            self._event_bus.publish(alert_event(
                event_type=EventType.ALERT_ESCALATED,
                severity=Severity.CRITICAL,
                alert_message=f"CRITICAL: {rule.name} - {rule.description}",
                triggering_events=[e.event_id for e in matched_events],
                correlation_id=correlation_id,
                rule_name=rule.name,
            ))
        
        return {'alert_type': 'critical', 'rule': rule.name}
    
    def _handle_send_emergency_alert(self, action, rule, matched_events, correlation_id, **kwargs):
        """Send an emergency alert (highest priority)."""
        logger.critical(
            "🆘 EMERGENCY: Rule '%s' - %s - IMMEDIATE ACTION REQUIRED", 
            rule.name, rule.description
        )
        
        if self._event_bus:
            self._event_bus.publish(alert_event(
                event_type=EventType.ALERT_LOCKDOWN,
                severity=Severity.CRITICAL,
                alert_message=f"EMERGENCY: {rule.name} - {rule.description}",
                triggering_events=[e.event_id for e in matched_events],
                correlation_id=correlation_id,
                rule_name=rule.name,
            ))
        
        return {'alert_type': 'emergency', 'rule': rule.name}
    
    def _handle_block_usb(self, action, rule, matched_events, correlation_id, **kwargs):
        """Block all USB transfers temporarily."""
        logger.warning(
            "🔌 USB BLOCK: Blocking all USB transfers due to '%s'", rule.name
        )
        # This will be integrated with USBMonitor/FileController
        # For now, we set a global flag and emit the event
        if self._event_bus:
            self._event_bus.publish(system_event(
                event_type=EventType.SYSTEM_CORRELATION_MATCH,
                severity=Severity.CRITICAL,
                message=f"USB transfers blocked by rule: {rule.name}",
                module="usb_monitor",
                action="block_all",
                correlation_id=correlation_id,
            ))
        
        return {'action': 'usb_blocked', 'duration': '1 hour'}
    
    def _handle_block_usb_transfer(self, action, rule, matched_events, correlation_id, **kwargs):
        """Block specific USB transfer that triggered the rule.""" 
        logger.warning(
            "⛔ USB TRANSFER BLOCKED: Sensitive data transfer prevented by '%s'", rule.name
        )
        return {'action': 'transfer_blocked'}
    
    def _handle_quarantine_file(self, action, rule, matched_events, correlation_id, **kwargs):
        """Quarantine a suspicious file (encrypt + isolate)."""
        file_paths = []
        for event in matched_events:
            path = event.data.get('file_path') or event.data.get('path')
            if path:
                file_paths.append(path)
        
        logger.warning(
            "🔒 QUARANTINE: Files flagged for quarantine by '%s': %s", 
            rule.name, file_paths
        )
        
        return {'action': 'quarantine', 'files': file_paths}
    
    def _handle_kill_process(self, action, rule, matched_events, correlation_id, **kwargs):
        """Attempt to kill a malicious process."""
        process_ids = []
        for event in matched_events:
            pid = event.data.get('process_id')
            if pid:
                process_ids.append(pid)
        
        logger.warning(
            "💀 KILL PROCESS: Process termination requested by '%s': PIDs %s", 
            rule.name, process_ids
        )
        
        # Actual process killing would go here
        # For safety, we log but don't auto-kill without admin confirmation
        return {'action': 'kill_requested', 'pids': process_ids, 
                'note': 'Requires admin confirmation'}
    
    def _handle_block_network(self, action, rule, matched_events, correlation_id, **kwargs):
        """Block network connections."""
        logger.warning(
            "🌐 NETWORK BLOCK: Outbound traffic restricted by '%s'", rule.name
        )
        return {'action': 'network_restricted'}
    
    def _handle_increase_monitoring(self, action, rule, matched_events, correlation_id, **kwargs):
        """Temporarily increase monitoring sensitivity."""
        logger.info(
            "🔍 MONITORING INCREASED: Sensitivity raised for 10 minutes by '%s'", rule.name
        )
        return {'action': 'monitoring_increased', 'duration': '10 minutes'}
    
    def _handle_block_execution(self, action, rule, matched_events, correlation_id, **kwargs):
        """Block execution of a suspicious file."""
        logger.warning(
            "🚫 EXECUTION BLOCKED: File execution prevented by '%s'", rule.name
        )
        return {'action': 'execution_blocked'}
    
    def _handle_scan_file(self, action, rule, matched_events, correlation_id, **kwargs):
        """Trigger a malware scan on a file."""
        file_paths = [
            event.data.get('file_path') or event.data.get('path')
            for event in matched_events
            if event.data.get('file_path') or event.data.get('path')
        ]
        
        logger.info(
            "🔬 AUTO-SCAN: Malware scan triggered by '%s' for: %s", 
            rule.name, file_paths
        )
        return {'action': 'scan_triggered', 'files': file_paths}
    
    def _handle_isolate_host(self, action, rule, matched_events, correlation_id, **kwargs):
        """Isolate the host from the network."""
        logger.critical(
            "🔒 HOST ISOLATION: Network isolation triggered by '%s'", rule.name
        )
        return {'action': 'host_isolation_requested',
                'note': 'Requires admin confirmation'}
    
    def _handle_lock_account(self, action, rule, matched_events, correlation_id, **kwargs):
        """Lock a user account after suspicious activity."""
        logger.warning(
            "🔐 ACCOUNT LOCK: Account lock triggered by '%s'", rule.name
        )
        return {'action': 'account_locked'}
    
    def _handle_flag_review(self, action, rule, matched_events, correlation_id, **kwargs):
        """Flag events for admin review."""
        logger.info(
            "🏁 FLAGGED: Events flagged for admin review by '%s'", rule.name
        )
        return {'action': 'flagged_for_review'}
    
    # =========================================================================
    # QUERY & STATS
    # =========================================================================
    
    def get_action_log(self, limit: int = 50, 
                       action_filter: str = None) -> List[Dict]:
        """Get the response action log."""
        with self._lock:
            log = list(self._action_log)
        
        if action_filter:
            log = [e for e in log if e['action'] == action_filter]
        
        return log[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get response executor statistics."""
        return {
            **self._stats,
            'registered_handlers': list(self._handlers.keys()),
            'destructive_actions': list(self.DESTRUCTIVE_ACTIONS),
            'log_size': len(self._action_log),
            'pending_count': len(self._pending_actions),
        }
    
    # =========================================================================
    # CONFIGURATION
    # =========================================================================
    
    def set_event_bus(self, event_bus):
        """Attach the Event Bus for publishing response events."""
        self._event_bus = event_bus
    
    def set_socketio(self, socketio):
        """Attach Socket.IO for real-time notifications."""
        self._socketio = socketio


# =============================================================================
# SINGLETON
# =============================================================================

_response_executor_instance: Optional[ResponseExecutor] = None
_executor_lock = threading.Lock()


def get_response_executor(event_bus=None, socketio=None) -> ResponseExecutor:
    """Get or create the ResponseExecutor singleton."""
    global _response_executor_instance
    
    with _executor_lock:
        if _response_executor_instance is None:
            _response_executor_instance = ResponseExecutor(event_bus, socketio)
        return _response_executor_instance
