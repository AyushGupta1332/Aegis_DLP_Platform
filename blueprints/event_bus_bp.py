"""
Event Bus Dashboard & API Routes
=================================
Handles the Event Bus dashboard and all event-related API endpoints.
"""

from flask import Blueprint, jsonify, request, render_template
import logging

logger = logging.getLogger(__name__)

event_bus_bp = Blueprint('event_bus', __name__)


def _get_event_bus_deps():
    """Get event bus dependencies from shared_state and modules.event_bus."""
    from blueprints.shared_state import app_state
    
    if not app_state.EVENT_BUS_AVAILABLE or not app_state.event_bus:
        return None, None, None, None, False
    
    bus = app_state.event_bus
    
    try:
        from modules.event_bus import (
            get_event_logger, get_correlation_engine, get_response_executor
        )
        return bus, get_event_logger, get_correlation_engine, get_response_executor, True
    except ImportError:
        return bus, None, None, None, True


@event_bus_bp.route('/event-bus')
def event_bus_dashboard():
    """Event Bus dashboard - real-time security event monitoring."""
    return render_template('event_bus.html')


@event_bus_bp.route('/api/events/recent')
def api_get_recent_events():
    """Get recent security events from the Event Bus."""
    bus, _, _, _, available = _get_event_bus_deps()
    if not available or not bus:
        return jsonify({'error': 'Event Bus not available'}), 503
    
    try:
        from modules.event_bus.events import EventType, ModuleSource, Severity
    except ImportError:
        return jsonify({'error': 'Event Bus modules not available'}), 503
    
    limit = request.args.get('limit', 50, type=int)
    event_type = request.args.get('type')
    source = request.args.get('source')
    min_severity = request.args.get('min_severity')
    since = request.args.get('since', type=float)
    
    events = bus.get_recent_events(
        limit=limit,
        event_type=EventType(event_type) if event_type else None,
        source=ModuleSource(source) if source else None,
        min_severity=Severity(min_severity) if min_severity else None,
        since_seconds=since
    )
    return jsonify({'events': events, 'count': len(events)})


@event_bus_bp.route('/api/events/stats')
def api_get_event_stats():
    """Get Event Bus and Logger statistics."""
    bus, get_event_logger, get_correlation_engine, get_response_executor, available = _get_event_bus_deps()
    if not available or not bus:
        return jsonify({'error': 'Event Bus not available'}), 503
    
    bus_stats = bus.get_stats()
    logger_stats = get_event_logger().get_stats()
    correlation_stats = get_correlation_engine().get_stats()
    response_stats = get_response_executor().get_stats()
    
    return jsonify({
        'bus': bus_stats,
        'logger': logger_stats,
        'correlation': correlation_stats,
        'responses': response_stats,
    })


@event_bus_bp.route('/api/events/health')
def api_get_event_health():
    """Get Event Bus health status."""
    bus, _, _, _, available = _get_event_bus_deps()
    if not available or not bus:
        return jsonify({'status': 'unavailable'}), 503
    return jsonify(bus.get_health())


@event_bus_bp.route('/api/events/subscriptions')
def api_get_subscriptions():
    """Get all active event subscriptions."""
    bus, _, _, _, available = _get_event_bus_deps()
    if not available or not bus:
        return jsonify({'error': 'Event Bus not available'}), 503
    return jsonify({'subscriptions': bus.get_subscriptions()})


@event_bus_bp.route('/api/events/correlation/rules')
def api_get_correlation_rules():
    """Get all correlation rules and their status."""
    _, _, get_correlation_engine, _, available = _get_event_bus_deps()
    if not available:
        return jsonify({'error': 'Event Bus not available'}), 503
    engine = get_correlation_engine()
    return jsonify({'rules': engine.get_rules()})


@event_bus_bp.route('/api/events/correlation/matches')
def api_get_correlation_matches():
    """Get correlation match history."""
    _, get_event_logger, _, _, available = _get_event_bus_deps()
    if not available:
        return jsonify({'error': 'Event Bus not available'}), 503
    limit = request.args.get('limit', 50, type=int)
    unresolved = request.args.get('unresolved', 'false').lower() == 'true'
    matches = get_event_logger().get_correlation_matches(limit=limit, unresolved_only=unresolved)
    return jsonify({'matches': matches, 'count': len(matches)})


@event_bus_bp.route('/api/events/correlation/rules/<rule_name>/toggle', methods=['POST'])
def api_toggle_correlation_rule(rule_name):
    """Enable or disable a correlation rule."""
    _, _, get_correlation_engine, _, available = _get_event_bus_deps()
    if not available:
        return jsonify({'error': 'Event Bus not available'}), 503
    data = request.get_json() or {}
    enabled = data.get('enabled', True)
    engine = get_correlation_engine()
    success = engine.enable_rule(rule_name, enabled)
    if success:
        return jsonify({'status': 'success', 'rule': rule_name, 'enabled': enabled})
    return jsonify({'error': f'Rule {rule_name} not found'}), 404


@event_bus_bp.route('/api/events/responses/log')
def api_get_response_log():
    """Get automated response action log."""
    _, _, _, get_response_executor, available = _get_event_bus_deps()
    if not available:
        return jsonify({'error': 'Event Bus not available'}), 503
    limit = request.args.get('limit', 50, type=int)
    executor = get_response_executor()
    return jsonify({'actions': executor.get_action_log(limit=limit)})


@event_bus_bp.route('/api/events/responses/pending')
def api_get_pending_actions():
    """Get all pending destructive actions awaiting approval."""
    _, _, _, get_response_executor, available = _get_event_bus_deps()
    if not available:
        return jsonify({'error': 'Event Bus not available'}), 503
    executor = get_response_executor()
    return jsonify({'pending': executor.get_pending_actions()})


@event_bus_bp.route('/api/events/responses/approve', methods=['POST'])
def api_approve_action():
    """Approve a pending destructive action."""
    _, _, _, get_response_executor, available = _get_event_bus_deps()
    if not available:
        return jsonify({'error': 'Event Bus not available'}), 503
    data = request.get_json() or {}
    approval_id = data.get('approval_id')
    if not approval_id:
        return jsonify({'error': 'approval_id required'}), 400
    executor = get_response_executor()
    result = executor.approve_action(approval_id)
    status_code = 200 if result['status'] == 'success' else 404
    return jsonify(result), status_code


@event_bus_bp.route('/api/events/responses/deny', methods=['POST'])
def api_deny_action():
    """Deny/cancel a pending destructive action."""
    _, _, _, get_response_executor, available = _get_event_bus_deps()
    if not available:
        return jsonify({'error': 'Event Bus not available'}), 503
    data = request.get_json() or {}
    approval_id = data.get('approval_id')
    if not approval_id:
        return jsonify({'error': 'approval_id required'}), 400
    executor = get_response_executor()
    result = executor.deny_action(approval_id)
    status_code = 200 if result['status'] == 'success' else 404
    return jsonify(result), status_code


logger.info("✅ Event Bus blueprint loaded")
