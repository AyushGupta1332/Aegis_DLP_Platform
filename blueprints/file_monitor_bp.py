"""
File Monitoring Routes
======================
Handles real-time file system monitoring with watchdog.
"""

from flask import Blueprint, jsonify, request, render_template, Response
import logging

logger = logging.getLogger(__name__)

file_monitor_bp = Blueprint('file_monitor', __name__)

# Import file monitor module
try:
    from modules.file_monitor import get_file_monitor, WATCHDOG_AVAILABLE
    FILE_MONITOR_AVAILABLE = WATCHDOG_AVAILABLE
except ImportError as e:
    logger.warning(f"File monitoring not available: {e}")
    FILE_MONITOR_AVAILABLE = False


def _get_socketio():
    """Get socketio instance from main app."""
    import sys
    main = sys.modules.get('__main__', None)
    return getattr(main, 'socketio', None) if main else None


def _get_publish_event_bus():
    """Get the publish_event_bus helper from main app."""
    import sys
    main = sys.modules.get('__main__', None)
    return getattr(main, 'publish_event_bus', None) if main else None


@file_monitor_bp.route('/file-monitoring')
def file_monitoring():
    """File monitoring dashboard"""
    return render_template('file_monitoring.html')


@file_monitor_bp.route('/api/file-monitor/start', methods=['POST'])
def start_file_monitoring():
    """Start file monitoring."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available. Install watchdog: pip install watchdog'}), 503
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    result = monitor.start()
    
    if result.get('status') == 'started':
        publish = _get_publish_event_bus()
        if publish:
            try:
                from modules.event_bus.events import EventType, Severity
                publish(
                    EventType.SYSTEM_MODULE_STARTED,
                    severity=Severity.MEDIUM,
                    module='File Monitoring',
                    message='File monitoring started — watching for file system changes'
                )
            except Exception:
                pass
    
    return jsonify(result)


@file_monitor_bp.route('/api/file-monitor/stop', methods=['POST'])
def stop_file_monitoring():
    """Stop file monitoring."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    result = monitor.stop()
    
    publish = _get_publish_event_bus()
    if publish:
        try:
            from modules.event_bus.events import EventType, Severity
            publish(
                EventType.SYSTEM_MODULE_STOPPED,
                severity=Severity.INFO,
                module='File Monitoring',
                message='File monitoring stopped'
            )
        except Exception:
            pass
    
    return jsonify(result)


@file_monitor_bp.route('/api/file-monitor/add-directory', methods=['POST'])
def add_monitor_directory():
    """Add a directory to watch list."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    data = request.json
    directory = data.get('directory', '').strip()
    
    if not directory:
        return jsonify({'status': 'error', 'message': 'No directory provided'})
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    result = monitor.add_directory(directory)
    return jsonify(result)


@file_monitor_bp.route('/api/file-monitor/remove-directory', methods=['POST'])
def remove_monitor_directory():
    """Remove a directory from watch list."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    data = request.json
    directory = data.get('directory', '').strip()
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    result = monitor.remove_directory(directory)
    return jsonify(result)


@file_monitor_bp.route('/api/file-monitor/events', methods=['GET'])
def get_monitor_events():
    """Get recent file events."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'events': []})
    
    limit = request.args.get('limit', 50, type=int)
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    events = monitor.get_events(limit)
    return jsonify({'status': 'success', 'events': events})


@file_monitor_bp.route('/api/file-monitor/stats', methods=['GET'])
def get_monitor_stats():
    """Get monitoring statistics."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'stats': {}})
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    stats = monitor.get_stats()
    return jsonify({'status': 'success', 'stats': stats})


@file_monitor_bp.route('/api/file-monitor/status', methods=['GET'])
def get_monitor_status():
    """Get monitoring status."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({
            'is_monitoring': False,
            'directories': [],
            'watchdog_available': False
        })
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    return jsonify(monitor.get_status())


@file_monitor_bp.route('/api/file-monitor/filters', methods=['POST'])
def set_monitor_filters():
    """Set event filtering options."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    data = request.json
    extensions = data.get('extensions')
    categories = data.get('categories')
    exclude_patterns = data.get('exclude_patterns')
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    monitor.set_filters(extensions, categories, exclude_patterns)
    
    return jsonify({'status': 'success', 'message': 'Filters updated'})


@file_monitor_bp.route('/api/file-monitor/events/search', methods=['GET'])
def search_monitor_events():
    """Search file events with filters."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'events': []})
    
    limit = request.args.get('limit', 100, type=int)
    event_type = request.args.get('event_type', 'all')
    search = request.args.get('search', '').strip()
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    events = monitor.get_events(
        limit=limit,
        event_type=event_type if event_type != 'all' else None,
        search=search if search else None,
        start_date=start_date if start_date else None,
        end_date=end_date if end_date else None
    )
    return jsonify({'status': 'success', 'events': events, 'count': len(events)})


@file_monitor_bp.route('/api/file-monitor/events/export', methods=['GET'])
def export_monitor_events():
    """Export file events to CSV or JSON."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    export_format = request.args.get('format', 'csv').lower()
    limit = request.args.get('limit', 1000, type=int)
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    
    if export_format == 'json':
        data = monitor.export_events(format='json', limit=limit)
        return Response(
            data,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=file_monitor_events.json'}
        )
    else:
        data = monitor.export_events(format='csv', limit=limit)
        return Response(
            data,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=file_monitor_events.csv'}
        )


@file_monitor_bp.route('/api/file-monitor/event/<event_id>', methods=['GET'])
def get_monitor_event_details(event_id):
    """Get detailed information about a specific event."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    event = monitor.get_event_by_id(event_id)
    
    if event:
        return jsonify({'status': 'success', 'event': event})
    else:
        return jsonify({'status': 'error', 'message': 'Event not found'}), 404


@file_monitor_bp.route('/api/file-monitor/config', methods=['GET'])
def get_monitor_config():
    """Get current file monitoring configuration."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'config': {}})
    
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    config = monitor.get_config()
    return jsonify({'status': 'success', 'config': config})


@file_monitor_bp.route('/api/file-monitor/config', methods=['POST'])
def update_monitor_config():
    """Update file monitoring configuration."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    data = request.json
    socketio = _get_socketio()
    monitor = get_file_monitor(socketio)
    result = monitor.update_config(data)
    return jsonify(result)


logger.info("✅ File Monitor blueprint loaded")
