"""
Data Classification Routes
===========================
Handles the Data Classification Scanner powered by RoBERTa AI.
"""

from flask import Blueprint, jsonify, request
import threading
import time
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

classification_bp = Blueprint('classification', __name__)


def _get_state():
    from blueprints.shared_state import app_state
    return app_state


def run_classification_scan(directory):
    """Run classification scan in background thread"""
    state = _get_state()
    
    try:
        logger.info(f"Starting scan of directory: {directory}")
        
        state.socketio.emit('scan_progress', {
            'current': 0, 'total': 0, 'percentage': 0,
            'message': 'Loading RoBERTa model... (this may take 30-60 seconds on first run)'
        })
        
        from modules.data_classifier import get_classifier
        classifier = get_classifier()
        logger.info("Classifier ready!")
        
        allowed_extensions = {'.txt', '.docx', '.pdf', '.csv', '.xlsx', '.xls'}
        directory_path = Path(directory)
        
        if not directory_path.exists():
            state.socketio.emit('scan_error', {'error': f'Directory does not exist: {directory}'})
            state.scanning_active = False
            return
        
        all_files = []
        for ext in allowed_extensions:
            all_files.extend(directory_path.glob(f'*{ext}'))
        
        total_files = len(all_files)
        
        if total_files == 0:
            state.socketio.emit('scan_complete', {
                'total': 0, 'sensitive': 0, 'non_sensitive': 0,
                'message': 'No supported files found'
            })
            state.scanning_active = False
            return
        
        state.socketio.emit('scan_progress', {
            'current': 0, 'total': total_files, 'percentage': 0,
            'message': f'Starting scan of {total_files} files...'
        })
        
        for idx, file_path in enumerate(all_files):
            if not state.scanning_active:
                break
            
            try:
                try:
                    result = classifier.classify_file(file_path)
                    
                    state.classification_stats['total_files'] += 1
                    if result['classification'] == 'Sensitive':
                        state.classification_stats['sensitive_count'] += 1
                    else:
                        state.classification_stats['non_sensitive_count'] += 1
                    
                    state.classification_results.append(result)
                    state.socketio.emit('classification_result', result)
                    time.sleep(0.05)
                    
                    # Event Bus integration
                    if state.EVENT_BUS_AVAILABLE and state.event_bus:
                        try:
                            from modules.event_bus.events import EventType, Severity
                            from modules.event_bus import classification_event
                            
                            is_sensitive = result['classification'] == 'Sensitive'
                            conf = result.get('confidence', 0)
                            should_publish = is_sensitive or (idx % 10 == 0)
                            
                            if should_publish:
                                evt = classification_event(
                                    event_type=EventType.DATA_SENSITIVE if is_sensitive else EventType.DATA_NON_SENSITIVE,
                                    path=str(file_path),
                                    severity=Severity.HIGH if (is_sensitive and conf > 80) else (Severity.MEDIUM if is_sensitive else Severity.INFO),
                                    is_sensitive=is_sensitive,
                                    confidence=round(conf, 1),
                                    classification_label=result.get('classification', 'Unknown'),
                                    file_type=file_path.suffix,
                                    file_size=result.get('file_size', 0),
                                    message=f"{'⚠️ SENSITIVE' if is_sensitive else '✓ Safe'}: {file_path.name} ({conf:.1f}% confidence)",
                                )
                                state.event_bus.publish(evt)
                        except Exception:
                            pass
                    
                except Exception as file_error:
                    error_result = {
                        'filename': file_path.name,
                        'path': str(file_path),
                        'classification': 'Error',
                        'confidence': 0.0,
                        'file_size': 0,
                        'file_type': file_path.suffix,
                        'error': str(file_error)
                    }
                    state.classification_results.append(error_result)
                    state.socketio.emit('classification_result', error_result)
                    time.sleep(0.05)
                
                state.socketio.emit('scan_progress', {
                    'current': idx + 1, 'total': total_files,
                    'percentage': ((idx + 1) / total_files) * 100,
                    'message': f'Processing {idx + 1}/{total_files} files...'
                })
                time.sleep(0.02)
                
            except Exception as e:
                logger.error(f"Unexpected error on file {file_path}: {e}")
                continue
        
        # Emit completion
        state.socketio.emit('scan_complete', {
            'total': state.classification_stats['total_files'],
            'sensitive': state.classification_stats['sensitive_count'],
            'non_sensitive': state.classification_stats['non_sensitive_count']
        })
        
        # Publish scan complete event
        if state.EVENT_BUS_AVAILABLE and state.event_bus:
            try:
                from modules.event_bus.events import EventType, Severity
                from modules.event_bus import classification_event
                
                total = state.classification_stats['total_files']
                sensitive = state.classification_stats['sensitive_count']
                non_sensitive = state.classification_stats['non_sensitive_count']
                sev = Severity.HIGH if sensitive > 0 else Severity.INFO
                evt = classification_event(
                    event_type=EventType.DATA_SCAN_COMPLETE,
                    path=directory,
                    severity=sev,
                    is_sensitive=(sensitive > 0),
                    message=f"Classification scan complete — {total} files: {sensitive} sensitive, {non_sensitive} safe",
                    total_files=total,
                    sensitive_count=sensitive,
                    non_sensitive_count=non_sensitive,
                )
                state.event_bus.publish(evt)
            except Exception:
                pass
        
        state.scanning_active = False
        
    except Exception as e:
        logger.error(f"FATAL ERROR in scan: {e}")
        import traceback
        traceback.print_exc()
        state.scanning_active = False
        state.socketio.emit('scan_error', {'error': str(e)})


# ---- Routes ----

@classification_bp.route('/api/classify/start', methods=['POST'])
def start_classification():
    state = _get_state()
    
    if state.scanning_active:
        return jsonify({'status': 'already_running', 'message': 'Scan is already running'})
    
    data = request.json
    directory = data.get('directory', '').strip()
    directory = os.path.normpath(directory)
    
    if not directory:
        return jsonify({'status': 'error', 'message': 'No directory path provided'})
    if not os.path.exists(directory):
        return jsonify({'status': 'error', 'message': f'Directory does not exist: {directory}'})
    if not os.path.isdir(directory):
        return jsonify({'status': 'error', 'message': f'Path is not a directory: {directory}'})
    
    state.scanning_active = True
    state.classification_results = []
    state.classification_stats = {
        'total_files': 0, 'sensitive_count': 0, 'non_sensitive_count': 0
    }
    
    state.scan_thread = threading.Thread(target=run_classification_scan, args=(directory,), daemon=True)
    state.scan_thread.start()
    
    state.publish_event_bus(
        _event_type('SYSTEM_MODULE_STARTED'),
        severity=_severity('MEDIUM'),
        module='Data Classification',
        message=f'Data classification scan started on: {directory}',
        directory=directory
    )
    
    return jsonify({'status': 'started', 'message': 'Scan started successfully'})


@classification_bp.route('/api/classify/stop', methods=['POST'])
def stop_classification():
    state = _get_state()
    state.scanning_active = False
    
    state.publish_event_bus(
        _event_type('SYSTEM_MODULE_STOPPED'),
        severity=_severity('INFO'),
        module='Data Classification',
        message='Data classification scan stopped'
    )
    
    return jsonify({'status': 'stopped', 'message': 'Scan stopped'})


@classification_bp.route('/api/classify/stats', methods=['GET'])
def get_classification_stats():
    state = _get_state()
    return jsonify(state.classification_stats)


@classification_bp.route('/api/classify/results', methods=['GET'])
def get_classification_results():
    state = _get_state()
    return jsonify(state.classification_results)


def _event_type(name):
    try:
        from modules.event_bus.events import EventType
        return getattr(EventType, name)
    except Exception:
        return None

def _severity(name):
    try:
        from modules.event_bus.events import Severity
        return getattr(Severity, name)
    except Exception:
        return None


logger.info("✅ Data Classification blueprint loaded")
