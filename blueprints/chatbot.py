"""
AI Chatbot & Activity Tracking Routes
======================================
Handles the AI Security Assistant (Groq LLM) and activity tracking endpoints.
"""

from flask import Blueprint, jsonify, request
import logging
import asyncio
import time
from collections import defaultdict

logger = logging.getLogger(__name__)

chatbot_bp = Blueprint('chatbot', __name__)

# ---- Rate Limiting (in-memory, per-IP) ----
_rate_limit_store = defaultdict(list)  # ip -> [timestamps]
RATE_LIMIT_MAX_REQUESTS = 20   # max requests
RATE_LIMIT_WINDOW_SECONDS = 60  # per this many seconds

def _check_rate_limit(ip: str) -> bool:
    """Check if the IP has exceeded the rate limit. Returns True if allowed."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    # Clean old entries
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if t > cutoff]
    if len(_rate_limit_store[ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    _rate_limit_store[ip].append(now)
    return True

# Import the agentic module for AI chatbot
try:
    from agentic import get_agent
    from agentic.memory import get_activity_tracker
    CHATBOT_AVAILABLE = True
    logger.info("✅ AI Chatbot module loaded")
except ImportError as e:
    CHATBOT_AVAILABLE = False
    logger.warning(f"⚠️ AI Chatbot not available: {e}")


def _get_app_state():
    """Get shared app state from the shared_state singleton."""
    from blueprints.shared_state import app_state
    return {
        'socketio': app_state.socketio,
        'event_bus': app_state.event_bus,
        'EVENT_BUS_AVAILABLE': app_state.EVENT_BUS_AVAILABLE,
        'stats': app_state.stats,
        'monitoring_active': app_state.monitoring_active,
        'classification_stats': app_state.classification_stats,
        'scanning_active': app_state.scanning_active,
    }


def enhance_page_context(page_context):
    """Enhance page context with live app state"""
    page_type = page_context.get('page_type', '')
    state = _get_app_state()
    
    if page_type == 'anomaly' or page_type == 'anomaly_detection':
        app_stats = state.get('stats', {})
        page_context['stats'] = {
            'total_samples': app_stats.get('total_samples', 0),
            'normal_count': app_stats.get('normal_count', 0),
            'anomaly_count': app_stats.get('anomaly_count', 0),
            'monitoring_active': state.get('monitoring_active', False)
        }
        page_context['page_type'] = 'anomaly_detection'
        page_context['feature'] = 'Intrusion Detection System'
        page_context['model'] = 'MLP Neural Network'
        
    elif page_type == 'classification' or page_type == 'data_classification':
        cls_stats = state.get('classification_stats', {})
        page_context['stats'] = {
            'total_files': cls_stats.get('total_files', 0),
            'sensitive_count': cls_stats.get('sensitive_count', 0),
            'non_sensitive_count': cls_stats.get('non_sensitive_count', 0),
            'scan_active': state.get('scanning_active', False)
        }
        page_context['page_type'] = 'data_classification'
        page_context['feature'] = 'Data Classification Scanner'
        page_context['model'] = 'RoBERTa Transformer'
        
    elif page_type == 'phishing':
        page_context['page_type'] = 'phishing_detection'
        page_context['feature'] = 'Email Phishing Detection'
        page_context['model'] = 'RoBERTa + YARA Rules'
        
    elif page_type == 'encryption':
        page_context['page_type'] = 'file_encryption'
        page_context['feature'] = 'File Encryption & Decryption'
        page_context['model'] = 'AES-256-GCM Encryption'
        page_context['capabilities'] = ['Password protection', 'Self-destruct timer', 'View-only mode', 'Secure key sharing link']
    
    elif page_type == 'file_monitoring':
        page_context['page_type'] = 'file_monitoring'
        page_context['feature'] = 'Real-time File System Monitoring'
        page_context['model'] = 'Watchdog Event Handler'
        page_context['capabilities'] = ['Created', 'Modified', 'Deleted', 'Moved file events']
        try:
            from modules.file_monitor import get_file_monitor, WATCHDOG_AVAILABLE
            if WATCHDOG_AVAILABLE:
                monitor = get_file_monitor()
                if monitor:
                    page_context['stats'] = {
                        'monitoring_active': monitor.is_running,
                        'directories_count': len(monitor.watched_directories) if hasattr(monitor, 'watched_directories') else 0
                    }
        except Exception:
            pass
    
    elif page_type == 'malware_scanner':
        page_context['page_type'] = 'malware_scanner'
        page_context['feature'] = 'Malware Scanner'
        page_context['model'] = 'VirusTotal API Integration'
        page_context['capabilities'] = ['File scanning', 'URL scanning', 'Threat detection', 'Scan history']
    
    elif page_type == 'device_monitoring':
        page_context['page_type'] = 'device_monitoring'
        page_context['feature'] = 'Unified Device Monitoring & File Transfer Control'
        page_context['model'] = 'USB Device Registry + RBAC'
        page_context['capabilities'] = ['USB device registration', 'File transfer control', 'User permissions', 'Cloud & Local monitoring']
    
    elif page_type == 'event_bus' or page_type == 'security_event_bus':
        page_context['page_type'] = 'event_bus'
        page_context['feature'] = 'Security Event Bus & Correlation Engine'
        page_context['model'] = 'Pub/Sub Event-Driven Architecture'
        page_context['capabilities'] = ['Real-time security event monitoring', 'Cross-module event correlation', 'Compound threat detection rules', 'Automated security responses', 'SQLite event audit trail', 'Socket.IO real-time push']
        try:
            eb = state.get('event_bus')
            if state.get('EVENT_BUS_AVAILABLE') and eb:
                bus_stats = eb.get_stats()
                try:
                    from modules.event_bus import get_correlation_engine
                    corr_stats = get_correlation_engine().get_stats() if get_correlation_engine else {}
                except Exception:
                    corr_stats = {}
                page_context['stats'] = {
                    'total_events_published': bus_stats.get('total_published', 0),
                    'active_subscriptions': bus_stats.get('active_subscriptions', 0),
                    'history_size': bus_stats.get('history_size', 0),
                    'dispatcher_running': bus_stats.get('dispatcher_running', False),
                    'total_correlation_rules': corr_stats.get('total_rules', 0),
                    'enabled_rules': corr_stats.get('enabled_rules', 0),
                    'total_correlation_matches': corr_stats.get('total_matches', 0)
                }
        except Exception:
            pass
    
    return page_context


@chatbot_bp.route('/api/chat', methods=['POST'])
def api_chat():
    """Main chat endpoint - send message to AI assistant"""
    # Rate limiting: 20 requests per minute per IP
    client_ip = request.remote_addr or 'unknown'
    if not _check_rate_limit(client_ip):
        return jsonify({
            'status': 'error',
            'message': 'Rate limit exceeded. Please wait before sending more messages.'
        }), 429
    
    if not CHATBOT_AVAILABLE:
        return jsonify({
            'status': 'error',
            'message': 'AI Chatbot not available. Check if agentic module is installed.'
        }), 503
    
    try:
        agent = get_agent()
        if not agent:
            return jsonify({
                'status': 'error',
                'message': 'Could not initialize AI agent. Check GROQ_API_KEY environment variable.'
            }), 503
        
        data = request.json
        message = data.get('message', '')
        user_id = data.get('user_id', 'default')
        page_context = data.get('page_context', {})
        
        if not message.strip():
            return jsonify({
                'status': 'error',
                'message': 'Message cannot be empty'
            }), 400
        
        # Enhance page context with current app state
        page_context = enhance_page_context(page_context)
        
        state = _get_app_state()
        socketio = state.get('socketio')
        
        # Run async chat in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                agent.chat(user_id, message, socketio, page_context)
            )
        finally:
            loop.close()
        
        response_text = result.get('response', 'No response generated')
        tools_used = result.get('tools_used', [])
        processing_time = result.get('processing_time', 0)
        
        # Event Bus integration
        eb = state.get('event_bus')
        if state.get('EVENT_BUS_AVAILABLE') and eb:
            try:
                from modules.event_bus.events import EventType, Severity
                from modules.event_bus import system_event
                evt = system_event(
                    event_type=EventType.AI_QUERY,
                    severity=Severity.INFO,
                    module='AI Chatbot',
                    message=f"AI query: {message[:80]}{'...' if len(message) > 80 else ''}",
                    user_id=user_id,
                    query=message[:200],
                    page_context=page_context.get('page_type', 'unknown'),
                    tools_used=tools_used,
                    processing_time=processing_time,
                    response_preview=response_text[:100],
                )
                eb.publish(evt)
            except Exception:
                pass
        
        return jsonify({
            'status': 'success',
            'response': response_text,
            'tools_used': tools_used,
            'processing_time': processing_time
        })
        
    except Exception as e:
        logger.error(f"Chat API error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500


@chatbot_bp.route('/api/chat/history', methods=['GET'])
def api_chat_history():
    """Get conversation history for user"""
    if not CHATBOT_AVAILABLE:
        return jsonify({'history': []})
    
    try:
        agent = get_agent()
        if not agent:
            return jsonify({'history': []})
        
        user_id = request.args.get('user_id', 'default')
        history = agent.get_history(user_id)
        
        return jsonify({'history': history})
        
    except Exception as e:
        logger.error(f"Chat history error: {e}")
        return jsonify({'history': []})


@chatbot_bp.route('/api/chat/clear', methods=['POST'])
def api_chat_clear():
    """Clear conversation history"""
    if not CHATBOT_AVAILABLE:
        return jsonify({'status': 'success', 'message': 'Nothing to clear'})
    
    try:
        agent = get_agent()
        if agent:
            data = request.json
            user_id = data.get('user_id', 'default')
            agent.clear_history(user_id)
        
        return jsonify({'status': 'success', 'message': 'Conversation cleared'})
        
    except Exception as e:
        logger.error(f"Clear history error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@chatbot_bp.route('/api/activity/log', methods=['POST'])
def api_activity_log():
    """Log a user security activity"""
    if not CHATBOT_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'Activity tracking not available'}), 503
    
    try:
        tracker = get_activity_tracker()
        data = request.json
        
        user_id = data.get('user_id', 'default')
        activity_type = data.get('activity_type', 'unknown')
        summary = data.get('summary', '')
        details = data.get('details', {})
        
        tracker.log_activity(user_id, activity_type, summary, details)
        
        return jsonify({'status': 'success', 'message': 'Activity logged'})
        
    except Exception as e:
        logger.error(f"Activity log error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@chatbot_bp.route('/api/activity/summary', methods=['GET'])
def api_activity_summary():
    """Get activity summary for user"""
    if not CHATBOT_AVAILABLE:
        return jsonify({'has_activities': False, 'message': 'Activity tracking not available'})
    
    try:
        tracker = get_activity_tracker()
        user_id = request.args.get('user_id', 'default')
        summary = tracker.get_activity_summary(user_id)
        
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Activity summary error: {e}")
        return jsonify({'has_activities': False, 'message': str(e)})


@chatbot_bp.route('/api/activity/recent', methods=['GET'])
def api_activity_recent():
    """Get recent activities for user"""
    if not CHATBOT_AVAILABLE:
        return jsonify({'activities': []})
    
    try:
        tracker = get_activity_tracker()
        user_id = request.args.get('user_id', 'default')
        limit = request.args.get('limit', 10, type=int)
        activities = tracker.get_recent_activities(user_id, limit)
        
        return jsonify({'activities': activities})
        
    except Exception as e:
        logger.error(f"Recent activities error: {e}")
        return jsonify({'activities': []})


logger.info("✅ AI Chatbot blueprint loaded")
