"""
Aegis DLP - Main Application Entry Point
==========================================
All module routes are handled by Flask Blueprints (see blueprints/).
This file contains only: Flask/SocketIO setup, blueprint registration,
Event Bus initialization, shared state injection, and the startup banner.
"""
# ---- Suppress noisy warnings & logs (must be before library imports) ----
import warnings
import os
import logging

# 1. Suppress requests dependency version mismatch warning
warnings.filterwarnings("ignore", message=".*doesn.t match a supported version.*")
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 2. Suppress HuggingFace Hub unauthenticated request warning
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '1'
os.environ['TRANSFORMERS_VERBOSITY'] = 'error'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['SAFETENSORS_FAST_GPU'] = '1'

# 3. Silence noisy third-party loggers (httpx, huggingface_hub, sentence_transformers)
for _noisy_logger in (
    'httpx', 'huggingface_hub', 'huggingface_hub.utils._http',
    'sentence_transformers', 'sentence_transformers.SentenceTransformer',
    'chromadb', 'chromadb.telemetry',
):
    logging.getLogger(_noisy_logger).setLevel(logging.ERROR)

# 4. Suppress safetensors "LOAD REPORT" (printed to stdout via safetensors C backend)
os.environ['SAFETENSORS_LOG_LEVEL'] = 'error'

from flask import Flask, render_template, request
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ---- Flask App ----
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'DFTY-563-Aegis-DLP-Secret-Key')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max upload
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---- Event Bus Initialization ----
EVENT_BUS_AVAILABLE = False
event_bus = None

try:
    from modules.event_bus import (
        init_event_system, EventType, Severity,
        system_event
    )
    EVENT_BUS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Event Bus not available: {e}")

if EVENT_BUS_AVAILABLE:
    try:
        event_bus = init_event_system(socketio=socketio)
        logger.info("✅ Event Bus System initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Event Bus: {e}")

# ---- Shared State Injection ----
# Populate the shared_state singleton so all blueprints can access
# the Flask app, SocketIO instance, and Event Bus without circular imports.
from blueprints.shared_state import app_state
app_state.app = app
app_state.socketio = socketio
app_state.event_bus = event_bus
app_state.EVENT_BUS_AVAILABLE = EVENT_BUS_AVAILABLE

# ---- Unified Monitoring Initialization ----
# Must be called BEFORE blueprint registration so SQLAlchemy models are ready.
from blueprints.unified_monitoring import init_unified_monitoring
init_unified_monitoring(app)

# ---- Register Blueprints ----
from blueprints import ALL_BLUEPRINTS
for bp in ALL_BLUEPRINTS:
    app.register_blueprint(bp)
    logger.info(f"✅ Registered blueprint: {bp.name}")


# ---- Page Visit Auto-Tracking ----
PAGE_MODULE_MAP = {
    '/': 'Home Dashboard',
    '/anomaly-detection': 'Network Anomaly Detection',
    '/data-classification': 'Data Classification',
    '/device-monitoring': 'Device Monitoring',
    '/phishing-detection': 'Phishing Detection',
    '/file-monitoring': 'File Monitoring',
    '/file-encryption': 'File Encryption',
    '/malware-scanner': 'Malware Scanner',
    '/event-bus': 'Event Bus Dashboard',
    '/unified-monitoring/local': 'Unified Local Monitoring',
    '/unified-monitoring/local/dashboard': 'UBA Dashboard',
}

@app.before_request
def track_page_visits():
    """Publish page visit events for module pages."""
    if not EVENT_BUS_AVAILABLE or not event_bus or request.method != 'GET':
        return
    module_name = PAGE_MODULE_MAP.get(request.path)
    if module_name:
        try:
            event_bus.publish(system_event(
                event_type=EventType.SYSTEM_PAGE_VISIT,
                severity=Severity.INFO,
                message=f"User opened {module_name}",
                module=module_name,
                page_path=request.path,
                user_agent=request.headers.get('User-Agent', 'unknown')[:100],
                remote_addr=request.remote_addr,
            ))
        except Exception:
            pass


# ---- SocketIO Event Handlers ----
@socketio.on('connect')
def handle_connect():
    logger.debug('Client connected')
    # Send IDS initial state to newly connected clients
    socketio.emit('initial_data', {
        'stats': app_state.stats,
        'recent_predictions': list(app_state.prediction_queue) if app_state.prediction_queue else [],
        'monitoring_active': app_state.monitoring_active
    })

@socketio.on('disconnect')
def handle_disconnect():
    logger.debug('Client disconnected')

@socketio.on('join_chat')
def handle_join_chat(data):
    from flask_socketio import join_room
    user_id = data.get('user_id', 'default')
    join_room(user_id)

@socketio.on('chat_message')
def handle_chat_message(data):
    from flask_socketio import emit
    try:
        from agentic import get_agent
        agent = get_agent()
    except ImportError:
        agent = None

    user_id = data.get('user_id', 'default')
    query = data.get('message', '')

    if not agent:
        emit('chat_response', {'status': 'error', 'response': 'AI assistant not available.'}, room=user_id)
        return
    if not query:
        return
    try:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(agent.chat(user_id, query, socketio))
        loop.close()
        emit('chat_response', {
            'status': 'success', 'response': result.get('response', ''),
            'tools_used': result.get('tools_used', []),
            'processing_time': result.get('processing_time', 0)
        }, room=user_id)
    except Exception as e:
        logger.error(f"WebSocket chat error: {e}")
        emit('chat_response', {'status': 'error', 'response': f'Error: {str(e)}'}, room=user_id)


# ---- Main Entry Point ----
if __name__ == '__main__':
    # ---- Startup Secrets Validation ----
    _REQUIRED_SECRETS = {
        'GROQ_API_KEY': 'AI Chatbot will not function',
        'VIRUS_TOTAL_API': 'Malware Scanner will be disabled',
    }
    _OPTIONAL_SECRETS = {
        'MAIL_PASSWORD': 'Email alerts will be disabled',
        'MAIL_USERNAME': 'Email alerts will be disabled',
        'SECRET_KEY': 'Using default secret key (insecure for production)',
    }
    
    print("=" * 60)
    print(" AEGIS DLP - Unified Data Loss Prevention Platform")
    print("=" * 60)
    print()
    
    # Validate secrets
    _missing_critical = False
    for var, msg in _REQUIRED_SECRETS.items():
        if not os.environ.get(var):
            print(f"  ⚠️  MISSING: {var} — {msg}")
            _missing_critical = True
    for var, msg in _OPTIONAL_SECRETS.items():
        if not os.environ.get(var):
            print(f"  ℹ️  OPTIONAL: {var} — {msg}")
    
    if _missing_critical:
        print()
        print("  ⚡ Some required environment variables are missing.")
        print("  ⚡ Set them in .env or your environment before production use.")
    print()
    
    print("Server starting on http://localhost:5000")
    print()
    print("Integrated Systems:")
    print("  1. Anomaly Detection (MLP Model)")
    print("  2. Data Classification (RoBERTa Model)")
    print("  3. Phishing Detection (RoBERTa + YARA)")
    print("  4. File Encryption (AES-256-GCM)")
    print("  5. File Monitoring (Watchdog)")
    print("  6. AI Security Assistant (Groq + ChromaDB)")
    print("  7. Malware Scanner (VirusTotal API)")
    print("  8. Unified Device Monitoring & File Transfer Control")
    if EVENT_BUS_AVAILABLE:
        print("  9. Event Bus & Correlation Engine (Module Interlinking)")
    print()
    print("Blueprint Modules: 9 registered")
    print()

    # Pre-load models
    print("Pre-loading Data Classification Model...")
    try:
        from modules.data_classifier import get_classifier
        get_classifier()
        print("✓ Data Classification Model loaded!")
    except Exception as e:
        print(f"⚠ Could not pre-load classifier: {e}")

    try:
        from modules.body_classifier import predict_body_label
        print("Pre-loading Phishing Detection Model...")
        predict_body_label("Test email content")
        print("✓ Phishing Detection Model loaded!")
    except Exception as e:
        print(f"⚠ Phishing Detection not available: {e}") 

    print()
    print("=" * 60)

    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
