"""
Unified Device Monitoring Routes
==================================
Handles Cloud (Google Drive) and Local (USB) device monitoring,
file transfer control, user management, and RBAC.
"""

from flask import Blueprint, jsonify, request, render_template, redirect, url_for, session, flash, send_file, current_app
from functools import wraps
from werkzeug.utils import secure_filename
import os
import json
import socket
import base64
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

unified_monitoring_bp = Blueprint('unified_monitoring', __name__)

# ---- Configuration ----
_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UNIFIED_DB_DIR = Path(_base_dir) / 'databases' / 'unified_monitoring'
UNIFIED_DB_DIR.mkdir(parents=True, exist_ok=True)

UNIFIED_CREDENTIALS_PATH = Path(_base_dir) / 'unified_monitoring_src' / 'credentials.json'
UNIFIED_TOKEN_PATH = Path(_base_dir) / 'unified_monitoring_src' / 'token.json'
UNIFIED_PERMISSIONS_FILE = UNIFIED_DB_DIR / 'cloud_permissions.json'
UNIFIED_UPLOAD_FOLDER = Path(_base_dir) / 'temp_uploads'
UNIFIED_UPLOAD_FOLDER.mkdir(exist_ok=True)

UNIFIED_SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'openid',
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/userinfo.profile'
]

# ---- Optional Imports (import each independently so one failure doesn't disable all) ----
UNIFIED_MONITORING_AVAILABLE = False

DeviceIdentifier = None
try:
    from unified_monitoring_src.device_identifier import DeviceIdentifier
except ImportError as e:
    logger.warning(f"DeviceIdentifier not available (WMI/USB detection disabled): {e}")

DeviceRegistry = None
try:
    from unified_monitoring_src.device_registry import DeviceRegistry
except ImportError as e:
    logger.warning(f"DeviceRegistry not available: {e}")

FileTransferController = None
try:
    from unified_monitoring_src.file_controller import FileTransferController
except ImportError as e:
    logger.warning(f"FileTransferController not available: {e}")

UserManager = None
get_mac_address = None
try:
    from unified_monitoring_src.user_manager import UserManager, get_mac_address
except ImportError as e:
    logger.warning(f"UserManager not available: {e}")

AlertManager = AlertType = AlertLevel = None
try:
    from unified_monitoring_src.alerts import AlertManager, AlertType, AlertLevel
except ImportError as e:
    logger.warning(f"AlertManager not available: {e}")

FilePolicyChecker = None
try:
    from unified_monitoring_src.file_policy import FilePolicyChecker
except ImportError as e:
    logger.warning(f"FilePolicyChecker not available: {e}")

# Core requirement for local login: UserManager must be available
if UserManager is not None:
    UNIFIED_MONITORING_AVAILABLE = True
else:
    logger.warning("Unified Device Monitoring disabled: UserManager could not be imported")

# Fixed redirect URI for Google OAuth (avoids LAN IP mismatch with Google Console)
UNIFIED_GOOGLE_REDIRECT_URI = os.environ.get(
    'UNIFIED_GOOGLE_REDIRECT_URI',
    'http://127.0.0.1:5000/unified-monitoring/cloud/auth/callback'
)

# Also conditionally import Google OAuth (shared with phishing)
GOOGLE_AUTH_AVAILABLE = False
try:
    from google_auth_oauthlib.flow import Flow
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    pass

# ---- Component Instances ----
unified_identifier = None
unified_registry = None
unified_controller = None
unified_user_manager = None
unified_alert_manager = None
unified_policy_checker = None
unified_db = None


def init_unified_monitoring(app):
    """Initialize Unified Device Monitoring components."""
    global unified_identifier, unified_registry, unified_controller
    global unified_user_manager, unified_alert_manager, unified_policy_checker, unified_db

    if not UNIFIED_MONITORING_AVAILABLE:
        logger.info("Unified monitoring modules not available, skipping initialization")
        return False

    try:
        from flask_sqlalchemy import SQLAlchemy
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{(UNIFIED_DB_DIR / "cloud_users.db").as_posix()}'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        unified_db = SQLAlchemy(app)

        class CloudUser(unified_db.Model):
            id = unified_db.Column(unified_db.Integer, primary_key=True)
            name = unified_db.Column(unified_db.String(100))
            email = unified_db.Column(unified_db.String(120), unique=True)
            ip_address = unified_db.Column(unified_db.String(50))
            created_at = unified_db.Column(unified_db.DateTime, default=datetime.utcnow)

        app.config['UNIFIED_CLOUD_USER_MODEL'] = CloudUser

        with app.app_context():
            unified_db.create_all()

        users_db = UNIFIED_DB_DIR / 'users.db'
        devices_db = UNIFIED_DB_DIR / 'devices.db'

        # Initialize components that are available (DeviceIdentifier needs WMI)
        if DeviceIdentifier is not None:
            unified_identifier = DeviceIdentifier()
        else:
            logger.warning("DeviceIdentifier skipped (WMI not available)")

        if DeviceRegistry is not None:
            unified_registry = DeviceRegistry(db_path=str(devices_db))
        else:
            logger.warning("DeviceRegistry skipped")

        if FileTransferController is not None and unified_registry and unified_identifier:
            unified_controller = FileTransferController(unified_registry, unified_identifier)
        else:
            logger.warning("FileTransferController skipped (missing dependencies)")

        # Core: UserManager is required for local login
        if UserManager is not None:
            unified_user_manager = UserManager(db_path=str(users_db))
        else:
            logger.error("UserManager not available - local login will not work")

        alert_config = {
            'MAIL_SERVER': os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
            'MAIL_PORT': int(os.environ.get('MAIL_PORT', 587)),
            'MAIL_USE_TLS': True,
            'MAIL_USERNAME': os.environ.get('MAIL_USERNAME', ''),
            'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD', ''),
            'MAIL_DEFAULT_SENDER': ('USB Monitor', os.environ.get('MAIL_USERNAME', '')),
            'ALERT_RECIPIENTS': os.environ.get('ALERT_RECIPIENTS', '').split(',') if os.environ.get('ALERT_RECIPIENTS') else [],
            'ALERT_CONFIG': {
                'enabled': True,
                'email_enabled': bool(os.environ.get('MAIL_PASSWORD')),
                'min_interval_seconds': 60,
                'max_alerts_per_hour': 50,
                'failed_login_threshold': 3,
                'failed_login_window_minutes': 5,
            },
            'APP_INFO': {
                'name': 'Aegis DLP - USB File Monitoring',
                'dashboard_url': 'http://localhost:5000/unified-monitoring'
            }
        }
        if AlertManager is not None:
            unified_alert_manager = AlertManager(alert_config)

        policy_config = {'enabled': True, 'mode': 'blacklist', 'max_file_size_mb': 102400, 'scan_archives': True}
        if FilePolicyChecker is not None:
            unified_policy_checker = FilePolicyChecker(policy_config)

        logger.info("✅ Unified Device Monitoring initialized successfully")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to initialize Unified Device Monitoring: {e}")
        import traceback
        traceback.print_exc()
        return False


def _get_event_helpers():
    from blueprints.shared_state import app_state
    if app_state.EVENT_BUS_AVAILABLE and app_state.event_bus:
        try:
            from modules.event_bus.events import EventType, Severity
            from modules.event_bus import usb_event
            return app_state.event_bus, EventType, Severity, usb_event
        except Exception:
            pass
    return None, None, None, None


# ---- Utility Functions ----
def get_unified_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def load_unified_cloud_permissions():
    if UNIFIED_PERMISSIONS_FILE.exists():
        with open(UNIFIED_PERMISSIONS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_unified_cloud_permissions(permissions):
    with open(UNIFIED_PERMISSIONS_FILE, 'w') as f:
        json.dump(permissions, f, indent=4)

# ---- Auth Decorators ----
def unified_cloud_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('unified_user_type') != 'cloud' or 'unified_cloud_user' not in session:
            flash('Please login with Google to access cloud features.', 'warning')
            return redirect(url_for('unified_monitoring.unified_cloud_login'))
        return f(*args, **kwargs)
    return decorated_function

def unified_local_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('unified_user_type') != 'local' or 'unified_local_user' not in session:
            flash('Please login to access local system features.', 'warning')
            return redirect(url_for('unified_monitoring.unified_local_login'))
        return f(*args, **kwargs)
    return decorated_function

# ---- Google Drive Helpers ----
_unified_drive_service = None

def create_unified_drive_service():
    global _unified_drive_service
    if _unified_drive_service is not None:
        return _unified_drive_service
    if not GOOGLE_AUTH_AVAILABLE:
        return None
    creds = None
    if UNIFIED_TOKEN_PATH.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(UNIFIED_TOKEN_PATH), UNIFIED_SCOPES)
        except ValueError:
            UNIFIED_TOKEN_PATH.unlink()
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(UNIFIED_TOKEN_PATH, 'w') as token:
                token.write(creds.to_json())
        elif 'unified_credentials' in session:
            creds = Credentials(**session['unified_credentials'])
    if creds:
        _unified_drive_service = build('drive', 'v3', credentials=creds)
        return _unified_drive_service
    return None

def unified_credentials_to_dict(credentials):
    return {
        'token': credentials.token, 'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri, 'client_id': credentials.client_id,
        'client_secret': credentials.client_secret, 'scopes': credentials.scopes
    }

def unified_list_files_from_drive(query=None):
    service = create_unified_drive_service()
    if not service:
        return []
    try:
        q = f"name contains '{query}' and trashed=false" if query else "trashed=false"
        results = service.files().list(q=q, pageSize=50, fields="files(id, name, mimeType, modifiedTime, size)").execute()
        return [{'id': f'google:{f["id"]}', 'name': f['name'], 'mimeType': f.get('mimeType'), 'size': f.get('size', '0')} for f in results.get('files', [])]
    except Exception as e:
        logger.error(f"Drive List Error: {e}")
        return []

def unified_get_file_details(file_id):
    service = create_unified_drive_service()
    if not service:
        return None
    try:
        return service.files().get(fileId=file_id, fields='id, name, mimeType, webViewLink').execute()
    except Exception:
        return None

# ==== ROUTES ====

# --- Main ---
@unified_monitoring_bp.route('/unified-monitoring')
def unified_monitoring_home():
    return render_template('unified_home.html')

@unified_monitoring_bp.route('/unified-monitoring/about')
def unified_monitoring_about():
    return render_template('unified_about.html')

# --- Cloud Monitoring ---
@unified_monitoring_bp.route('/unified-monitoring/cloud')
def unified_cloud_home():
    if session.get('unified_user_type') == 'cloud':
        return redirect(url_for('unified_monitoring.unified_cloud_dashboard'))
    return redirect(url_for('unified_monitoring.unified_cloud_login'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/login')
def unified_cloud_login():
    return render_template('unified_cloud/login.html')

@unified_monitoring_bp.route('/unified-monitoring/cloud/auth/google')
def unified_cloud_google_auth():
    if not GOOGLE_AUTH_AVAILABLE:
        flash('Google authentication dependencies not available.', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_login'))
    if not UNIFIED_CREDENTIALS_PATH.exists():
        flash('Google credentials.json not found.', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_login'))
    try:
        import secrets as _secrets, hashlib as _hashlib
        flow = Flow.from_client_secrets_file(
            str(UNIFIED_CREDENTIALS_PATH), scopes=UNIFIED_SCOPES,
            redirect_uri=UNIFIED_GOOGLE_REDIRECT_URI)
        # Generate PKCE code_verifier and challenge (required by Google OAuth2)
        code_verifier = _secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            _hashlib.sha256(code_verifier.encode('ascii')).digest()
        ).rstrip(b'=').decode('ascii')
        auth_url, state = flow.authorization_url(
            access_type='offline', include_granted_scopes='true', prompt='consent',
            code_challenge=code_challenge,
            code_challenge_method='S256'
        )
        session['unified_oauth_state'] = state
        # Store code_verifier SERVER-SIDE (cookie sessions lose it across OAuth redirects)
        from blueprints.phishing import _pkce_save
        _pkce_save(state, code_verifier)
        return redirect(auth_url)
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_login'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/auth/callback')
def unified_cloud_google_callback():
    if not GOOGLE_AUTH_AVAILABLE:
        flash('Authentication dependencies not available.', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_login'))
    try:
        flow = Flow.from_client_secrets_file(
            str(UNIFIED_CREDENTIALS_PATH), scopes=UNIFIED_SCOPES,
            redirect_uri=UNIFIED_GOOGLE_REDIRECT_URI)
        # Retrieve PKCE code_verifier from server-side store
        state = request.args.get('state') or session.get('unified_oauth_state')
        from blueprints.phishing import _pkce_pop
        code_verifier = _pkce_pop(state) if state else None
        auth_code = request.args.get('code')
        if not auth_code:
            flash('No authorization code received from Google.', 'error')
            return redirect(url_for('unified_monitoring.unified_cloud_login'))
        flow.fetch_token(code=auth_code, code_verifier=code_verifier)
        credentials = flow.credentials
        session['unified_credentials'] = unified_credentials_to_dict(credentials)
        with open(UNIFIED_TOKEN_PATH, 'w') as token:
            token.write(credentials.to_json())
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        session['unified_user_type'] = 'cloud'
        session['unified_cloud_user'] = {
            'id': user_info.get('id'), 'email': user_info.get('email'),
            'name': user_info.get('name'), 'picture': user_info.get('picture')
        }
        flash(f'Welcome, {user_info.get("name", "User")}!', 'success')
        return redirect(url_for('unified_monitoring.unified_cloud_dashboard'))
    except Exception as e:
        flash(f'Authentication failed: {str(e)}', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_login'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/logout')
def unified_cloud_logout():
    session.pop('unified_cloud_user', None)
    session.pop('unified_credentials', None)
    session.pop('unified_user_type', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('unified_monitoring.unified_monitoring_home'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/dashboard')
@unified_cloud_login_required
def unified_cloud_dashboard():
    permissions = load_unified_cloud_permissions()
    files = unified_list_files_from_drive()
    return render_template('unified_cloud/dashboard.html',
                          total_files=len(files), total_users=len(permissions),
                          user=session.get('unified_cloud_user', {}))

@unified_monitoring_bp.route('/unified-monitoring/cloud/admin')
@unified_cloud_login_required
def unified_cloud_admin():
    if not UNIFIED_MONITORING_AVAILABLE:
        flash('Feature not available', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_dashboard'))
    CloudUser = current_app.config.get('UNIFIED_CLOUD_USER_MODEL')
    permissions = load_unified_cloud_permissions()
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 50)
    all_files = unified_list_files_from_drive(search)
    total_files = len(all_files)
    total_pages = (total_files + per_page - 1) // per_page if total_files > 0 else 1
    page = max(1, min(page, total_pages))
    start_idx = (page - 1) * per_page
    paginated_files = all_files[start_idx:start_idx + per_page]
    db_users = CloudUser.query.all() if CloudUser else []
    return render_template('unified_cloud/admin.html',
                          users=permissions, db_users=db_users,
                          google_files=paginated_files, all_files=all_files,
                          search_query=search, page=page, per_page=per_page,
                          total_files=total_files, total_pages=total_pages,
                          user=session.get('unified_cloud_user', {}))

@unified_monitoring_bp.route('/unified-monitoring/cloud/files', methods=['GET', 'POST'])
@unified_cloud_login_required
def unified_cloud_files():
    current_user = session.get('unified_cloud_user', {})
    if request.method == 'POST':
        return redirect(url_for('unified_monitoring.unified_cloud_files', email=request.form.get('email')))
    email = request.args.get('email')
    if not email:
        return render_template('unified_cloud/files.html', user=current_user, logged_in_email=current_user.get('email'))
    permissions = load_unified_cloud_permissions()
    user_data = permissions.get(email)
    if not user_data:
        flash('No files assigned to this email.', 'warning')
        return render_template('unified_cloud/files.html', user=current_user, logged_in_email=current_user.get('email'), searched_email=email)
    user_files_list = []
    for file_id in user_data.get('file_ids', []):
        if file_id.startswith('google:'):
            file_details = unified_get_file_details(file_id.split(':')[1])
            if file_details:
                user_files_list.append({'id': file_id, 'name': file_details.get('name', 'Unknown'),
                    'mimeType': file_details.get('mimeType', ''), 'webViewLink': file_details.get('webViewLink', '')})
    return render_template('unified_cloud/files.html', files=user_files_list, email=email,
                          user_name=user_data.get('name', email), user=current_user)

@unified_monitoring_bp.route('/unified-monitoring/cloud/add_user', methods=['POST'])
@unified_cloud_login_required
def unified_cloud_add_user():
    if not UNIFIED_MONITORING_AVAILABLE:
        flash('Feature not available', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_admin'))
    CloudUser = current_app.config.get('UNIFIED_CLOUD_USER_MODEL')
    name = request.form.get('name')
    email = request.form.get('email')
    if CloudUser and not CloudUser.query.filter_by(email=email).first():
        new_user = CloudUser(name=name, email=email, ip_address=get_unified_local_ip())
        unified_db.session.add(new_user)
        unified_db.session.commit()
    permissions = load_unified_cloud_permissions()
    permissions[email] = {'name': name, 'file_ids': request.form.getlist('google_files')}
    save_unified_cloud_permissions(permissions)
    flash(f'User {name} added successfully!', 'success')
    return redirect(url_for('unified_monitoring.unified_cloud_admin'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/update_permissions', methods=['POST'])
@unified_cloud_login_required
def unified_cloud_update_permissions():
    email = request.form.get('email')
    permissions = load_unified_cloud_permissions()
    if email not in permissions:
        flash(f'User {email} not found.', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_admin'))
    permissions[email]['file_ids'] = request.form.getlist('google_files')
    save_unified_cloud_permissions(permissions)
    flash(f'Permissions updated for {email}.', 'success')
    return redirect(url_for('unified_monitoring.unified_cloud_admin'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/remove_user', methods=['POST'])
@unified_cloud_login_required
def unified_cloud_remove_user():
    if not UNIFIED_MONITORING_AVAILABLE:
        flash('Feature not available', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_admin'))
    CloudUser = current_app.config.get('UNIFIED_CLOUD_USER_MODEL')
    email = request.form.get('email')
    permissions = load_unified_cloud_permissions()
    if email in permissions:
        del permissions[email]
        save_unified_cloud_permissions(permissions)
        if CloudUser:
            user = CloudUser.query.filter_by(email=email).first()
            if user:
                unified_db.session.delete(user)
                unified_db.session.commit()
        flash(f'User {email} removed.', 'success')
    else:
        flash(f'User {email} not found.', 'error')
    return redirect(url_for('unified_monitoring.unified_cloud_admin'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/upload', methods=['POST'])
@unified_cloud_login_required
def unified_cloud_upload():
    if 'file' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_admin'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('unified_monitoring.unified_cloud_admin'))
    file_path = UNIFIED_UPLOAD_FOLDER / secure_filename(file.filename)
    file.save(str(file_path))
    try:
        service = create_unified_drive_service()
        if not service:
            raise Exception("Not authenticated with Google Drive")
        from googleapiclient.http import MediaFileUpload
        media = MediaFileUpload(str(file_path), resumable=True)
        uploaded_file = service.files().create(body={'name': file.filename}, media_body=media, fields='id').execute()
        service.permissions().create(fileId=uploaded_file.get('id'), body={'type': 'anyone', 'role': 'reader'}).execute()
        flash(f'File "{file.filename}" uploaded successfully!', 'success')
    except Exception as e:
        flash(f'Error uploading file: {e}', 'error')
    finally:
        if file_path.exists():
            file_path.unlink()
    return redirect(url_for('unified_monitoring.unified_cloud_admin'))

@unified_monitoring_bp.route('/unified-monitoring/cloud/api/files')
@unified_cloud_login_required
def unified_cloud_api_files():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 50)
    all_files = unified_list_files_from_drive(search)
    total_files = len(all_files)
    total_pages = (total_files + per_page - 1) // per_page if total_files > 0 else 1
    page = max(1, min(page, total_pages))
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_files = all_files[start_idx:end_idx]
    files_data = [{'index': start_idx + idx + 1, 'id': f.get('id', ''), 'name': f.get('name', 'Unknown'),
                   'mimeType': f.get('mimeType', '').split('.')[-1] if f.get('mimeType') else 'Unknown',
                   'modifiedTime': f.get('modifiedTime', '')[:10] if f.get('modifiedTime') else 'N/A',
                   'size': round(int(f.get('size', 0)) / 1024, 1)} for idx, f in enumerate(paginated_files)]
    return jsonify({'success': True, 'files': files_data, 'page': page, 'per_page': per_page,
                   'total_files': total_files, 'total_pages': total_pages,
                   'start_idx': start_idx + 1, 'end_idx': min(end_idx, total_files)})

# --- Local USB Monitoring ---
@unified_monitoring_bp.route('/unified-monitoring/local')
def unified_local_home():
    if session.get('unified_user_type') == 'local':
        return redirect(url_for('unified_monitoring.unified_local_dashboard'))
    return redirect(url_for('unified_monitoring.unified_local_login'))

@unified_monitoring_bp.route('/unified-monitoring/local/login')
def unified_local_login():
    return render_template('unified_local/login.html')

@unified_monitoring_bp.route('/unified-monitoring/local/api/auth/login', methods=['POST'])
def unified_local_api_login():
    if not UNIFIED_MONITORING_AVAILABLE or not unified_user_manager:
        return jsonify({'success': False, 'error': 'Monitoring not available'}), 503
    data = request.get_json()
    try:
        client_mac = get_mac_address() if UNIFIED_MONITORING_AVAILABLE else None
    except Exception:
        client_mac = None
    user, result = unified_user_manager.authenticate(data.get('username'), data.get('password'), client_mac)
    if user:
        session['unified_user_type'] = 'local'
        session['unified_local_user'] = {'id': user.id, 'username': user.username, 'role': user.role}
        return jsonify({'success': True, 'user': session['unified_local_user']})
    if unified_alert_manager:
        unified_alert_manager.track_failed_login(data.get('username'), 'unknown')
    return jsonify({'success': False, 'error': result}), 401

@unified_monitoring_bp.route('/unified-monitoring/local/api/auth/me')
@unified_local_login_required
def unified_local_auth_me():
    if 'unified_local_user' in session:
        return jsonify({'success': True, 'user': session['unified_local_user']})
    return jsonify({'success': False, 'error': 'Not logged in'}), 401

@unified_monitoring_bp.route('/unified-monitoring/local/logout')
def unified_local_logout():
    session.pop('unified_local_user', None)
    session.pop('unified_user_type', None)
    return redirect(url_for('unified_monitoring.unified_monitoring_home'))

@unified_monitoring_bp.route('/unified-monitoring/local/dashboard')
@unified_local_login_required
def unified_local_dashboard():
    if not UNIFIED_MONITORING_AVAILABLE or not unified_registry:
        flash('Device monitoring components not initialized', 'error')
        return redirect(url_for('unified_monitoring.unified_monitoring_home'))
    stats = unified_registry.get_statistics()
    users = unified_user_manager.get_all_users() if unified_user_manager else []
    return render_template('unified_local/dashboard.html',
                          user=session.get('unified_local_user'),
                          total_devices=stats.get('total_devices', 0),
                          total_transfers=stats.get('total_transfers', 0),
                          total_users=len(users),
                          local_modules_available=UNIFIED_MONITORING_AVAILABLE)

@unified_monitoring_bp.route('/unified-monitoring/local/api/devices', methods=['GET'])
@unified_local_login_required
def unified_local_get_devices():
    if not unified_identifier:
        return jsonify({'success': False, 'error': 'Device identifier not available'}), 503
    try:
        devices = unified_identifier.get_connected_devices()
        output = []
        for d in devices:
            info = d.to_dict()
            info['name'] = info.get('friendly_name', 'Unknown')
            info['type'] = info.get('device_type', 'Removable')
            info['registered'] = unified_registry.is_registered(d.device_hash)
            output.append(info)

        bus, EventType, Severity, usb_event = _get_event_helpers()
        if bus and output:
            try:
                for ud in [d for d in output if not d.get('registered')]:
                    evt = usb_event(event_type=EventType.USB_UNAUTHORIZED, severity=Severity.HIGH,
                        device_name=ud.get('name', 'Unknown USB'), device_hash=ud.get('device_hash', ''),
                        device_type=ud.get('type', 'Removable'),
                        message=f"Unregistered USB device detected: {ud.get('name', 'Unknown')}")
                    bus.publish(evt)
                for rd in [d for d in output if d.get('registered')]:
                    evt = usb_event(event_type=EventType.USB_INSERTED, severity=Severity.INFO,
                        device_name=rd.get('name', 'Unknown USB'), device_hash=rd.get('device_hash', ''),
                        device_type=rd.get('type', 'Removable'),
                        message=f"Registered USB device connected: {rd.get('name', 'Unknown')}")
                    bus.publish(evt)
            except Exception:
                pass
        return jsonify({'success': True, 'devices': output})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@unified_monitoring_bp.route('/unified-monitoring/local/api/stats')
@unified_local_login_required
def unified_local_stats():
    if not unified_registry:
        return jsonify({'success': False}), 503
    return jsonify({'success': True, 'stats': unified_registry.get_statistics()})

@unified_monitoring_bp.route('/unified-monitoring/local/api/logs')
@unified_local_login_required
def unified_local_logs():
    if not unified_registry:
        return jsonify({'success': False, 'error': 'Registry not available'}), 503
    try:
        logs = unified_registry.get_transfer_logs(limit=50)
        log_data = []
        for l in logs:
            file_name = os.path.basename(l.source_path) if l.source_path else 'Unknown'
            log_data.append({'id': l.id, 'timestamp': l.timestamp, 'device_hash': l.device_hash,
                'file_name': file_name, 'source': file_name,
                'destination': l.destination_path or 'N/A',
                'status': l.transfer_status, 'file_size': l.file_size})
        return jsonify({'success': True, 'logs': log_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@unified_monitoring_bp.route('/unified-monitoring/local/api/drives')
@unified_local_login_required
def unified_local_get_drives():
    if not unified_identifier:
        return jsonify({'success': False, 'error': 'Identifier not available'}), 503
    try:
        devices = unified_identifier.get_connected_devices()
        drives = [d.drive_letter for d in devices if d.drive_letter]
        return jsonify({'success': True, 'drives': drives})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@unified_monitoring_bp.route('/unified-monitoring/local/api/transfer', methods=['POST'])
@unified_local_login_required
def unified_local_transfer():
    if not UNIFIED_MONITORING_AVAILABLE or not unified_controller:
        return jsonify({'success': False, 'error': 'Transfer controller not available'}), 503
    current_user = session.get('unified_local_user', {})
    username = current_user.get('username')
    user_id = current_user.get('id')
    role = current_user.get('role')
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})
        file = request.files['file']
        destination = request.form.get('destination')
        if not destination or not file.filename:
            return jsonify({'success': False, 'error': 'Destination and filename required'})
        device = unified_controller.get_device_for_path(destination + "\\")
        if not device:
            devices = unified_identifier.get_connected_devices()
            for d in devices:
                if d.drive_letter and destination.startswith(d.drive_letter):
                    device = d
                    break
        device_hash = device.device_hash if device else "unknown"

        bus, EventType, Severity, usb_event = _get_event_helpers()

        # Security Check 1: Device must be registered
        if not device or not unified_registry.is_registered(device.device_hash):
            unified_registry.log_transfer(device_hash, file.filename, destination, 0, 'BLOCKED')
            if unified_alert_manager:
                unified_alert_manager.send_alert(AlertType.UNREGISTERED_DEVICE, AlertLevel.WARNING,
                    {'username': username, 'filename': file.filename, 'device': device.friendly_name if device else destination})
            if bus:
                try:
                    evt = usb_event(event_type=EventType.USB_TRANSFER_BLOCKED, severity=Severity.CRITICAL,
                        device_name=device.friendly_name if device else 'Unknown', device_hash=device_hash,
                        message=f"Transfer BLOCKED: {file.filename} to unregistered device",
                        filename=file.filename, username=username, reason='unregistered_device')
                    bus.publish(evt)
                except Exception:
                    pass
            return jsonify({'success': False, 'blocked': True, 'error': 'Device not registered'})

        # Security Check 2: Permission check
        if role == 'user':
            if not unified_user_manager.has_device_permission(user_id, device.device_hash):
                unified_registry.log_transfer(device_hash, file.filename, destination, 0, 'BLOCKED')
                if unified_alert_manager:
                    unified_alert_manager.send_alert(AlertType.BLOCKED_TRANSFER, AlertLevel.WARNING,
                        {'username': username, 'filename': file.filename, 'device': device.friendly_name})
                if bus:
                    try:
                        evt = usb_event(event_type=EventType.USB_TRANSFER_BLOCKED, severity=Severity.HIGH,
                            device_name=device.friendly_name, device_hash=device.device_hash,
                            message=f"Transfer BLOCKED: {file.filename} — user '{username}' lacks permission",
                            filename=file.filename, username=username, reason='permission_denied')
                        bus.publish(evt)
                    except Exception:
                        pass
                return jsonify({'success': False, 'blocked': True, 'error': 'Permission denied'})

        # Perform Transfer
        filename = secure_filename(file.filename)
        dest_path = Path(destination) / filename
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        file.save(str(dest_path))
        unified_registry.log_transfer(device_hash, file.filename, str(dest_path), os.path.getsize(dest_path), 'SUCCESS')

        if bus:
            try:
                evt = usb_event(event_type=EventType.USB_TRANSFER_ALLOWED, severity=Severity.MEDIUM,
                    device_name=device.friendly_name if device else 'Unknown', device_hash=device_hash,
                    message=f"File transferred: {file.filename} to {destination}",
                    filename=file.filename, destination=str(dest_path), username=username,
                    file_size=os.path.getsize(dest_path))
                bus.publish(evt)
            except Exception:
                pass
        return jsonify({'success': True, 'message': 'File transferred', 'destination': str(dest_path)})
    except Exception as e:
        try:
            unified_registry.log_transfer(device_hash if 'device_hash' in locals() else 'unknown',
                file.filename if 'file' in locals() else 'unknown',
                destination if 'destination' in locals() else 'unknown', 0, 'FAILED')
        except Exception:
            pass
        return jsonify({'success': False, 'error': str(e)}), 500

@unified_monitoring_bp.route('/unified-monitoring/local/api/register', methods=['POST'])
@unified_local_login_required
def unified_local_register_device():
    if not unified_registry:
        return jsonify({'success': False, 'error': 'Registry not available'}), 503
    current_user = session.get('unified_local_user', {})
    if current_user.get('role') not in ['superadmin', 'admin']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.json
    device_hash = data.get('hash')
    if not device_hash:
        return jsonify({'success': False, 'error': 'Device hash required'}), 400
    device = None
    if unified_identifier:
        for d in unified_identifier.get_connected_devices():
            if d.device_hash == device_hash:
                device = d
                break
    if not device:
        return jsonify({'success': False, 'error': 'Device not found or not connected'}), 404
    device_info = {
        'device_hash': device.device_hash, 'vendor_id': device.vendor_id,
        'product_id': device.product_id, 'serial_number': device.serial_number,
        'hardware_id': device.hardware_id, 'friendly_name': device.friendly_name,
        'device_type': device.device_type, 'drive_letter': device.drive_letter
    }
    success, message = unified_registry.register_device(device_info)
    if success:
        bus, EventType, Severity, usb_event = _get_event_helpers()
        if bus:
            try:
                evt = usb_event(event_type=EventType.USB_AUTHORIZED, severity=Severity.MEDIUM,
                    device_name=device.friendly_name, device_hash=device.device_hash,
                    message=f"USB device registered: {device.friendly_name}",
                    registered_by=current_user.get('username', 'unknown'))
                bus.publish(evt)
            except Exception:
                pass
        return jsonify({'success': True, 'message': message})
    return jsonify({'success': False, 'error': message}), 500

@unified_monitoring_bp.route('/unified-monitoring/local/api/unregister', methods=['POST'])
@unified_local_login_required
def unified_local_unregister_device():
    if not unified_registry:
        return jsonify({'success': False, 'error': 'Registry not available'}), 503
    current_user = session.get('unified_local_user', {})
    if current_user.get('role') not in ['superadmin', 'admin']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.json
    device_hash = data.get('hash')
    if not device_hash:
        return jsonify({'success': False, 'error': 'Device hash required'}), 400
    success, message = unified_registry.unregister_device(device_hash)
    if success:
        bus, EventType, Severity, usb_event = _get_event_helpers()
        if bus:
            try:
                evt = usb_event(event_type=EventType.USB_DEVICE_BANNED, severity=Severity.HIGH,
                    device_hash=device_hash, message=f"USB device unregistered/banned: {device_hash[:12]}...",
                    unregistered_by=current_user.get('username', 'unknown'))
                bus.publish(evt)
            except Exception:
                pass
        return jsonify({'success': True, 'message': message})
    return jsonify({'success': False, 'error': message}), 500

@unified_monitoring_bp.route('/unified-monitoring/local/api/users', methods=['GET'])
@unified_local_login_required
def unified_local_get_users():
    if not unified_user_manager:
        return jsonify({'success': False, 'error': 'User manager not available'}), 503
    current_user = session.get('unified_local_user', {})
    if current_user.get('role') == 'user':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    users = unified_user_manager.get_all_users()
    users_data = [{'id': u.id, 'username': u.username, 'role': u.role,
                   'mac_address': u.mac_address, 'is_active': u.is_active, 'last_login': u.last_login}
                  for u in users]
    return jsonify({'success': True, 'users': users_data})

@unified_monitoring_bp.route('/unified-monitoring/local/api/users', methods=['POST'])
@unified_local_login_required
def unified_local_add_user():
    if not unified_user_manager:
        return jsonify({'success': False, 'error': 'User manager not available'}), 503
    current_user = session.get('unified_local_user', {})
    creator_role = current_user.get('role')
    if creator_role == 'user':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.json
    role = data.get('role', 'user')
    mac_address = data.get('mac_address')
    if not mac_address:
        try:
            mac_address = get_mac_address()
        except Exception:
            mac_address = ""
    if creator_role == 'admin' and role != 'user':
        return jsonify({'success': False, 'error': 'Admins can only create regular users'}), 403
    success, message = unified_user_manager.create_user(data.get('username'), data.get('password'), mac_address, role, current_user.get('id'))
    if success:
        return jsonify({'success': True, 'message': message})
    return jsonify({'success': False, 'message': message}), 400

@unified_monitoring_bp.route('/unified-monitoring/local/api/users/<int:user_id>', methods=['DELETE'])
@unified_local_login_required
def unified_local_delete_user(user_id):
    if not unified_user_manager:
        return jsonify({'success': False, 'error': 'User manager not available'}), 503
    current_user = session.get('unified_local_user', {})
    if current_user.get('role') == 'user':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    success, message = unified_user_manager.deactivate_user(user_id, current_user.get('id'))
    if success:
        return jsonify({'success': True, 'message': message})
    return jsonify({'success': False, 'message': message}), 400

@unified_monitoring_bp.route('/unified-monitoring/local/api/users/<int:user_id>/reset-password', methods=['POST'])
@unified_local_login_required
def unified_local_reset_password(user_id):
    if not unified_user_manager:
        return jsonify({'success': False, 'error': 'User manager not available'}), 503
    current_user = session.get('unified_local_user', {})
    if current_user.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Only superadmin can reset passwords'}), 403
    data = request.json
    new_password = data.get('new_password')
    if not new_password:
        return jsonify({'success': False, 'message': 'New password required'}), 400
    success, message = unified_user_manager.reset_password(user_id, new_password, current_user.get('id'))
    if success:
        return jsonify({'success': True, 'message': message})
    return jsonify({'success': False, 'message': message}), 400


logger.info("✅ Unified Device Monitoring blueprint loaded")
