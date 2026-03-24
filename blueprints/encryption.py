"""
File Encryption (CryptoVault) Routes
======================================
Handles file encryption/decryption with AES-256-GCM, self-destruct links,
and single-use key sharing links.

Security Notes:
  - Uses AESGCM with 32-byte (256-bit) keys for true AES-256-GCM encryption.
  - PBKDF2 iteration count is 600,000 per NIST SP 800-132 (2023).
  - QR code key sharing has been removed (trivially photographable).
  - View-only mode renders server-side images (PIL) instead of sending raw files.
  - Backward-compatible Fernet decryption is retained for legacy files.
"""

from flask import Blueprint, jsonify, request, render_template, send_file, Response
import os
import io
import json
import uuid
import base64
import time
import mimetypes
import zipfile
import threading
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Backward compatibility — legacy files may still use Fernet
try:
    from cryptography.fernet import Fernet
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

# Optional: PIL for server-side view-only image rendering
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)

encryption_bp = Blueprint('encryption', __name__)

# ---- Configuration ----

encryption_file_storage = {}
ENCRYPTION_STORAGE_EXPIRY_MINUTES = 5

SELF_DESTRUCT_OPTIONS = {
    'none': 0, '30s': 30, '1m': 60, '2m': 120, '5m': 300, '10m': 600
}

VIEWABLE_EXTENSIONS = {
    'images': ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'],
    'documents': ['pdf'],
    'text': ['txt', 'md', 'json', 'xml', 'csv', 'log'],
    'code': ['py', 'js', 'html', 'css', 'java', 'cpp', 'c', 'h', 'php', 'rb', 'go', 'rs', 'ts']
}

FILE_ICONS = {
    'pdf': 'fa-file-pdf',
    'doc': 'fa-file-word', 'docx': 'fa-file-word',
    'xls': 'fa-file-excel', 'xlsx': 'fa-file-excel',
    'ppt': 'fa-file-powerpoint', 'pptx': 'fa-file-powerpoint',
    'jpg': 'fa-file-image', 'jpeg': 'fa-file-image', 'png': 'fa-file-image', 'gif': 'fa-file-image', 'svg': 'fa-file-image',
    'mp3': 'fa-file-audio', 'wav': 'fa-file-audio', 'ogg': 'fa-file-audio',
    'mp4': 'fa-file-video', 'avi': 'fa-file-video', 'mkv': 'fa-file-video',
    'zip': 'fa-file-archive', 'rar': 'fa-file-archive', '7z': 'fa-file-archive', 'tar': 'fa-file-archive',
    'py': 'fa-file-code', 'js': 'fa-file-code', 'html': 'fa-file-code', 'css': 'fa-file-code', 'java': 'fa-file-code',
    'txt': 'fa-file-lines',
    'csv': 'fa-file-csv',
}


# ---- Helper Functions ----

def get_encryption_file_extension(filename):
    return filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

def get_encryption_file_icon(filename):
    ext = get_encryption_file_extension(filename)
    return FILE_ICONS.get(ext, 'fa-file')

def is_file_viewable(filename):
    ext = get_encryption_file_extension(filename)
    for category, extensions in VIEWABLE_EXTENSIONS.items():
        if ext in extensions:
            return True, category
    return False, None

def get_encryption_mime_type(filename):
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'

def cleanup_encryption_expired_files():
    while True:
        time.sleep(5)
        current_time = datetime.now()
        expired_tokens = []
        for token, data in list(encryption_file_storage.items()):
            if current_time > data['expires']:
                expired_tokens.append(token)
                logger.info(f"[SELF-DESTRUCT] File '{data['filename']}' destroyed (expired)")
        for token in expired_tokens:
            if token in encryption_file_storage:
                del encryption_file_storage[token]

# Start cleanup thread
_cleanup_thread = threading.Thread(target=cleanup_encryption_expired_files, daemon=True)
_cleanup_thread.start()

# AES-256-GCM version marker prefix (to distinguish from legacy Fernet data)
_AESGCM_MARKER = b'AEGIS_GCM_V1:'

def generate_encryption_key():
    """Generate a 32-byte (256-bit) key for AES-256-GCM."""
    raw_key = AESGCM.generate_key(bit_length=256)  # 32 bytes
    return base64.urlsafe_b64encode(raw_key)

def derive_key_from_password(password, salt=None):
    """Derive a 32-byte key from a password using PBKDF2 (600,000 iterations)."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=600_000, backend=default_backend()
    )
    raw_key = kdf.derive(password.encode())
    key = base64.urlsafe_b64encode(raw_key)
    return key, salt

def encrypt_file_data(data, key):
    """Encrypt data using AES-256-GCM.
    
    Format: AEGIS_GCM_V1:<12-byte nonce><ciphertext+tag>
    """
    raw_key = base64.urlsafe_b64decode(key)
    aesgcm = AESGCM(raw_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return _AESGCM_MARKER + nonce + ciphertext

def decrypt_file_data(encrypted_data, key):
    """Decrypt data. Supports AES-256-GCM (new) and Fernet (legacy)."""
    raw_key = base64.urlsafe_b64decode(key)
    
    # New AES-256-GCM format
    if encrypted_data.startswith(_AESGCM_MARKER):
        payload = encrypted_data[len(_AESGCM_MARKER):]
        nonce = payload[:12]
        ciphertext = payload[12:]
        aesgcm = AESGCM(raw_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    # Legacy Fernet decryption (backward compatibility)
    if FERNET_AVAILABLE:
        fernet_key = base64.urlsafe_b64encode(raw_key)
        return Fernet(fernet_key).decrypt(encrypted_data)
    
    raise ValueError("Unable to decrypt: unrecognized format and Fernet not available")

def sanitize_upload_filename(filename):
    return secure_filename(filename)

def create_encrypted_package(file_data, original_filename, self_destruct_seconds, view_only=False):
    metadata = {
        'original_filename': original_filename,
        'self_destruct_seconds': self_destruct_seconds,
        'view_only': view_only,
        'created_at': datetime.now().strftime('%d %b %Y, %I:%M:%S %p')
    }
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_length = len(metadata_json).to_bytes(4, 'big')
    return metadata_length + metadata_json + file_data

def extract_encrypted_package(package_data):
    try:
        metadata_length = int.from_bytes(package_data[:4], 'big')
        metadata_json = package_data[4:4+metadata_length].decode('utf-8')
        metadata = json.loads(metadata_json)
        file_data = package_data[4+metadata_length:]
        return metadata, file_data
    except Exception:
        return {'self_destruct_seconds': 0, 'view_only': False}, package_data

def store_encrypted_file(filename, data, original_name=None, self_destruct_seconds=0, is_decrypted=False, view_only=False):
    token = str(uuid.uuid4())
    expiry_time = datetime.now() + timedelta(minutes=ENCRYPTION_STORAGE_EXPIRY_MINUTES)
    encryption_file_storage[token] = {
        'filename': filename,
        'original_name': original_name or filename,
        'data': data,
        'size': len(data),
        'expires': expiry_time,
        'created': datetime.now(),
        'self_destruct_seconds': self_destruct_seconds,
        'is_decrypted': is_decrypted,
        'view_only': view_only,
        'download_count': 0,
        'view_count': 0,
        'self_destruct_activated': False,
        'max_downloads': 999
    }
    return token


# ---- Single-Use Key Link Storage ----
_key_link_storage = {}  # token -> { key, expires, used }

def create_key_link(key_display, expiry_minutes=10):
    """Create a single-use, time-limited link for sharing an encryption key."""
    token = str(uuid.uuid4())
    _key_link_storage[token] = {
        'key': key_display,
        'expires': datetime.now() + timedelta(minutes=expiry_minutes),
        'used': False
    }
    return token

def retrieve_key_link(token):
    """Retrieve a key from a single-use link. Returns key or None.
    Automatically destroys the link after first access."""
    entry = _key_link_storage.get(token)
    if not entry:
        return None
    if entry['used'] or datetime.now() > entry['expires']:
        _key_link_storage.pop(token, None)
        return None
    # Mark as used and schedule deletion
    entry['used'] = True
    key = entry['key']
    _key_link_storage.pop(token, None)
    return key


def _get_event_helpers():
    from blueprints.shared_state import app_state
    if app_state.EVENT_BUS_AVAILABLE and app_state.event_bus:
        try:
            from modules.event_bus.events import EventType, Severity
            from modules.event_bus import encryption_event
            return app_state.event_bus, EventType, Severity, encryption_event
        except Exception:
            pass
    return None, None, None, None


# ---- Routes ----

@encryption_bp.route('/file-encryption')
def file_encryption():
    """File encryption dashboard"""
    return render_template('file_encryption.html')


@encryption_bp.route('/encryption/encrypt', methods=['POST'])
def encrypt_files():
    """Encrypt uploaded files and return download tokens"""
    if 'files' not in request.files:
        return jsonify({'status': 'error', 'message': 'No files selected'}), 400
    
    files = request.files.getlist('files')
    use_password = request.form.get('use_password', 'false') == 'true'
    user_password = request.form.get('password', '')
    self_destruct = request.form.get('self_destruct', 'none')
    view_only = request.form.get('view_only', 'false') == 'true'
    
    self_destruct_seconds = SELF_DESTRUCT_OPTIONS.get(self_destruct, 0)
    file_details = []
    
    if use_password and user_password:
        key, salt = derive_key_from_password(user_password)
        key_display = f"PASSWORD:{base64.b64encode(salt).decode()}"
    else:
        key = generate_encryption_key()
        key_display = key.decode()
    
    for file in files:
        if file.filename:
            sanitized_name = sanitize_upload_filename(file.filename)
            try:
                file_data = file.read()
                original_size = len(file_data)
                
                viewable, category = is_file_viewable(sanitized_name)
                if view_only and not viewable:
                    return jsonify({
                        'status': 'error',
                        'message': f"File '{sanitized_name}' cannot be viewed in browser. Supported: images, PDFs, text files"
                    }), 400
                
                package_data = create_encrypted_package(file_data, sanitized_name, self_destruct_seconds, view_only)
                encrypted_data = encrypt_file_data(package_data, key)
                encrypted_filename = f"encrypted_{sanitized_name}"
                token = store_encrypted_file(encrypted_filename, encrypted_data, sanitized_name)
                icon = get_encryption_file_icon(sanitized_name)
                
                file_details.append({
                    'name': encrypted_filename,
                    'original_name': sanitized_name,
                    'size': f"{len(encrypted_data) / 1024:.1f} KB",
                    'original_size': f"{original_size / 1024:.1f} KB",
                    'token': token,
                    'icon': icon,
                    'self_destruct': self_destruct if self_destruct != 'none' else None,
                    'view_only': view_only
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': f"Error processing {sanitized_name}: {str(e)}"}), 500
    
    bus, EventType, Severity, encryption_event = _get_event_helpers()
    if bus:
        try:
            for fd in file_details:
                evt = encryption_event(
                    event_type=EventType.ENCRYPT_FILE_ENCRYPTED,
                    path=fd.get('original_name', 'unknown'),
                    severity=Severity.MEDIUM,
                    action='encrypt',
                    encrypted_size=fd.get('size', ''),
                    original_size=fd.get('original_size', ''),
                    self_destruct=self_destruct if self_destruct != 'none' else 'disabled',
                    view_only=view_only,
                )
                bus.publish(evt)
        except Exception:
            pass
    
    return jsonify({
        'status': 'success',
        'key': key_display,
        'files': file_details,
        'expires_in': ENCRYPTION_STORAGE_EXPIRY_MINUTES,
        'self_destruct_enabled': self_destruct_seconds > 0,
        'view_only': view_only
    })


@encryption_bp.route('/encryption/decrypt', methods=['POST'])
def decrypt_file_request():
    """Decrypt uploaded files and return view tokens"""
    if 'file' not in request.files or 'key' not in request.form:
        return jsonify({'status': 'error', 'message': 'Missing file or key'}), 400
    
    encrypted_files = request.files.getlist('file')
    key_input = request.form['key']
    file_details = []
    
    try:
        if key_input.startswith('PASSWORD:'):
            user_password = request.form.get('password', '')
            if not user_password:
                return jsonify({'status': 'error', 'message': 'Password required for decryption'}), 400
            salt = base64.b64decode(key_input.replace('PASSWORD:', ''))
            key, _ = derive_key_from_password(user_password, salt)
        else:
            key = key_input.encode()
        
        for encrypted_file in encrypted_files:
            if encrypted_file.filename:
                sanitized_name = sanitize_upload_filename(encrypted_file.filename)
                encrypted_data = encrypted_file.read()
                decrypted_package = decrypt_file_data(encrypted_data, key)
                metadata, file_data = extract_encrypted_package(decrypted_package)
                
                self_destruct_seconds = metadata.get('self_destruct_seconds', 0)
                view_only = metadata.get('view_only', False)
                original_filename = metadata.get('original_filename', sanitized_name)
                output_name = original_filename[10:] if original_filename.startswith('encrypted_') else original_filename
                
                token = store_encrypted_file(
                    output_name, file_data, sanitized_name,
                    self_destruct_seconds=self_destruct_seconds,
                    is_decrypted=True, view_only=view_only
                )
                
                icon = get_encryption_file_icon(output_name)
                viewable, category = is_file_viewable(output_name)
                
                file_details.append({
                    'name': output_name, 'original_name': sanitized_name,
                    'size': f"{len(file_data) / 1024:.1f} KB",
                    'token': token, 'icon': icon, 'view_only': True,
                    'viewable': viewable, 'file_type': category,
                    'self_destruct_seconds': self_destruct_seconds
                })
        
        if file_details and file_details[0].get('self_destruct_seconds', 0) > 0:
            expiry_seconds = file_details[0]['self_destruct_seconds']
            expires_display = f"{expiry_seconds} seconds (after first view)" if expiry_seconds < 60 else f"{expiry_seconds // 60} minute(s) (after first view)"
        else:
            expires_display = f"{ENCRYPTION_STORAGE_EXPIRY_MINUTES} minutes"
        
        bus, EventType, Severity, encryption_event = _get_event_helpers()
        if bus:
            try:
                for fd in file_details:
                    evt = encryption_event(
                        event_type=EventType.ENCRYPT_FILE_DECRYPTED,
                        path=fd.get('original_name', 'unknown'),
                        severity=Severity.MEDIUM, action='decrypt',
                    )
                    bus.publish(evt)
            except Exception:
                pass
        
        return jsonify({'status': 'success', 'files': file_details, 'expires_in': expires_display})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Decryption failed: {str(e)}"}), 500


@encryption_bp.route('/encryption/view/<token>')
def view_encrypted_file(token):
    """View file in browser with watermark (view-only mode)"""
    if token not in encryption_file_storage:
        return render_template('encryption_viewer_error.html', message="File not found or has been destroyed")
    
    file_data = encryption_file_storage[token]
    
    if datetime.now() > file_data['expires']:
        del encryption_file_storage[token]
        return render_template('encryption_viewer_error.html', message="File has expired or been destroyed")
    
    encryption_file_storage[token]['view_count'] += 1
    
    if (file_data.get('is_decrypted') and 
        file_data.get('self_destruct_seconds', 0) > 0 and
        not file_data.get('self_destruct_activated', False)):
        self_destruct_seconds = file_data['self_destruct_seconds']
        new_expiry = datetime.now() + timedelta(seconds=self_destruct_seconds)
        encryption_file_storage[token]['expires'] = new_expiry
        encryption_file_storage[token]['self_destruct_activated'] = True
        logger.info(f"[SELF-DESTRUCT ACTIVATED] File '{file_data['filename']}' will be destroyed in {self_destruct_seconds} seconds")
    
    filename = file_data['filename']
    data = file_data['data']
    ext = get_encryption_file_extension(filename)
    
    watermark_text = f"CONFIDENTIAL • {datetime.now().strftime('%Y-%m-%d %H:%M')} • View Only"
    viewable, category = is_file_viewable(filename)
    
    if not viewable:
        return render_template('encryption_viewer_error.html', message="This file type cannot be viewed in browser")
    
    if category == 'images':
        # Security: render server-side image with burned-in watermark (PIL)
        # CSS watermarks are trivially removed via DevTools
        if PIL_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(data)).convert('RGBA')
                watermark_layer = Image.new('RGBA', img.size, (0, 0, 0, 0))
                draw = ImageDraw.Draw(watermark_layer)
                try:
                    font = ImageFont.truetype("arial.ttf", max(16, img.width // 30))
                except Exception:
                    font = ImageFont.load_default()
                # Tile watermark across the image
                y = 20
                while y < img.height:
                    x = 20
                    while x < img.width:
                        draw.text((x, y), watermark_text, fill=(255, 0, 0, 60), font=font)
                        x += max(200, img.width // 3)
                    y += max(80, img.height // 6)
                img = Image.alpha_composite(img, watermark_layer).convert('RGB')
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                buf.seek(0)
                image_base64 = base64.b64encode(buf.getvalue()).decode()
                return render_template('encryption_viewer_image.html', filename=filename, image_data=f"data:image/png;base64,{image_base64}", watermark=watermark_text)
            except Exception:
                pass  # fallback to raw image below
        # Fallback if PIL not available
        image_base64 = base64.b64encode(data).decode()
        mime_type = get_encryption_mime_type(filename)
        return render_template('encryption_viewer_image.html', filename=filename, image_data=f"data:{mime_type};base64,{image_base64}", watermark=watermark_text)
    elif category == 'documents' and ext == 'pdf':
        pdf_base64 = base64.b64encode(data).decode()
        return render_template('encryption_viewer_pdf.html', filename=filename, pdf_data=pdf_base64, watermark=watermark_text)
    elif category in ['text', 'code']:
        try:
            text_content = data.decode('utf-8')
        except Exception:
            text_content = data.decode('latin-1')
        return render_template('encryption_viewer_text.html', filename=filename, content=text_content, is_code=(category == 'code'), language=ext, watermark=watermark_text)
    
    return render_template('encryption_viewer_error.html', message="Unable to display file")


@encryption_bp.route('/encryption/file-content/<token>')
def get_encryption_file_content(token):
    if token not in encryption_file_storage:
        return jsonify({'status': 'error'}), 404
    file_data = encryption_file_storage[token]
    if datetime.now() > file_data['expires']:
        del encryption_file_storage[token]
        return jsonify({'status': 'error'}), 410
    mime_type = get_encryption_mime_type(file_data['filename'])
    return Response(
        file_data['data'], mimetype=mime_type,
        headers={'Content-Disposition': 'inline', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0', 'X-Content-Type-Options': 'nosniff'}
    )


@encryption_bp.route('/encryption/download/<token>')
def download_encrypted_file(token):
    if token not in encryption_file_storage:
        return jsonify({'status': 'error', 'message': 'File not found or has been destroyed'}), 404
    file_data = encryption_file_storage[token]
    if file_data.get('is_decrypted', False):
        return jsonify({'status': 'error', 'message': 'Decrypted files can only be viewed, not downloaded'}), 403
    if datetime.now() > file_data['expires']:
        del encryption_file_storage[token]
        return jsonify({'status': 'error', 'message': 'File has expired or been destroyed'}), 410
    encryption_file_storage[token]['download_count'] += 1
    return send_file(io.BytesIO(file_data['data']), download_name=file_data['filename'], as_attachment=True)


@encryption_bp.route('/encryption/download-zip', methods=['POST'])
def download_encrypted_zip():
    tokens = request.json.get('tokens', [])
    if not tokens:
        return jsonify({'status': 'error', 'message': 'No files selected'}), 400
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for token in tokens:
            if token in encryption_file_storage:
                file_data = encryption_file_storage[token]
                if not file_data.get('is_decrypted', False) and datetime.now() <= file_data['expires']:
                    zip_file.writestr(file_data['filename'], file_data['data'])
    zip_buffer.seek(0)
    return send_file(zip_buffer, download_name='encrypted_files.zip', as_attachment=True, mimetype='application/zip')


# QR code key sharing REMOVED — security risk (trivially photographed/screenshotted).
# Replaced with single-use, time-limited HTTPS key links.

@encryption_bp.route('/encryption/create-key-link', methods=['POST'])
def create_encryption_key_link():
    """Create a single-use, time-limited link for sharing an encryption key."""
    key = request.json.get('key', '')
    if not key:
        return jsonify({'status': 'error', 'message': 'No key provided'}), 400
    expiry_minutes = request.json.get('expiry_minutes', 10)
    token = create_key_link(key, expiry_minutes=expiry_minutes)
    link = f"/encryption/key-link/{token}"
    return jsonify({
        'status': 'success',
        'link': link,
        'expires_in_minutes': expiry_minutes,
        'note': 'This link can only be accessed once.'
    })

@encryption_bp.route('/encryption/key-link/<token>')
def get_key_link(token):
    """Retrieve encryption key from a single-use link.
    The link self-destructs after first access."""
    key = retrieve_key_link(token)
    if key is None:
        return jsonify({
            'status': 'error',
            'message': 'Key link has expired, already been used, or does not exist.'
        }), 410
    return jsonify({'status': 'success', 'key': key})


@encryption_bp.route('/encryption/file-info/<token>')
def get_encryption_file_info(token):
    if token not in encryption_file_storage:
        return jsonify({'status': 'error', 'message': 'File not found'}), 404
    file_data = encryption_file_storage[token]
    remaining_time = (file_data['expires'] - datetime.now()).total_seconds()
    return jsonify({
        'status': 'success', 'filename': file_data['filename'],
        'size': file_data['size'], 'expires_in_seconds': max(0, int(remaining_time)),
        'created': file_data['created'].strftime('%d %b %Y, %I:%M:%S %p'),
        'view_only': file_data.get('view_only', False)
    })


logger.info("✅ File Encryption blueprint loaded")
