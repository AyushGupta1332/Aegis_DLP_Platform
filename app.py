from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, g, send_file, Response
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
import time
import pandas as pd
import numpy as np
import pickle
from collections import deque
import os
import subprocess
import warnings
from pathlib import Path
import re
import json
import logging
import sqlite3
import io
import base64
from datetime import datetime, timedelta
from urllib.parse import urlparse
import uuid
import zipfile
import mimetypes
from werkzeug.utils import secure_filename

# File Encryption imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import qrcode

warnings.filterwarnings('ignore')


# Phishing Detection imports
try:
    import yara
    import tldextract
    from langdetect import detect
    from bs4 import BeautifulSoup
    from PIL import Image
    import PyPDF2
    from docx import Document
    from modules.body_classifier import predict_body_label
    from google_auth_oauthlib.flow import Flow
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    import requests as http_requests  # renamed to avoid conflict
    PHISHING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some phishing detection dependencies not available: {e}")
    PHISHING_AVAILABLE = False

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'No-Secret-For-Now'
CORS(app)
# Use threading mode for proper background thread emit support
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables - Anomaly Detection
monitoring_active = False
traffic_gen_process = None
monitor_thread = None
prediction_queue = deque(maxlen=100)
stats = {
    'total_samples': 0,
    'normal_count': 0,
    'anomaly_count': 0,
    'accuracy': 0.0
}

# Track last processed row count
last_processed_rows = 0

# Global variables - Data Classification
scanning_active = False
scan_thread = None
classification_results = []
classification_stats = {
    'total_files': 0,
    'sensitive_count': 0,
    'non_sensitive_count': 0
}

# ========== FILE ENCRYPTION CONFIGURATION ==========
# In-memory file storage with expiration
encryption_file_storage = {}
ENCRYPTION_STORAGE_EXPIRY_MINUTES = 5
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Self-destruct timer options (in seconds)
SELF_DESTRUCT_OPTIONS = {
    'none': 0,
    '30s': 30,
    '1m': 60,
    '2m': 120,
    '5m': 300,
    '10m': 600
}

# Supported file types for view-only mode
VIEWABLE_EXTENSIONS = {
    'images': ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'],
    'documents': ['pdf'],
    'text': ['txt', 'md', 'json', 'xml', 'csv', 'log'],
    'code': ['py', 'js', 'html', 'css', 'java', 'cpp', 'c', 'h', 'php', 'rb', 'go', 'rs', 'ts']
}

# File type icons mapping
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

# File Encryption Helper Functions
def get_encryption_file_extension(filename):
    """Get file extension in lowercase"""
    return filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

def get_encryption_file_icon(filename):
    """Get Font Awesome icon class based on file extension"""
    ext = get_encryption_file_extension(filename)
    return FILE_ICONS.get(ext, 'fa-file')

def is_file_viewable(filename):
    """Check if file can be viewed in browser"""
    ext = get_encryption_file_extension(filename)
    for category, extensions in VIEWABLE_EXTENSIONS.items():
        if ext in extensions:
            return True, category
    return False, None

def get_encryption_mime_type(filename):
    """Get MIME type for file"""
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'

def cleanup_encryption_expired_files():
    """Background thread to cleanup expired files from memory"""
    while True:
        time.sleep(5)
        current_time = datetime.now()
        expired_tokens = []
        
        for token, data in list(encryption_file_storage.items()):
            if current_time > data['expires']:
                expired_tokens.append(token)
                logger.info(f"[SELF-DESTRUCT] File '{data['filename']}' has been destroyed (expired)")
        
        for token in expired_tokens:
            if token in encryption_file_storage:
                del encryption_file_storage[token]

# Start cleanup thread for file encryption
encryption_cleanup_thread = threading.Thread(target=cleanup_encryption_expired_files, daemon=True)
encryption_cleanup_thread.start()

def generate_encryption_key():
    return Fernet.generate_key()

def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data)

def decrypt_file_data(encrypted_data, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data)

def sanitize_upload_filename(filename):
    return secure_filename(filename)

def create_encrypted_package(file_data, original_filename, self_destruct_seconds, view_only=False):
    """Create a package with file data and hidden metadata"""
    metadata = {
        'original_filename': original_filename,
        'self_destruct_seconds': self_destruct_seconds,
        'view_only': view_only,
        'created_at': datetime.now().isoformat()
    }
    
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_length = len(metadata_json).to_bytes(4, 'big')
    
    return metadata_length + metadata_json + file_data

def extract_encrypted_package(package_data):
    """Extract file data and hidden metadata from package"""
    try:
        metadata_length = int.from_bytes(package_data[:4], 'big')
        metadata_json = package_data[4:4+metadata_length].decode('utf-8')
        metadata = json.loads(metadata_json)
        file_data = package_data[4+metadata_length:]
        return metadata, file_data
    except:
        return {'self_destruct_seconds': 0, 'view_only': False}, package_data

def store_encrypted_file(filename, data, original_name=None, self_destruct_seconds=0, is_decrypted=False, view_only=False):
    """Store file in memory with UUID token and expiration"""
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

# ========== PHISHING DETECTION CONFIGURATION ==========

# YARA configuration
app.config['YARA_RULES_DIR'] = os.path.join(os.path.dirname(__file__), 'data', 'yara_rules', 'rules')
app.config['TEMP_DIR'] = os.path.join(os.getcwd(), 'temp')
app.config['PHISHING_DB'] = os.path.join(os.path.dirname(__file__), 'databases', 'emails.db')

# Load trusted domains
TRUSTED_CSV_PATH = os.path.join(os.path.dirname(__file__), 'data', 'top-1m.csv')
trusted_set = set()

PUBLIC_EMAIL_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'icloud.com', 'mail.com', 'protonmail.com', 'yandex.com'
}

# Load trusted domains from CSV
if PHISHING_AVAILABLE:
    try:
        df = pd.read_csv(TRUSTED_CSV_PATH, header=None)
        trusted_set = set(str(x).strip().lower() for x in df[0].dropna() 
                         if str(x).strip().lower() not in PUBLIC_EMAIL_PROVIDERS)
        logger.info(f"Loaded {len(trusted_set)} trusted entries from {TRUSTED_CSV_PATH}")
    except Exception as e:
        logger.warning(f"Could not load trusted domains: {e}")
        trusted_set = set()

# YARA rules initialization
yara_rules = None

def initialize_yara_rules():
    global yara_rules
    if not PHISHING_AVAILABLE:
        return
    rules_dir = app.config['YARA_RULES_DIR']
    if not os.path.exists(rules_dir):
        logger.warning(f"YARA rules directory not found: {rules_dir}")
        yara_rules = None
        return
    try:
        rule_files = []
        for root, dirs, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    rule_path = os.path.join(root, file)
                    try:
                        with open(rule_path, 'r') as f:
                            content = f.read()
                            yara.compile(source=content)
                        rule_files.append((os.path.splitext(os.path.basename(file))[0], rule_path))
                    except Exception as e:
                        continue
        if rule_files:
            yara_rules = yara.compile(filepaths={rule_name: rule_path for rule_name, rule_path in rule_files})
            logger.info(f"YARA rules loaded: {len(rule_files)} rule files")
    except Exception as e:
        logger.warning(f"Error loading YARA rules: {e}")
        yara_rules = None

# Initialize phishing database
def init_phishing_db():
    conn = sqlite3.connect(app.config['PHISHING_DB'])
    conn.execute('''
        CREATE TABLE IF NOT EXISTS Email (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT,
            sender TEXT,
            receiver TEXT,
            subject TEXT,
            body TEXT,
            category TEXT,
            confidence_score REAL,
            needs_review INTEGER DEFAULT 0,
            explanation TEXT,
            features TEXT,
            urls TEXT,
            provider TEXT,
            user_email TEXT,
            received_date INTEGER,
            has_feedback INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS Attachment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            data BLOB,
            email_id INTEGER,
            sensitivity TEXT,
            content_type TEXT,
            yara_result TEXT,
            FOREIGN KEY (email_id) REFERENCES Email(id)
        )
    ''')
    conn.commit()
    conn.close()

# ========== SINGLE DATABASE FOR ALL USERS ==========
FEEDBACK_DB_PATH = os.path.join(os.path.dirname(__file__), 'databases', 'feedback.db')

def get_phishing_db_connection():
    """Get a connection to the main phishing emails database"""
    conn = sqlite3.connect(app.config['PHISHING_DB'])
    conn.row_factory = sqlite3.Row
    return conn

# Initialize feedback database
def init_feedback_db():
    """Initialize the unified feedback database"""
    conn = sqlite3.connect(FEEDBACK_DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS Feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            user_email TEXT,
            provider TEXT,
            original_category TEXT,
            corrected_category TEXT,
            feedback_reason TEXT,
            email_subject TEXT,
            email_sender TEXT,
            email_body_preview TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    logger.info(f"Initialized feedback database: {FEEDBACK_DB_PATH}")

# Initialize databases on startup
init_feedback_db()

if PHISHING_AVAILABLE:
    init_phishing_db()
    initialize_yara_rules()

# ========== GOOGLE & OUTLOOK API CONFIGURATION ==========
# Google Gmail API credentials from environment variables
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5000/phishing/callback')
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Outlook API credentials from environment variables
OUTLOOK_CLIENT_ID = os.environ.get('OUTLOOK_CLIENT_ID')
OUTLOOK_CLIENT_SECRET = os.environ.get('OUTLOOK_CLIENT_SECRET')
OUTLOOK_REDIRECT_URI = os.environ.get('OUTLOOK_REDIRECT_URI', 'http://localhost:5000/phishing/callback_outlook')
OUTLOOK_SCOPES = ['https://graph.microsoft.com/Mail.Read']

def get_google_client_config():
    """Build Google OAuth client config dynamically from environment variables"""
    return {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [GOOGLE_REDIRECT_URI]
        }
    }

def build_gmail_service(credentials):
    """Build Gmail API service"""
    return build('gmail', 'v1', credentials=credentials)

def clean_preview_text(html_content, max_length=200):
    """Clean HTML content for preview"""
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, 'html.parser')
    for tag in soup.find_all(True):
        tag.unwrap()
    text = soup.get_text(separator=' ', strip=True)
    text = ' '.join(text.split())
    if len(text) > max_length:
        text = text[:max_length] + "..."
    return text

def extract_text_from_pdf(pdf_data):
    """Extract text from PDF data."""
    text = ''
    reader = PyPDF2.PdfReader(io.BytesIO(pdf_data))
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text += page_text + '\n'
    return text

def extract_text_from_docx(docx_data):
    """Extract text from DOCX data."""
    doc = Document(io.BytesIO(docx_data))
    return "\n".join([para.text for para in doc.paragraphs])

def classify_text_attachment(text):
    """Classify text content as sensitive or non-sensitive."""
    try:
        if not text or text.strip() == '':
            return 'non-sensitive'
        # Use document classifier if available
        try:
            from phishing_document_classifier import classify_text_content
            return classify_text_content(text)
        except:
            return 'non-sensitive'
    except Exception as e:
        logger.error(f"Error classifying text attachment: {e}")
        return 'non-sensitive'

# Global cache for the image classification model
_cached_image_model = None

def _load_image_model():
    """Load and cache the image classification model with Keras 3.x to 2.x conversion."""
    global _cached_image_model
    
    if _cached_image_model is not None:
        return _cached_image_model
    
    image_model_path = os.path.join(os.path.dirname(__file__), 'image_model.h5')
    if not os.path.exists(image_model_path):
        return None
    
    import tensorflow as tf
    import h5py
    import tempfile
    import shutil
    
    def convert_keras3_config_to_keras2(config):
        """Recursively convert Keras 3.x config format to Keras 2.x format."""
        if isinstance(config, dict):
            new_config = {}
            for key, value in config.items():
                # Convert DTypePolicy to simple string
                if key == 'dtype' and isinstance(value, dict) and value.get('class_name') == 'DTypePolicy':
                    new_config[key] = value.get('config', {}).get('name', 'float32')
                # Convert batch_shape to batch_input_shape
                elif key == 'batch_shape':
                    new_config['batch_input_shape'] = value
                # Convert nested initializer/regularizer objects to simple format
                elif key in ['kernel_initializer', 'bias_initializer', 'kernel_regularizer', 
                             'bias_regularizer', 'activity_regularizer'] and isinstance(value, dict):
                    if 'class_name' in value:
                        class_name = value.get('class_name', '')
                        inner_config = value.get('config', {})
                        # Simplify to the format Keras 2.x expects
                        new_config[key] = {'class_name': class_name, 'config': inner_config}
                    else:
                        new_config[key] = convert_keras3_config_to_keras2(value)
                else:
                    new_config[key] = convert_keras3_config_to_keras2(value)
            return new_config
        elif isinstance(config, list):
            return [convert_keras3_config_to_keras2(item) for item in config]
        else:
            return config
    
    try:
        # Create a temporary copy of the model file and modify it
        with tempfile.NamedTemporaryFile(suffix='.h5', delete=False) as tmp_file:
            temp_path = tmp_file.name
        
        shutil.copy2(image_model_path, temp_path)
        
        # Modify the model config in the temp file
        with h5py.File(temp_path, 'r+') as f:
            if 'model_config' in f.attrs:
                model_config_str = f.attrs['model_config']
                if isinstance(model_config_str, bytes):
                    model_config_str = model_config_str.decode('utf-8')
                model_config = json.loads(model_config_str)
                
                # Convert the config
                converted_config = convert_keras3_config_to_keras2(model_config)
                
                # Write back
                f.attrs['model_config'] = json.dumps(converted_config).encode('utf-8')
        
        # Load the modified model
        _cached_image_model = tf.keras.models.load_model(temp_path, compile=False)
        logger.info("Image classification model loaded and cached successfully")
        
        # Clean up temp file
        try:
            os.remove(temp_path)
        except:
            pass
        
        return _cached_image_model
    except Exception as e:
        logger.error(f"Error loading image model: {e}")
        return None

def classify_image_attachment(image_data):
    """Classify image content as sensitive or non-sensitive using CNN."""
    try:
        if not PHISHING_AVAILABLE:
            return 'non-sensitive'
        image = Image.open(io.BytesIO(image_data))
        if image.mode == 'RGBA':
            image = image.convert('RGB')
        image = image.resize((150, 150))
        image_array = np.array(image) / 255.0
        image_array = np.expand_dims(image_array, axis=0)
        
        # Get cached model
        image_model = _load_image_model()
        if image_model is not None:
            prediction = image_model.predict(image_array, verbose=0)
            sensitivity = 'sensitive' if prediction[0] > 0.5 else 'non-sensitive'
            return sensitivity
        return 'non-sensitive'
    except Exception as e:
        logger.error(f"Error classifying image attachment: {e}")
        return 'non-sensitive'


def process_gmail_message(service, message_id):
    """Process a Gmail message and extract data for classification."""
    try:
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        headers = {h['name']: h['value'] for h in msg['payload']['headers']}
        sender = headers.get('From', 'Unknown Sender')
        if not re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender):
            sender = 'unknown@unknown.com'
        receiver = headers.get('To', 'Unknown Receiver')
        subject = headers.get('Subject', 'No Subject')

        attachments = []
        body = ""
        html_content = None
        plain_content = None

        # Process message parts
        parts_to_process = [msg['payload']]
        while parts_to_process:
            part = parts_to_process.pop(0)
            mime_type = part.get('mimeType', '')

            if 'parts' in part:
                parts_to_process = part['parts'] + parts_to_process
                continue

            if mime_type == 'text/html':
                if 'data' in part['body']:
                    html_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
            elif mime_type == 'text/plain':
                if 'data' in part['body'] and not html_content:
                    plain_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')

            # Attachments
            if part.get('filename'):
                if part['body'].get('attachmentId'):
                    att_id = part['body']['attachmentId']
                    att = service.users().messages().attachments().get(
                        userId='me', messageId=message_id, id=att_id
                    ).execute()
                    data = base64.urlsafe_b64decode(att['data'])
                    file_type = part.get('mimeType')
                    sensitivity = 'non-sensitive'
                    if file_type and file_type.startswith('image/'):
                        sensitivity = classify_image_attachment(data)
                    elif file_type == 'application/pdf':
                        text = extract_text_from_pdf(data)
                        sensitivity = classify_text_attachment(text)
                    elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                        text = extract_text_from_docx(data)
                        sensitivity = classify_text_attachment(text)
                    elif file_type == 'text/plain':
                        text = data.decode('utf-8', errors='ignore')
                        sensitivity = classify_text_attachment(text)

                    attachments.append({
                        'filename': part['filename'],
                        'data': data,
                        'sensitivity': sensitivity,
                        'content_type': file_type
                    })

        # Fallback for simple emails
        if not (html_content or plain_content) and msg['payload'].get('body', {}).get('data'):
            body_data = msg['payload']['body']['data']
            plain_content = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

        # Clean body
        if html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            for tag in soup.find_all(['script', 'style', 'link', 'meta']):
                tag.decompose()
            body = soup.get_text(separator=' ', strip=True)
        elif plain_content:
            body = plain_content
        body = ' '.join(body.split())
        if body.startswith(subject):
            body = body[len(subject):].strip()

        urls = extract_and_classify_urls(subject, body)
        category, confidence, explanation, needs_review, features = classify_email(message_id, sender, subject, body, attachments)

        return {
            'message_id': message_id,
            'sender': sender,
            'receiver': receiver,
            'subject': subject,
            'body': body,
            'category': category,
            'confidence_score': confidence,
            'explanation': explanation,
            'needs_review': needs_review,
            'features': features,
            'attachments': attachments,
            'urls': urls
        }
    except Exception as e:
        logger.error(f"Error processing Gmail message {message_id}: {str(e)}")
        return None

def process_outlook_email(email):
    """Process an Outlook email and extract data for classification."""
    try:
        sender = email['from']['emailAddress']['address'] if 'from' in email and 'emailAddress' in email['from'] else 'Unknown Sender'
        if not re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender):
            sender = 'unknown@unknown.com'
        receiver = email['toRecipients'][0]['emailAddress']['address'] if 'toRecipients' in email and email['toRecipients'] else 'Unknown Receiver'
        subject = email.get('subject', 'No Subject')
        body = email.get('body', {}).get('content', '')

        soup = BeautifulSoup(body, 'html.parser')
        for tag in soup.find_all(['style', 'script']):
            tag.decompose()
        body = soup.get_text(separator=' ', strip=True)
        body = ' '.join(body.split())
        if body.startswith(subject):
            body = body[len(subject):].strip()

        urls = extract_and_classify_urls(subject, body)

        # Process attachments
        attachments = []
        if 'attachments' in email:
            for attachment in email['attachments']:
                att_data = base64.b64decode(attachment.get('contentBytes', ''))
                content_type = attachment.get('contentType', '')
                sensitivity = 'non-sensitive'
                if content_type.startswith('image/'):
                    sensitivity = classify_image_attachment(att_data)
                elif content_type == 'application/pdf':
                    text = extract_text_from_pdf(att_data)
                    sensitivity = classify_text_attachment(text)
                elif content_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                    text = extract_text_from_docx(att_data)
                    sensitivity = classify_text_attachment(text)
                elif content_type == 'text/plain':
                    text = att_data.decode('utf-8', errors='ignore')
                    sensitivity = classify_text_attachment(text)
                
                attachments.append({
                    'filename': attachment.get('name', 'unknown'),
                    'data': att_data,
                    'sensitivity': sensitivity,
                    'content_type': content_type
                })

        category, confidence, explanation, needs_review, features = classify_email(email['id'], sender, subject, body, attachments)

        return {
            'message_id': email['id'],
            'sender': sender,
            'receiver': receiver,
            'subject': subject,
            'body': body,
            'category': category,
            'confidence_score': confidence,
            'explanation': explanation,
            'needs_review': needs_review,
            'features': features,
            'attachments': attachments,
            'urls': urls
        }
    except Exception as e:
        logger.error(f"Error processing Outlook email: {str(e)}")
        return None

def fetch_and_process_gmail_emails(service, user_email, num_emails):
    """Fetch emails from Gmail and process them."""
    try:
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=num_emails
        ).execute()
        messages = results.get('messages', [])
        
        logger.info(f"Fetching {len(messages)} emails for {user_email}")
        
        # Use single phishing database
        conn = get_phishing_db_connection()
        
        for msg in messages:
            try:
                message_id = msg['id']
                
                # Check if already processed for this user
                cursor = conn.execute('SELECT id FROM Email WHERE message_id = ? AND user_email = ?', (message_id, user_email))
                if cursor.fetchone():
                    continue
                    continue
                
                # Get full message
                msg_full = service.users().messages().get(userId='me', id=message_id, format='full').execute()
                received_date = int(msg_full.get('internalDate', 0))
                
                # Process the message
                email_data = process_gmail_message(service, message_id)
                if email_data is None:
                    continue
                
                # Store in single phishing database with user info
                conn.execute('''
                    INSERT INTO Email (message_id, sender, receiver, subject, body, category, 
                                      confidence_score, needs_review, explanation, features, urls, 
                                      provider, user_email, received_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email_data['message_id'],
                    email_data['sender'],
                    email_data['receiver'],
                    email_data['subject'],
                    email_data['body'],
                    email_data['category'],
                    email_data['confidence_score'],
                    1 if email_data['needs_review'] else 0,
                    json.dumps(email_data.get('explanation', [])),
                    json.dumps(email_data.get('features', {})),
                    json.dumps(email_data.get('urls', [])),
                    'gmail',
                    user_email,
                    received_date
                ))
                
                # Store attachments
                email_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                for att in email_data.get('attachments', []):
                    conn.execute('''
                        INSERT INTO Attachment (filename, data, email_id, sensitivity, content_type)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (att['filename'], att['data'], email_id, att['sensitivity'], att['content_type']))
                
                conn.commit()
                logger.info(f"Processed Gmail email for {user_email}: {email_data['subject'][:50]}")
                
            except Exception as e:
                logger.error(f"Error processing email {msg.get('id')}: {e}")
                continue
        
        conn.close()
        logger.info(f"Finished processing {len(messages)} emails")
        
    except Exception as e:
        logger.error(f"Error fetching Gmail emails: {e}")

def fetch_and_process_outlook_emails(access_token, user_email, num_emails):
    """Fetch emails from Outlook and process them."""
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = http_requests.get(
            'https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages',
            headers=headers,
            params={'$top': num_emails, '$orderby': 'receivedDateTime desc', '$expand': 'attachments'}
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch Outlook emails: {response.text}")
            return
        
        messages = response.json().get('value', [])
        logger.info(f"Fetching {len(messages)} Outlook emails for {user_email}")
        
        # Use single phishing database
        conn = get_phishing_db_connection()
        
        for email in messages:
            try:
                message_id = email['id']
                
                # Check if already processed for this user
                cursor = conn.execute('SELECT id FROM Email WHERE message_id = ? AND user_email = ?', (message_id, user_email))
                if cursor.fetchone():
                    continue
                
                # Parse date
                received_date_str = email.get('receivedDateTime', '1970-01-01T00:00:00Z')
                try:
                    received_date_dt = datetime.strptime(received_date_str.replace('Z', ''), '%Y-%m-%dT%H:%M:%S')
                    received_date = int(received_date_dt.timestamp() * 1000)
                except:
                    received_date = 0
                
                # Process the email
                email_data = process_outlook_email(email)
                if email_data is None:
                    continue
                
                # Store in phishing database with provider and user_email
                conn.execute('''
                    INSERT OR IGNORE INTO Email (message_id, sender, receiver, subject, body, category, 
                                      confidence_score, needs_review, explanation, features, urls, 
                                      provider, user_email, received_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email_data['message_id'],
                    email_data['sender'],
                    email_data['receiver'],
                    email_data['subject'],
                    email_data['body'],
                    email_data['category'],
                    email_data['confidence_score'],
                    1 if email_data['needs_review'] else 0,
                    json.dumps(email_data.get('explanation', [])),
                    json.dumps(email_data.get('features', {})),
                    json.dumps(email_data.get('urls', [])),
                    'outlook',
                    user_email,
                    received_date
                ))
                
                # Store attachments
                email_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                for att in email_data.get('attachments', []):
                    conn.execute('''
                        INSERT INTO Attachment (filename, data, email_id, sensitivity, content_type)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (att['filename'], att['data'], email_id, att['sensitivity'], att['content_type']))
                
                conn.commit()
                logger.info(f"Processed Outlook email: {email_data['subject'][:50]}")
                
            except Exception as e:
                logger.error(f"Error processing Outlook email {email.get('id')}: {e}")
                continue
        
        conn.close()
        logger.info(f"Finished processing {len(messages)} Outlook emails")
        
    except Exception as e:
        logger.error(f"Error fetching Outlook emails: {e}")

# Load MLP model and preprocessors
def load_mlp_model():
    try:
        print("Loading MLP model and preprocessors...")
        
        # Use absolute paths based on script location
        base_dir = os.path.dirname(os.path.abspath(__file__))
        models_dir = os.path.join(base_dir, 'models', 'anomaly_detection')
        
        model_path = os.path.join(models_dir, 'mlp_ids_model.pkl')
        scaler_path = os.path.join(models_dir, 'scaler.pkl')
        encoders_path = os.path.join(models_dir, 'label_encoders.pkl')
        features_path = os.path.join(models_dir, 'feature_info.pkl')
        
        print(f"  Loading model from: {model_path}")
        
        if not os.path.exists(model_path):
            print(f"  ERROR: Model file not found at {model_path}")
            return None, None, None, None
        
        with open(model_path, 'rb') as f:
            mlp_model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            mlp_scaler = pickle.load(f)
        
        with open(encoders_path, 'rb') as f:
            mlp_label_encoders = pickle.load(f)
        
        with open(features_path, 'rb') as f:
            mlp_feature_info = pickle.load(f)
        
        print("✓ MLP model loaded successfully!")
        return mlp_model, mlp_scaler, mlp_label_encoders, mlp_feature_info
    except Exception as e:
        print(f"Error loading MLP model: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None

mlp_model, mlp_scaler, mlp_label_encoders, mlp_feature_info = load_mlp_model()

# Prediction function for MLP model
def predict_samples(df):
    global stats
    
    if mlp_model is None:
        print("MLP Model not loaded!")
        return []
    
    try:
        # Remove target columns if present
        X_test = df.drop(['label', 'anomaly'], axis=1, errors='ignore')
        
        # Encode categorical features
        X_test_encoded = X_test.copy()
        categorical_cols = mlp_feature_info['categorical_cols']
        
        for col in categorical_cols:
            if col in X_test_encoded.columns:
                le = mlp_label_encoders[col]
                # Handle unseen categories
                X_test_encoded[col] = X_test_encoded[col].astype(str).apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                )
        
        # Scale features
        X_test_scaled = mlp_scaler.transform(X_test_encoded)
        
        # Predict
        y_pred = mlp_model.predict(X_test_scaled)
        y_pred_proba = mlp_model.predict_proba(X_test_scaled)[:, 1]
        
        results = []
        for i, pred in enumerate(y_pred):
            # Get confidence (probability of predicted class)
            confidence = y_pred_proba[i] if pred == 1 else (1 - y_pred_proba[i])
            
            result = {
                'prediction': 'Normal' if pred == 0 else 'Anomaly',
                'confidence': float(confidence * 100),
                'timestamp': time.strftime('%H:%M:%S')
            }
            results.append(result)
            
            # Update stats
            stats['total_samples'] += 1
            if pred == 0:
                stats['normal_count'] += 1
            else:
                stats['anomaly_count'] += 1
        
        return results
    except Exception as e:
        print(f"Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return []

# Monitor thread function
def monitor_and_predict():
    global monitoring_active, prediction_queue, last_processed_rows
    
    csv_files = []
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    
    while monitoring_active:
        try:
            # Find latest CSV file from monitor in data folder
            if os.path.exists(data_dir):
                csv_files = [f for f in os.listdir(data_dir) if f.startswith('normal_windows_') and f.endswith('.csv')]
            else:
                csv_files = []
            
            if csv_files:
                latest_csv = max([os.path.join(data_dir, f) for f in csv_files], key=os.path.getctime)
                
                # Read the entire CSV
                df = pd.read_csv(latest_csv)
                current_rows = len(df)
                
                # Process only NEW rows since last check
                if current_rows > last_processed_rows:
                    print(f"[DEBUG] Total rows in CSV: {current_rows}, Last processed: {last_processed_rows}")
                    
                    # Get new rows
                    new_df = df.iloc[last_processed_rows:current_rows]
                    print(f"[DEBUG] Processing {len(new_df)} new samples...")
                    
                    if len(new_df) > 0:
                        # Process in batches of 10 to avoid overwhelming the UI
                        batch_size = 10
                        for i in range(0, len(new_df), batch_size):
                            batch = new_df.iloc[i:i+batch_size]
                            predictions = predict_samples(batch)
                            
                            for pred in predictions:
                                prediction_queue.append(pred)
                                socketio.emit('new_prediction', pred)
                            
                            # Emit stats update after each batch
                            socketio.emit('stats_update', stats)
                            print(f"[DEBUG] Stats - Total: {stats['total_samples']}, Normal: {stats['normal_count']}, Anomaly: {stats['anomaly_count']}")
                    
                    # Update last processed row count
                    last_processed_rows = current_rows
            
            time.sleep(2)  # Check every 2 seconds
            
        except Exception as e:
            print(f"Monitor error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(2)

# Routes
@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/anomaly-detection')
def anomaly_detection():
    """Anomaly detection dashboard"""
    return render_template('anomaly_detection.html')

@app.route('/data-classification')
def data_classification():
    """Data classification scanner"""
    return render_template('data_classification.html')

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    global monitoring_active, traffic_gen_process, monitor_thread, last_processed_rows
    
    if not monitoring_active:
        monitoring_active = True
        
        # Reset stats and tracking
        stats['total_samples'] = 0
        stats['normal_count'] = 0
        stats['anomaly_count'] = 0
        last_processed_rows = 0
        
        # Start traffic generator
        try:
            traffic_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules', 'traffic.py')
            traffic_gen_process = subprocess.Popen(['python', traffic_script], cwd=os.path.dirname(os.path.abspath(__file__)))
            time.sleep(2)  # Give it time to start
            print("[INFO] Traffic generator started")
        except Exception as e:
            print(f"Traffic generator error: {e}")
        
        # Start monitor in background thread
        try:
            monitor_thread = threading.Thread(target=run_monitor, daemon=True)
            monitor_thread.start()
            print("[INFO] Monitor thread started")
        except Exception as e:
            print(f"Monitor start error: {e}")
        
        # Start prediction thread
        pred_thread = threading.Thread(target=monitor_and_predict, daemon=True)
        pred_thread.start()
        print("[INFO] Prediction thread started")
        
        return jsonify({'status': 'started', 'message': 'Monitoring started successfully'})
    
    return jsonify({'status': 'already_running', 'message': 'Monitoring is already active'})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    global monitoring_active, traffic_gen_process
    
    monitoring_active = False
    
    # Stop traffic generator
    if traffic_gen_process:
        try:
            print("[INFO] Stopping traffic generator...")
            traffic_gen_process.terminate()
            
            # Wait a bit for graceful shutdown
            try:
                traffic_gen_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # If it doesn't stop gracefully, force kill it
                print("[INFO] Traffic generator not responding, forcing kill...")
                traffic_gen_process.kill()
            
            traffic_gen_process = None
            print("[INFO] Traffic generator stopped successfully")
        except Exception as e:
            print(f"[ERROR] Error stopping traffic generator: {e}")
            traffic_gen_process = None
    
    return jsonify({'status': 'stopped', 'message': 'Monitoring stopped'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(stats)

@app.route('/api/recent', methods=['GET'])
def get_recent_predictions():
    return jsonify(list(prediction_queue))

# ========== DATA CLASSIFICATION API ENDPOINTS ==========

@app.route('/api/classify/start', methods=['POST'])
def start_classification():
    global scanning_active, scan_thread, classification_results, classification_stats
    
    if scanning_active:
        return jsonify({'status': 'already_running', 'message': 'Scan is already running'})
    
    data = request.json
    directory = data.get('directory', '').strip()
    
    # Normalize path separators
    directory = os.path.normpath(directory)
    
    print(f"\n[API] Classification scan requested for: {directory}")
    
    if not directory:
        print("[API] ERROR: No directory provided")
        return jsonify({'status': 'error', 'message': 'No directory path provided'})
    
    if not os.path.exists(directory):
        print(f"[API] ERROR: Directory does not exist: {directory}")
        return jsonify({'status': 'error', 'message': f'Directory does not exist: {directory}'})
    
    if not os.path.isdir(directory):
        print(f"[API] ERROR: Path is not a directory: {directory}")
        return jsonify({'status': 'error', 'message': f'Path is not a directory: {directory}'})
    
    # Reset stats and results
    print("[API] Resetting stats and starting scan thread...")
    scanning_active = True
    classification_results = []
    classification_stats = {
        'total_files': 0,
        'sensitive_count': 0,
        'non_sensitive_count': 0
    }
    
    # Start scanning thread
    scan_thread = threading.Thread(target=run_classification_scan, args=(directory,), daemon=True)
    scan_thread.start()
    print("[API] Scan thread started successfully")
    
    return jsonify({'status': 'started', 'message': 'Scan started successfully'})

@app.route('/api/classify/stop', methods=['POST'])
def stop_classification():
    global scanning_active
    scanning_active = False
    return jsonify({'status': 'stopped', 'message': 'Scan stopped'})

@app.route('/api/classify/stats', methods=['GET'])
def get_classification_stats():
    return jsonify(classification_stats)

@app.route('/api/classify/results', methods=['GET'])
def get_classification_results():
    return jsonify(classification_results)

def run_classification_scan(directory):
    """Run classification scan in background thread"""
    global scanning_active, classification_results, classification_stats
    
    try:
        print(f"\n[CLASSIFICATION] Starting scan of directory: {directory}")
        
        # Emit loading message
        socketio.emit('scan_progress', {
            'current': 0,
            'total': 0,
            'percentage': 0,
            'message': 'Loading RoBERTa model... (this may take 30-60 seconds on first run)'
        })
        
        # Import classifier
        print("[CLASSIFICATION] Importing classifier module...")
        from modules.data_classifier import get_classifier
        
        # Get classifier instance (this will load the model - takes time!)
        print("[CLASSIFICATION] Initializing classifier (loading RoBERTa model)...")
        classifier = get_classifier()
        print("[CLASSIFICATION] Classifier ready!")
        
        # Define allowed extensions
        allowed_extensions = {'.txt', '.docx', '.pdf', '.csv', '.xlsx', '.xls'}
        
        # Get all files
        print(f"[CLASSIFICATION] Scanning directory for files...")
        directory_path = Path(directory)
        
        if not directory_path.exists():
            print(f"[CLASSIFICATION] ERROR: Directory does not exist: {directory}")
            socketio.emit('scan_error', {'error': f'Directory does not exist: {directory}'})
            scanning_active = False
            return
        
        all_files = []
        for ext in allowed_extensions:
            all_files.extend(directory_path.glob(f'*{ext}'))
        
        total_files = len(all_files)
        print(f"[CLASSIFICATION] Found {total_files} files to process")
        
        if total_files == 0:
            print(f"[CLASSIFICATION] No supported files found in directory")
            socketio.emit('scan_complete', {
                'total': 0,
                'sensitive': 0,
                'non_sensitive': 0,
                'message': 'No supported files found'
            })
            scanning_active = False
            return
        
        # Emit initial progress
        socketio.emit('scan_progress', {
            'current': 0,
            'total': total_files,
            'percentage': 0,
            'message': f'Starting scan of {total_files} files...'
        })
        
        # Process each file
        for idx, file_path in enumerate(all_files):
            if not scanning_active:
                print("[CLASSIFICATION] Scan stopped by user")
                break
            
            try:
                print(f"[CLASSIFICATION] Processing file {idx + 1}/{total_files}: {file_path.name}")
                
                # Wrap classification in try-except to prevent any single file from crashing the scan
                try:
                    # Classify file
                    result = classifier.classify_file(file_path)
                    
                    # Update stats
                    classification_stats['total_files'] += 1
                    if result['classification'] == 'Sensitive':
                        classification_stats['sensitive_count'] += 1
                    else:
                        classification_stats['non_sensitive_count'] += 1
                    
                    # Add to results
                    classification_results.append(result)
                    
                    # Emit result
                    socketio.emit('classification_result', result)
                    # Small delay to ensure Socket.IO broadcasts the message
                    time.sleep(0.05)
                    
                    print(f"[CLASSIFICATION] ✓ {file_path.name}: {result['classification']} ({result['confidence']:.1f}%)")
                    
                except Exception as file_error:
                    # Handle errors for individual files without crashing
                    print(f"[CLASSIFICATION] ✗ Error classifying {file_path.name}: {file_error}")
                    
                    # Create error result
                    error_result = {
                        'filename': file_path.name,
                        'path': str(file_path),
                        'classification': 'Error',
                        'confidence': 0.0,
                        'file_size': 0,
                        'file_type': file_path.suffix,
                        'error': str(file_error)
                    }
                    
                    classification_results.append(error_result)
                    socketio.emit('classification_result', error_result)
                    time.sleep(0.05)
                
                # Emit progress regardless of success/failure
                socketio.emit('scan_progress', {
                    'current': idx + 1,
                    'total': total_files,
                    'percentage': ((idx + 1) / total_files) * 100,
                    'message': f'Processing {idx + 1}/{total_files} files...'
                })
                time.sleep(0.02)  # Small delay for progress update
                
            except Exception as e:
                print(f"[CLASSIFICATION] Unexpected error on file {file_path}: {e}")
                import traceback
                traceback.print_exc()
                # Continue to next file
                continue
        
        # Emit completion
        print(f"[CLASSIFICATION] Scan complete! Processed {classification_stats['total_files']} files")
        socketio.emit('scan_complete', {
            'total': classification_stats['total_files'],
            'sensitive': classification_stats['sensitive_count'],
            'non_sensitive': classification_stats['non_sensitive_count']
        })
        
        scanning_active = False
        
    except Exception as e:
        print(f"[CLASSIFICATION] FATAL ERROR in scan: {e}")
        import traceback
        traceback.print_exc()
        scanning_active = False
        socketio.emit('scan_error', {'error': str(e)})

# ========== PHISHING DETECTION ROUTES ==========

@app.route('/phishing-detection')
def phishing_detection():
    """Phishing detection dashboard"""
    return render_template('phishing_detection.html')

# Phishing helper functions
def extract_and_classify_urls(subject, body):
    """Extract URLs from email and classify them as Safe or Potentially Phishing"""
    if not PHISHING_AVAILABLE:
        return []
    try:
        soup = BeautifulSoup(body or '', 'html.parser')
        plain_text_body = soup.get_text(separator=' ', strip=True)
        text = f"{subject or ''} {plain_text_body}"
        
        url_pattern = re.compile(
            r'(https?://[\w\.-]+\.\w+[\w\.:/?=&%-]*|www\.[\w\.-]+\.\w+[\w\.:/?=&%-]*)',
            re.IGNORECASE
        )
        urls = url_pattern.findall(text)
        url_list = []
        
        for url in urls:
            if url.lower().startswith('www.'):
                normalized_url = 'http://' + url
            else:
                normalized_url = url
            if normalized_url not in url_list:
                url_list.append(normalized_url)
        
        url_info = []
        for url in url_list:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                if not hostname:
                    continue
                hostname = hostname.lower()
                ext = tldextract.extract(hostname)
                normalized_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname
                
                if normalized_domain in trusted_set:
                    status = "Safe"
                else:
                    status = "Potentially Phishing"
                
                url_info.append({
                    "url": url,
                    "domain": normalized_domain,
                    "status": status
                })
            except Exception:
                continue
        
        return url_info
    except Exception as e:
        logger.error(f"Error extracting URLs: {e}")
        return []

def scan_attachment_with_yara(attachment_data, filename):
    """Scan attachment with YARA rules"""
    if not PHISHING_AVAILABLE or yara_rules is None:
        return {'status': 'skipped', 'message': 'YARA scanning not available'}
    
    try:
        temp_dir = app.config['TEMP_DIR']
        os.makedirs(temp_dir, exist_ok=True)
        temp_file_path = os.path.join(temp_dir, f"temp_{filename}")
        
        with open(temp_file_path, 'wb') as f:
            f.write(attachment_data)
        
        matches = yara_rules.match(temp_file_path)
        os.remove(temp_file_path)
        
        if matches:
            match_details = [f"{match.rule}" for match in matches]
            return {
                'status': 'unsafe',
                'message': f"Malicious patterns detected: {', '.join(match_details)}",
                'details': match_details
            }
        else:
            return {
                'status': 'safe',
                'message': "No malicious patterns detected"
            }
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def is_trusted_email_or_domain(email):
    """Check if email or domain is in trusted set"""
    if not email or not PHISHING_AVAILABLE:
        return False
    
    email = email.strip().lower()
    
    if email in trusted_set:
        return True
    
    match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email)
    if not match:
        return False
    
    domain_raw = match.group(1).lower()
    ext = tldextract.extract(domain_raw)
    normalized_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    
    if normalized_domain in PUBLIC_EMAIL_PROVIDERS:
        return False
    
    return normalized_domain in trusted_set

def extract_domain(sender):
    """Extract domain from sender email"""
    if not isinstance(sender, str):
        return ""
    sender = sender.strip()
    domain_match = re.search(r'@([\w\.-]+\.\w+)', sender)
    if domain_match:
        return domain_match.group(1).lower()
    return ""

def classify_email(email_id, sender_email, subject, content, attachments=None):
    """Classify email using multi-layered approach"""
    if not PHISHING_AVAILABLE:
        return "Unknown", 0.0, [], True, {}
    
    try:
        SAFE_THRESHOLD = 0.90
        PHISHING_THRESHOLD = 0.35
        
        # Check whitelist
        if is_trusted_email_or_domain(sender_email):
            return "Safe", 100.0, [], False, {}
        
        # Language detection
        text_for_language = f"{subject or ''} {content or ''}".strip()
        if not text_for_language:
            return "Unknown", 0.0, [], True, {}
        
        try:
            detected_lang = detect(text_for_language)
            if detected_lang != 'en':
                return "Unknown", 50.0, [], True, {}
        except:
            pass
        
        # Initialize factors
        factors = {
            'ai_model_prediction': 0.0,
            'url_analysis': 0.0,
            'attachment_analysis': 0.0,
            'content_analysis': 0.0,
            'sender_trust': 0.0
        }
        
        # AI body classifier
        try:
            label, conf, probs = predict_body_label(text_for_language)
            if isinstance(probs, dict) and 'Phishing' in probs:
                phish_prob = float(probs['Phishing'])
            else:
                phish_prob = float(conf) if label.lower() == 'phishing' else float(1.0 - conf)
            factors['ai_model_prediction'] = max(0.0, min(1.0, phish_prob))
        except Exception as e:
            logger.error(f"Body classifier error: {e}")
        
        # URL analysis
        urls = extract_and_classify_urls(subject, content)
        if any(u['status'] == 'Potentially Phishing' for u in urls):
            factors['url_analysis'] = 0.7
        
        # Attachment analysis
        if attachments:
            for att in attachments:
                if len(att) >= 2:
                    yara_result = scan_attachment_with_yara(att[1], att[0])
                    if yara_result.get('status') == 'unsafe':
                        factors['attachment_analysis'] = 1.0
                        break
        
        # Content heuristics
        content_lower = (content or '').lower()
        suspicious_keywords = ['urgent', 'verify', 'security alert', 'password', 'click here', 'suspended', 'confirm']
        if any(kw in content_lower for kw in suspicious_keywords):
            factors['content_analysis'] = 0.4
        
        # Sender trust
        suspicious_tlds = ['.xyz', '.biz', '.info', '.top', '.loan', '.click']
        normalized_domain = extract_domain(sender_email)
        if any(normalized_domain.endswith(tld) for tld in suspicious_tlds):
            factors['sender_trust'] = 0.5
        
        # Weighted score
        weights = {
            'ai_model_prediction': 0.40,
            'url_analysis': 0.25,
            'attachment_analysis': 0.15,
            'content_analysis': 0.10,
            'sender_trust': 0.10
        }
        
        weighted_score = sum(factors.get(k, 0.0) * w for k, w in weights.items())
        model_confidence = max(0.0, min(1.0, weighted_score))
        
        # Apply thresholds
        needs_review = False
        if model_confidence >= SAFE_THRESHOLD:
            category = "Safe"
        elif model_confidence >= PHISHING_THRESHOLD:
            category = "Phishing"
        else:
            category = "Safe"
            needs_review = True
        
        confidence = round(model_confidence * 100, 2)
        
        # Build explanation
        mapping = {
            'ai_model_prediction': 'AI Body Analysis',
            'url_analysis': 'URL Analysis',
            'attachment_analysis': 'Attachment Analysis',
            'content_analysis': 'Content Analysis',
            'sender_trust': 'Sender Trust'
        }
        explanation = [(mapping[k], v) for k, v in factors.items() if k in mapping and v > 0]
        
        return category, confidence, explanation, needs_review, factors
        
    except Exception as e:
        logger.error(f"Classification error: {e}")
        return "Unknown", 0.0, [], True, {}

@app.route('/api/phishing/analyze', methods=['POST'])
def analyze_email_manual():
    """Analyze email content manually"""
    if not PHISHING_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'Phishing detection not available'})
    
    try:
        data = request.json
        subject = data.get('subject', '')
        sender = data.get('sender', '')
        body = data.get('body', '')
        
        if not body.strip():
            return jsonify({'status': 'error', 'message': 'Email body is required'})
        
        category, confidence, explanation, needs_review, factors = classify_email(
            'manual', sender, subject, body
        )
        
        urls = extract_and_classify_urls(subject, body)
        
        return jsonify({
            'status': 'success',
            'result': {
                'category': category,
                'confidence': confidence,
                'explanation': explanation,
                'needs_review': needs_review,
                'factors': factors,
                'urls': urls
            }
        })
    except Exception as e:
        logger.error(f"Manual analysis error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/phishing/set-email-count')
def set_phishing_email_count():
    """Set email count and redirect to OAuth"""
    count = request.args.get('count', 10, type=int)
    provider = request.args.get('provider', 'gmail')
    session['phishing_email_count'] = count
    
    if provider == 'gmail':
        return redirect(url_for('phishing_authorize_gmail'))
    else:
        return redirect(url_for('phishing_authorize_outlook'))

@app.route('/phishing/authorize_gmail')
def phishing_authorize_gmail():
    """Redirect to Gmail OAuth"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Gmail API credentials not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        # Use the redirect URI from environment variable to match Google Cloud Console config
        redirect_uri = GOOGLE_REDIRECT_URI
        flow = Flow.from_client_config(
            get_google_client_config(),
            scopes=GMAIL_SCOPES,
            redirect_uri=redirect_uri
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"Gmail OAuth error: {e}")
        flash(f'Error initiating Gmail authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/callback')
@app.route('/phishing/callback')
def phishing_gmail_callback():
    """Handle Gmail OAuth callback"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        num_emails = session.get('phishing_email_count', 10)
        
        # Use the redirect URI from environment variable to match Google Cloud Console config
        redirect_uri = GOOGLE_REDIRECT_URI
        flow = Flow.from_client_config(
            get_google_client_config(),
            scopes=GMAIL_SCOPES,
            state=session.get('oauth_state'),
            redirect_uri=redirect_uri
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        service = build_gmail_service(credentials)
        
        # Get user email
        try:
            profile = service.users().getProfile(userId='me').execute()
            user_email = profile.get('emailAddress', 'unknown_user')
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'gmail'
            logger.info(f"Gmail user authenticated: {user_email}")
        except Exception as e:
            logger.error(f"Error fetching user email: {e}")
            user_email = 'unknown_user'
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'gmail'
        
        # Fetch and process emails
        flash(f'Successfully connected! Fetching {num_emails} emails...', 'success')
        fetch_and_process_gmail_emails(service, user_email, num_emails)
        
        return redirect(url_for('phishing_dashboard'))
    except Exception as e:
        logger.error(f"Gmail callback error: {e}")
        flash(f'Error during Gmail authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/phishing/authorize_outlook')
def phishing_authorize_outlook():
    """Redirect to Outlook OAuth"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    if not OUTLOOK_CLIENT_ID or not OUTLOOK_CLIENT_SECRET:
        flash('Outlook API credentials not configured. Please set OUTLOOK_CLIENT_ID and OUTLOOK_CLIENT_SECRET environment variables.', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
        params = {
            'client_id': OUTLOOK_CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': OUTLOOK_REDIRECT_URI,
            'response_mode': 'query',
            'scope': ' '.join(OUTLOOK_SCOPES),
            'state': os.urandom(16).hex()
        }
        session['outlook_state'] = params['state']
        return redirect(auth_url + '&'.join([f"{k}={v}" for k, v in params.items()]))
    except Exception as e:
        logger.error(f"Outlook OAuth error: {e}")
        flash(f'Error initiating Outlook authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/callback_outlook')
@app.route('/phishing/callback_outlook')
def phishing_outlook_callback():
    """Handle Outlook OAuth callback"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        code = request.args.get('code')
        if not code:
            flash('Authorization failed - no code received', 'error')
            return redirect(url_for('phishing_detection'))
        
        num_emails = session.get('phishing_email_count', 10)
        
        # Exchange code for token
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': OUTLOOK_REDIRECT_URI,
            'client_id': OUTLOOK_CLIENT_ID,
            'client_secret': OUTLOOK_CLIENT_SECRET
        }
        
        token_response = http_requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            data=data
        )
        
        if token_response.status_code != 200:
            error_data = token_response.json()
            flash(f'Token error: {error_data.get("error_description", "Unknown error")}', 'error')
            return redirect(url_for('phishing_detection'))
        
        access_token = token_response.json().get('access_token')
        
        # Get user info
        headers = {'Authorization': f'Bearer {access_token}'}
        user_response = http_requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
        if user_response.status_code == 200:
            user_email = user_response.json().get('userPrincipalName', 'unknown_user')
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'outlook'
            logger.info(f"Outlook user authenticated: {user_email}")
        else:
            user_email = 'unknown_user'
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'outlook'
        
        # Fetch and process emails
        flash(f'Successfully connected! Fetching {num_emails} emails...', 'success')
        fetch_and_process_outlook_emails(access_token, user_email, num_emails)
        
        return redirect(url_for('phishing_dashboard'))
    except Exception as e:
        logger.error(f"Outlook callback error: {e}")
        flash(f'Error during Outlook authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/phishing/dashboard')
def phishing_dashboard():
    """Display phishing detection dashboard with analyzed emails"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        # Get emails for this specific user
        cursor.execute('''
            SELECT * FROM Email 
            WHERE user_email = ?
            ORDER BY created_at DESC
        ''', (user_email,))
        emails = [dict(row) for row in cursor.fetchall()]
        
        # Get stats for this user
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE user_email = ?", (user_email,))
        total = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE category = 'Safe' AND user_email = ?", (user_email,))
        safe = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE category = 'Phishing' AND user_email = ?", (user_email,))
        phishing = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE needs_review = 1 AND user_email = ?", (user_email,))
        review = cursor.fetchone()['count']
        
        conn.close()
        
        return render_template('phishing_dashboard.html',
                              emails=emails,
                              stats={'total': total, 'safe': safe, 'phishing': phishing, 'review': review},
                              user_email=user_email,
                              provider=provider)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/api/phishing/stats')
def get_phishing_stats():
    """Get phishing detection statistics"""
    try:
        conn = sqlite3.connect(app.config['PHISHING_DB'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as total FROM Email')
        total = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as safe FROM Email WHERE category = 'Safe'")
        safe = cursor.fetchone()['safe']
        
        cursor.execute("SELECT COUNT(*) as phishing FROM Email WHERE category = 'Phishing'")
        phishing = cursor.fetchone()['phishing']
        
        cursor.execute("SELECT COUNT(*) as review FROM Email WHERE needs_review = 1")
        review = cursor.fetchone()['review']
        
        conn.close()
        
        return jsonify({
            'total': total,
            'safe': safe,
            'phishing': phishing,
            'needs_review': review
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/phishing/email/<int:email_id>')
def phishing_email_details(email_id):
    """View email details"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        # Get email for this user
        cursor.execute('SELECT * FROM Email WHERE id = ? AND user_email = ?', (email_id, user_email))
        email_row = cursor.fetchone()
        
        if not email_row:
            flash('Email not found!', 'error')
            return redirect(url_for('phishing_detection'))
        
        email = dict(email_row)
        
        # Parse JSON fields
        try:
            email['explanation'] = json.loads(email['explanation']) if email.get('explanation') else []
            email['features'] = json.loads(email['features']) if email.get('features') else {}
            email['urls'] = json.loads(email['urls']) if email.get('urls') else []
        except:
            email['explanation'] = []
            email['features'] = {}
            email['urls'] = []
        
        # Get attachments
        cursor.execute('SELECT * FROM Attachment WHERE email_id = ?', (email_id,))
        attachments = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return render_template('email_details.html',
                              email=email,
                              attachments=attachments,
                              modified_body=email.get('body', ''),
                              provider=provider)
    except Exception as e:
        logger.error(f"Error loading email details: {e}")
        flash('Error loading email details', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/phishing/feedback/<int:email_id>', methods=['POST'])
def submit_phishing_feedback(email_id):
    """Submit feedback for email classification - stores in unified feedback database"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        correct_category = request.form.get('correct_category')
        feedback_reason = request.form.get('feedback_reason', '')
        
        if correct_category not in ['Safe', 'Phishing']:
            flash('Invalid category selected', 'error')
            return redirect(url_for('phishing_email_details', email_id=email_id))
        
        # Get email info from phishing database
        user_conn = get_phishing_db_connection()
        cursor = user_conn.cursor()
        cursor.execute('SELECT * FROM Email WHERE id = ? AND user_email = ?', (email_id, user_email))
        email_row = cursor.fetchone()
        
        if not email_row:
            flash('Email not found', 'error')
            return redirect(url_for('phishing_dashboard'))
        
        email = dict(email_row)
        original_category = email.get('category', 'Unknown')
        
        # Store feedback in unified feedback database
        feedback_conn = sqlite3.connect(FEEDBACK_DB_PATH)
        feedback_conn.execute('''
            INSERT INTO Feedback (email_id, user_email, provider, original_category, 
                                 corrected_category, feedback_reason, email_subject, 
                                 email_sender, email_body_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            email_id,
            user_email,
            provider,
            original_category,
            correct_category,
            feedback_reason,
            email.get('subject', ''),
            email.get('sender', ''),
            email.get('body', '')[:500] if email.get('body') else ''
        ))
        feedback_conn.commit()
        feedback_conn.close()
        
        # Update the email category in user-specific database
        user_conn.execute('''
            UPDATE Email SET category = ? WHERE id = ?
        ''', (correct_category, email_id))
        user_conn.commit()
        user_conn.close()
        
        flash('Feedback submitted successfully! Thank you for helping improve our detection.', 'success')
        return redirect(url_for('phishing_email_details', email_id=email_id))
    except Exception as e:
        logger.error(f"Error submitting feedback: {e}")
        flash('Error submitting feedback', 'error')
        return redirect(url_for('phishing_email_details', email_id=email_id))

@app.route('/phishing/attachment/<int:attachment_id>/download')
def download_attachment(attachment_id):
    """Download an email attachment"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Attachment WHERE id = ?', (attachment_id,))
        attachment = cursor.fetchone()
        conn.close()
        
        if not attachment:
            flash('Attachment not found', 'error')
            return redirect(url_for('phishing_dashboard'))
        
        # Create file-like object from binary data
        file_data = io.BytesIO(attachment['data'])
        
        # Determine mimetype
        content_type = attachment['content_type'] or 'application/octet-stream'
        
        return send_file(
            file_data,
            mimetype=content_type,
            as_attachment=True,
            download_name=attachment['filename']
        )
    except Exception as e:
        logger.error(f"Error downloading attachment: {e}")
        flash('Error downloading attachment', 'error')
        return redirect(url_for('phishing_dashboard'))

@app.route('/phishing/attachment/<int:attachment_id>/scan')
def scan_attachment(attachment_id):
    """Scan an attachment with YARA rules"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Attachment WHERE id = ?', (attachment_id,))
        attachment = cursor.fetchone()
        
        if not attachment:
            return jsonify({'status': 'error', 'message': 'Attachment not found'})
        
        # Scan with YARA if available
        scan_result = {'status': 'clean', 'matches': []}
        if yara_rules and attachment['data']:
            try:
                matches = yara_rules.match(data=attachment['data'])
                if matches:
                    scan_result = {
                        'status': 'malicious',
                        'matches': [str(m) for m in matches]
                    }
            except Exception as e:
                logger.error(f"YARA scan error: {e}")
        
        # Update database with scan result
        cursor.execute('''
            UPDATE Attachment SET yara_result = ? WHERE id = ?
        ''', (json.dumps(scan_result), attachment_id))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'result': scan_result})
    except Exception as e:
        logger.error(f"Error scanning attachment: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/phishing/emails')
def get_phishing_emails():
    """Get list of analyzed emails"""
    try:
        conn = sqlite3.connect(app.config['PHISHING_DB'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Email ORDER BY created_at DESC LIMIT 100')
        emails = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({'status': 'success', 'emails': emails})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/phishing/feedback')
def get_all_feedback():
    """Get all feedback from unified feedback database"""
    try:
        conn = sqlite3.connect(FEEDBACK_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Feedback ORDER BY created_at DESC')
        feedback_list = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({'status': 'success', 'feedback': feedback_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/phishing/user-databases')
def get_user_databases():
    """Get list of all users from the single phishing database"""
    try:
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        # Get distinct users with their email counts
        cursor.execute('''
            SELECT provider, user_email, COUNT(*) as email_count 
            FROM Email 
            WHERE user_email IS NOT NULL 
            GROUP BY provider, user_email
        ''')
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'provider': row['provider'],
                'user_email': row['user_email'],
                'email_count': row['email_count']
            })
        
        conn.close()
        
        return jsonify({'status': 'success', 'users': users})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Helper function to run monitor
def run_monitor():
    from modules.monitor import NormalCapture
    try:
        capture = NormalCapture(samples=1000000)
        capture.run()
    except Exception as e:
        print(f"Capture error: {e}")

# ========== FILE ENCRYPTION ROUTES ==========
@app.route('/file-encryption')
def file_encryption():
    """File encryption dashboard"""
    return render_template('file_encryption.html')

@app.route('/encryption/encrypt', methods=['POST'])
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
                
                package_data = create_encrypted_package(
                    file_data, 
                    sanitized_name, 
                    self_destruct_seconds,
                    view_only
                )
                
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
                return jsonify({
                    'status': 'error', 
                    'message': f"Error processing {sanitized_name}: {str(e)}"
                }), 500
    
    return jsonify({
        'status': 'success',
        'key': key_display,
        'files': file_details,
        'expires_in': ENCRYPTION_STORAGE_EXPIRY_MINUTES,
        'self_destruct_enabled': self_destruct_seconds > 0,
        'view_only': view_only
    })

@app.route('/encryption/decrypt', methods=['POST'])
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
                return jsonify({
                    'status': 'error', 
                    'message': 'Password required for decryption'
                }), 400
            
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
                
                if original_filename.startswith('encrypted_'):
                    output_name = original_filename[10:]
                else:
                    output_name = original_filename
                
                token = store_encrypted_file(
                    output_name, 
                    file_data, 
                    sanitized_name,
                    self_destruct_seconds=self_destruct_seconds,
                    is_decrypted=True,
                    view_only=view_only
                )
                
                icon = get_encryption_file_icon(output_name)
                viewable, category = is_file_viewable(output_name)
                
                file_details.append({
                    'name': output_name,
                    'original_name': sanitized_name,
                    'size': f"{len(file_data) / 1024:.1f} KB",
                    'token': token,
                    'icon': icon,
                    'view_only': True,
                    'viewable': viewable,
                    'file_type': category,
                    'self_destruct_seconds': self_destruct_seconds
                })
        
        # Calculate display expiry time
        if file_details and file_details[0].get('self_destruct_seconds', 0) > 0:
            expiry_seconds = file_details[0]['self_destruct_seconds']
            if expiry_seconds < 60:
                expires_display = f"{expiry_seconds} seconds (after first view)"
            else:
                expires_display = f"{expiry_seconds // 60} minute(s) (after first view)"
        else:
            expires_display = f"{ENCRYPTION_STORAGE_EXPIRY_MINUTES} minutes"
        
        return jsonify({
            'status': 'success',
            'files': file_details,
            'expires_in': expires_display
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'message': f"Decryption failed: {str(e)}"
        }), 500

@app.route('/encryption/view/<token>')
def view_encrypted_file(token):
    """View file in browser with watermark (view-only mode)"""
    if token not in encryption_file_storage:
        return render_template('encryption_viewer_error.html', message="File not found or has been destroyed")
    
    file_data = encryption_file_storage[token]
    
    if datetime.now() > file_data['expires']:
        del encryption_file_storage[token]
        return render_template('encryption_viewer_error.html', message="File has expired or been destroyed")
    
    # Increment view count
    encryption_file_storage[token]['view_count'] += 1
    
    # Activate self-destruct on first view
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
    mime_type = get_encryption_mime_type(filename)
    
    # Generate watermark text
    watermark_text = f"CONFIDENTIAL • {datetime.now().strftime('%Y-%m-%d %H:%M')} • View Only"
    
    viewable, category = is_file_viewable(filename)
    
    if not viewable:
        return render_template('encryption_viewer_error.html', message="This file type cannot be viewed in browser")
    
    if category == 'images':
        image_base64 = base64.b64encode(data).decode()
        return render_template(
            'encryption_viewer_image.html',
            filename=filename,
            image_data=f"data:{mime_type};base64,{image_base64}",
            watermark=watermark_text
        )
    
    elif category == 'documents' and ext == 'pdf':
        pdf_base64 = base64.b64encode(data).decode()
        return render_template(
            'encryption_viewer_pdf.html',
            filename=filename,
            pdf_data=pdf_base64,
            watermark=watermark_text
        )
    
    elif category in ['text', 'code']:
        try:
            text_content = data.decode('utf-8')
        except:
            text_content = data.decode('latin-1')
        
        return render_template(
            'encryption_viewer_text.html',
            filename=filename,
            content=text_content,
            is_code=(category == 'code'),
            language=ext,
            watermark=watermark_text
        )
    
    return render_template('encryption_viewer_error.html', message="Unable to display file")

@app.route('/encryption/file-content/<token>')
def get_encryption_file_content(token):
    """Get raw file content for embedding (internal use)"""
    if token not in encryption_file_storage:
        return jsonify({'status': 'error'}), 404
    
    file_data = encryption_file_storage[token]
    
    if datetime.now() > file_data['expires']:
        del encryption_file_storage[token]
        return jsonify({'status': 'error'}), 410
    
    mime_type = get_encryption_mime_type(file_data['filename'])
    
    return Response(
        file_data['data'],
        mimetype=mime_type,
        headers={
            'Content-Disposition': 'inline',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'X-Content-Type-Options': 'nosniff'
        }
    )

@app.route('/encryption/download/<token>')
def download_encrypted_file(token):
    """Download a processed file by its token - only for encrypted files"""
    if token not in encryption_file_storage:
        return jsonify({
            'status': 'error', 
            'message': 'File not found or has been destroyed'
        }), 404
    
    file_data = encryption_file_storage[token]
    
    # Block ALL decrypted files from download - they must use view-only
    if file_data.get('is_decrypted', False):
        return jsonify({
            'status': 'error',
            'message': 'Decrypted files can only be viewed, not downloaded'
        }), 403
    
    if datetime.now() > file_data['expires']:
        del encryption_file_storage[token]
        return jsonify({
            'status': 'error', 
            'message': 'File has expired or been destroyed'
        }), 410
    
    encryption_file_storage[token]['download_count'] += 1
    
    return send_file(
        io.BytesIO(file_data['data']),
        download_name=file_data['filename'],
        as_attachment=True
    )

@app.route('/encryption/download-zip', methods=['POST'])
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
    
    return send_file(
        zip_buffer,
        download_name='encrypted_files.zip',
        as_attachment=True,
        mimetype='application/zip'
    )

@app.route('/encryption/generate-qr', methods=['POST'])
def generate_encryption_qr():
    key = request.json.get('key', '')
    
    if not key:
        return jsonify({'status': 'error', 'message': 'No key provided'}), 400
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(key)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return jsonify({
        'status': 'success',
        'qr_code': f"data:image/png;base64,{qr_base64}"
    })

@app.route('/encryption/file-info/<token>')
def get_encryption_file_info(token):
    if token not in encryption_file_storage:
        return jsonify({'status': 'error', 'message': 'File not found'}), 404
    
    file_data = encryption_file_storage[token]
    remaining_time = (file_data['expires'] - datetime.now()).total_seconds()
    
    return jsonify({
        'status': 'success',
        'filename': file_data['filename'],
        'size': file_data['size'],
        'expires_in_seconds': max(0, int(remaining_time)),
        'created': file_data['created'].isoformat(),
        'view_only': file_data.get('view_only', False)
    })


# =============================================================================
# FILE MONITORING ROUTES
# =============================================================================

# Import file monitor module
try:
    from modules.file_monitor import get_file_monitor, WATCHDOG_AVAILABLE
    FILE_MONITOR_AVAILABLE = WATCHDOG_AVAILABLE
except ImportError as e:
    print(f"Warning: File monitoring not available: {e}")
    FILE_MONITOR_AVAILABLE = False

@app.route('/file-monitoring')
def file_monitoring():
    """File monitoring dashboard"""
    return render_template('file_monitoring.html')

@app.route('/api/file-monitor/start', methods=['POST'])
def start_file_monitoring():
    """Start file monitoring."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available. Install watchdog: pip install watchdog'}), 503
    
    monitor = get_file_monitor(socketio)
    result = monitor.start()
    return jsonify(result)

@app.route('/api/file-monitor/stop', methods=['POST'])
def stop_file_monitoring():
    """Stop file monitoring."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    monitor = get_file_monitor(socketio)
    result = monitor.stop()
    return jsonify(result)

@app.route('/api/file-monitor/add-directory', methods=['POST'])
def add_monitor_directory():
    """Add a directory to watch list."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    data = request.json
    directory = data.get('directory', '').strip()
    
    if not directory:
        return jsonify({'status': 'error', 'message': 'No directory provided'})
    
    monitor = get_file_monitor(socketio)
    result = monitor.add_directory(directory)
    return jsonify(result)

@app.route('/api/file-monitor/remove-directory', methods=['POST'])
def remove_monitor_directory():
    """Remove a directory from watch list."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    data = request.json
    directory = data.get('directory', '').strip()
    
    monitor = get_file_monitor(socketio)
    result = monitor.remove_directory(directory)
    return jsonify(result)

@app.route('/api/file-monitor/events', methods=['GET'])
def get_monitor_events():
    """Get recent file events."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'events': []})
    
    limit = request.args.get('limit', 50, type=int)
    monitor = get_file_monitor(socketio)
    events = monitor.get_events(limit)
    return jsonify({'status': 'success', 'events': events})

@app.route('/api/file-monitor/stats', methods=['GET'])
def get_monitor_stats():
    """Get monitoring statistics."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'stats': {}})
    
    monitor = get_file_monitor(socketio)
    stats = monitor.get_stats()
    return jsonify({'status': 'success', 'stats': stats})

@app.route('/api/file-monitor/status', methods=['GET'])
def get_monitor_status():
    """Get monitoring status."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({
            'is_monitoring': False,
            'directories': [],
            'watchdog_available': False
        })
    
    monitor = get_file_monitor(socketio)
    return jsonify(monitor.get_status())

@app.route('/api/file-monitor/filters', methods=['POST'])
def set_monitor_filters():
    """Set event filtering options."""
    if not FILE_MONITOR_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'File monitoring not available'}), 503
    
    data = request.json
    extensions = data.get('extensions')
    categories = data.get('categories')
    exclude_patterns = data.get('exclude_patterns')
    
    monitor = get_file_monitor(socketio)
    monitor.set_filters(extensions, categories, exclude_patterns)
    
    return jsonify({'status': 'success', 'message': 'Filters updated'})


# =============================================================================
# AI CHATBOT ROUTES
# =============================================================================

# Initialize AI agent (lazy loaded)
ai_agent = None

def get_ai_agent():
    """Get or create AI agent instance."""
    global ai_agent
    if ai_agent is None:
        try:
            from agentic import get_agent
            ai_agent = get_agent()
        except Exception as e:
            logger.error(f"Failed to initialize AI agent: {e}")
            return None
    return ai_agent

@app.route('/api/chat', methods=['POST'])
def chat_api():
    """Handle chat messages to AI assistant."""
    agent = get_ai_agent()
    
    if not agent:
        return jsonify({
            'status': 'error',
            'message': 'AI assistant not available. Check GROQ_API_KEY and dependencies.'
        }), 503
    
    data = request.get_json()
    query = data.get('message', '')
    user_id = data.get('user_id', 'default')
    page_context = data.get('page_context', {})
    
    if not query:
        return jsonify({'status': 'error', 'message': 'No message provided'}), 400
    
    try:
        import asyncio
        # Run async chat in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(agent.chat(user_id, query, socketio, page_context))
        loop.close()
        
        return jsonify({
            'status': 'success',
            'response': result.get('response', ''),
            'tools_used': result.get('tools_used', []),
            'processing_time': result.get('processing_time', 0)
        })
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/chat/history', methods=['GET'])
def chat_history():
    """Get conversation history."""
    user_id = request.args.get('user_id', 'default')
    agent = get_ai_agent()
    
    if not agent:
        return jsonify({'history': []})
    
    history = agent.get_history(user_id)
    return jsonify({'history': history})

@app.route('/api/chat/clear', methods=['POST'])
def clear_chat():
    """Clear conversation history."""
    data = request.get_json()
    user_id = data.get('user_id', 'default')
    agent = get_ai_agent()
    
    if agent:
        agent.clear_history(user_id)
    
    return jsonify({'status': 'success'})


# ========================================
# Activity Tracking API
# ========================================

def get_activity_tracker_instance():
    """Get the activity tracker singleton."""
    try:
        from agentic.memory import get_activity_tracker
        return get_activity_tracker()
    except Exception as e:
        logger.warning(f"Could not get activity tracker: {e}")
        return None

@app.route('/api/activity/log', methods=['POST'])
def log_activity():
    """Log a security activity for a user."""
    data = request.get_json()
    user_id = data.get('user_id', 'default')
    activity_type = data.get('activity_type', 'unknown')
    summary = data.get('summary', '')
    details = data.get('details', {})
    
    tracker = get_activity_tracker_instance()
    if tracker:
        tracker.log_activity(user_id, activity_type, summary, details)
        return jsonify({'status': 'success', 'message': 'Activity logged'})
    
    return jsonify({'status': 'error', 'message': 'Activity tracker not available'}), 503

@app.route('/api/activity/summary', methods=['GET'])
def get_activity_summary():
    """Get activity summary for a user."""
    user_id = request.args.get('user_id', 'default')
    
    tracker = get_activity_tracker_instance()
    if tracker:
        summary = tracker.get_activity_summary(user_id)
        return jsonify({'status': 'success', 'summary': summary})
    
    return jsonify({'status': 'error', 'summary': {}}), 503

@app.route('/api/activity/recent', methods=['GET'])
def get_recent_activities():
    """Get recent activities for a user."""
    user_id = request.args.get('user_id', 'default')
    limit = request.args.get('limit', 10, type=int)
    
    tracker = get_activity_tracker_instance()
    if tracker:
        activities = tracker.get_recent_activities(user_id, limit)
        return jsonify({'status': 'success', 'activities': activities})
    
    return jsonify({'status': 'error', 'activities': []}), 503


# ========================================
# Malware Scanner (VirusTotal Integration)
# ========================================

# Initialize malware scanner components
MALWARE_UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads', 'malware')
MALWARE_DB_PATH = os.path.join(os.path.dirname(__file__), 'databases', 'malware_scans.db')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUS_TOTAL_API', '')

# Create upload folder
os.makedirs(MALWARE_UPLOAD_FOLDER, exist_ok=True)

# Initialize malware scanner
malware_scanner = None
try:
    from modules.malware_scanner import VirusTotalScanner
    if VIRUSTOTAL_API_KEY:
        malware_scanner = VirusTotalScanner(VIRUSTOTAL_API_KEY)
        logger.info("VirusTotal Malware Scanner initialized")
    else:
        logger.warning("VIRUS_TOTAL_API environment variable not set - Malware Scanner disabled")
except ImportError as e:
    logger.warning(f"Malware Scanner not available: {e}")


def init_malware_db():
    """Initialize the malware scan results database."""
    conn = sqlite3.connect(MALWARE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target_name TEXT NOT NULL,
            file_hash TEXT,
            file_size INTEGER,
            analysis_id TEXT,
            malicious_count INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            harmless_count INTEGER DEFAULT 0,
            undetected_count INTEGER DEFAULT 0,
            timeout_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            vt_link TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


# Initialize malware database
init_malware_db()


def get_malware_db_connection():
    """Get a connection to the malware scans database."""
    conn = sqlite3.connect(MALWARE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def calculate_threat_level(malicious, suspicious):
    """Calculate threat level based on detection counts."""
    if malicious > 5:
        return 'high'
    elif malicious > 0 or suspicious > 3:
        return 'medium'
    elif suspicious > 0:
        return 'low'
    else:
        return 'safe'


@app.route('/malware-scanner')
def malware_scanner_page():
    """Malware Scanner page."""
    return render_template('malware_scanner.html')


@app.route('/api/malware/status')
def malware_api_status():
    """Check VirusTotal API connection status."""
    if not malware_scanner:
        return jsonify({
            'connected': False,
            'message': 'VirusTotal API not configured',
            'api_configured': bool(VIRUSTOTAL_API_KEY)
        })
    
    is_connected, message = malware_scanner.test_connection()
    return jsonify({
        'connected': is_connected,
        'message': message,
        'api_configured': bool(VIRUSTOTAL_API_KEY)
    })


@app.route('/api/malware/scan/file', methods=['POST'])
def malware_scan_file():
    """Upload and scan a file for malware."""
    if not malware_scanner:
        return jsonify({'success': False, 'error': 'Malware scanner not configured. Set VIRUS_TOTAL_API environment variable.'}), 503
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    from werkzeug.utils import secure_filename
    import uuid
    
    # Create a unique filename to avoid conflicts
    original_filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())[:8]
    filename = f"{unique_id}_{original_filename}"
    
    # Use MALWARE_UPLOAD_FOLDER (should be excluded from Windows Defender for malware testing)
    # This folder must be excluded from antivirus to allow malware file uploads
    os.makedirs(MALWARE_UPLOAD_FOLDER, exist_ok=True)
    file_path = os.path.join(MALWARE_UPLOAD_FOLDER, filename)
    
    try:
        # Read file content into memory first
        file_content = file.read()
        
        # Write using standard Python with explicit binary mode
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        file_size = os.path.getsize(file_path)
        
        # Calculate file hash
        file_hash = malware_scanner.calculate_hash(file_path)
        
        # Insert scan record into database
        conn = get_malware_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_results (scan_type, target_name, file_hash, file_size, vt_link)
            VALUES (?, ?, ?, ?, ?)
        ''', ('file', original_filename, file_hash, file_size, f"https://www.virustotal.com/gui/file/{file_hash}"))
        scan_id = cursor.lastrowid
        conn.commit()
        
        # Check if file already exists in VT database
        success, report = malware_scanner.check_file_report(file_hash)
        
        if success and report.get('found'):
            # File already analyzed
            stats = report.get('stats', {})
            cursor.execute('''
                UPDATE scan_results SET 
                    malicious_count = ?, suspicious_count = ?, harmless_count = ?,
                    undetected_count = ?, timeout_count = ?, status = ?
                WHERE id = ?
            ''', (
                stats.get('malicious', 0), stats.get('suspicious', 0),
                stats.get('harmless', 0), stats.get('undetected', 0),
                stats.get('timeout', 0), 'completed', scan_id
            ))
            conn.commit()
            conn.close()
            
            # Clean up file immediately after getting hash
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
            
            result = {
                'id': scan_id,
                'scan_type': 'file',
                'target_name': original_filename,
                'file_hash': file_hash,
                'file_size': file_size,
                'malicious_count': stats.get('malicious', 0),
                'suspicious_count': stats.get('suspicious', 0),
                'harmless_count': stats.get('harmless', 0),
                'undetected_count': stats.get('undetected', 0),
                'timeout_count': stats.get('timeout', 0),
                'total_engines': sum(stats.values()),
                'status': 'completed',
                'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}",
                'threat_level': calculate_threat_level(stats.get('malicious', 0), stats.get('suspicious', 0))
            }
            return jsonify({'success': True, 'result': result, 'cached': True})
        
        # Upload file for scanning
        success, upload_result = malware_scanner.upload_file(file_path)
        
        # Clean up file after upload attempt
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except:
            pass
        
        if not success:
            cursor.execute('UPDATE scan_results SET status = ?, error_message = ? WHERE id = ?',
                         ('error', upload_result.get('error', 'Upload failed'), scan_id))
            conn.commit()
            conn.close()
            return jsonify({'success': False, 'error': upload_result.get('error')}), 400
        
        cursor.execute('UPDATE scan_results SET analysis_id = ? WHERE id = ?',
                      (upload_result.get('analysis_id'), scan_id))
        conn.commit()
        
        # Wait for analysis to complete
        analysis_success, analysis = malware_scanner.wait_for_analysis(
            upload_result.get('analysis_id'), max_attempts=15, delay=2
        )
        
        if analysis_success:
            stats = analysis.get('stats', {})
            cursor.execute('''
                UPDATE scan_results SET 
                    malicious_count = ?, suspicious_count = ?, harmless_count = ?,
                    undetected_count = ?, timeout_count = ?, status = ?
                WHERE id = ?
            ''', (
                stats.get('malicious', 0), stats.get('suspicious', 0),
                stats.get('harmless', 0), stats.get('undetected', 0),
                stats.get('timeout', 0), 'completed', scan_id
            ))
            conn.commit()
            
            result = {
                'id': scan_id,
                'scan_type': 'file',
                'target_name': original_filename,
                'file_hash': file_hash,
                'file_size': file_size,
                'malicious_count': stats.get('malicious', 0),
                'suspicious_count': stats.get('suspicious', 0),
                'harmless_count': stats.get('harmless', 0),
                'undetected_count': stats.get('undetected', 0),
                'timeout_count': stats.get('timeout', 0),
                'total_engines': sum(stats.values()),
                'status': 'completed',
                'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}",
                'threat_level': calculate_threat_level(stats.get('malicious', 0), stats.get('suspicious', 0))
            }
        else:
            cursor.execute('UPDATE scan_results SET status = ?, error_message = ? WHERE id = ?',
                         ('pending', 'Analysis in progress - check back later', scan_id))
            conn.commit()
            result = {
                'id': scan_id,
                'scan_type': 'file',
                'target_name': original_filename,
                'file_hash': file_hash,
                'file_size': file_size,
                'status': 'pending',
                'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}",
                'threat_level': 'unknown'
            }
        
        conn.close()
        return jsonify({'success': True, 'result': result})
        
    except Exception as e:
        logger.error(f"Malware file scan error: {e}")
        # Clean up file on error
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except:
            pass
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/malware/scan/url', methods=['POST'])
def malware_scan_url():
    """Scan a URL for malicious content."""
    if not malware_scanner:
        return jsonify({'success': False, 'error': 'Malware scanner not configured'}), 503
    
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'success': False, 'error': 'No URL provided'}), 400
    
    url = data['url'].strip()
    
    if not url:
        return jsonify({'success': False, 'error': 'URL cannot be empty'}), 400
    
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # Insert scan record
    conn = get_malware_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_results (scan_type, target_name, vt_link)
        VALUES (?, ?, ?)
    ''', ('url', url, f"https://www.virustotal.com/gui/url/{url_id}"))
    scan_id = cursor.lastrowid
    conn.commit()
    
    try:
        # Submit URL for scanning
        success, result = malware_scanner.scan_url(url)
        
        if not success:
            cursor.execute('UPDATE scan_results SET status = ?, error_message = ? WHERE id = ?',
                         ('error', result.get('error', 'Scan failed'), scan_id))
            conn.commit()
            conn.close()
            return jsonify({'success': False, 'error': result.get('error')}), 400
        
        cursor.execute('UPDATE scan_results SET analysis_id = ? WHERE id = ?',
                      (result.get('analysis_id'), scan_id))
        conn.commit()
        
        # Wait for analysis
        analysis_success, analysis = malware_scanner.wait_for_analysis(
            result.get('analysis_id'), max_attempts=15, delay=2
        )
        
        if analysis_success:
            stats = analysis.get('stats', {})
            cursor.execute('''
                UPDATE scan_results SET 
                    malicious_count = ?, suspicious_count = ?, harmless_count = ?,
                    undetected_count = ?, timeout_count = ?, status = ?
                WHERE id = ?
            ''', (
                stats.get('malicious', 0), stats.get('suspicious', 0),
                stats.get('harmless', 0), stats.get('undetected', 0),
                stats.get('timeout', 0), 'completed', scan_id
            ))
            conn.commit()
            
            scan_result = {
                'id': scan_id,
                'scan_type': 'url',
                'target_name': url,
                'malicious_count': stats.get('malicious', 0),
                'suspicious_count': stats.get('suspicious', 0),
                'harmless_count': stats.get('harmless', 0),
                'undetected_count': stats.get('undetected', 0),
                'timeout_count': stats.get('timeout', 0),
                'total_engines': sum(stats.values()),
                'status': 'completed',
                'vt_link': f"https://www.virustotal.com/gui/url/{url_id}",
                'threat_level': calculate_threat_level(stats.get('malicious', 0), stats.get('suspicious', 0))
            }
        else:
            cursor.execute('UPDATE scan_results SET status = ?, error_message = ? WHERE id = ?',
                         ('pending', 'Analysis in progress', scan_id))
            conn.commit()
            scan_result = {
                'id': scan_id,
                'scan_type': 'url',
                'target_name': url,
                'status': 'pending',
                'vt_link': f"https://www.virustotal.com/gui/url/{url_id}",
                'threat_level': 'unknown'
            }
        
        conn.close()
        return jsonify({'success': True, 'result': scan_result})
        
    except Exception as e:
        logger.error(f"Malware URL scan error: {e}")
        cursor.execute('UPDATE scan_results SET status = ?, error_message = ? WHERE id = ?',
                     ('error', str(e), scan_id))
        conn.commit()
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/malware/history')
def malware_get_history():
    """Get malware scan history."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    scan_type = request.args.get('type', None)
    
    conn = get_malware_db_connection()
    cursor = conn.cursor()
    
    # Build query
    if scan_type:
        cursor.execute('SELECT COUNT(*) FROM scan_results WHERE scan_type = ?', (scan_type,))
    else:
        cursor.execute('SELECT COUNT(*) FROM scan_results')
    
    total = cursor.fetchone()[0]
    total_pages = max(1, (total + per_page - 1) // per_page)
    
    offset = (page - 1) * per_page
    
    if scan_type:
        cursor.execute('''
            SELECT * FROM scan_results WHERE scan_type = ?
            ORDER BY created_at DESC LIMIT ? OFFSET ?
        ''', (scan_type, per_page, offset))
    else:
        cursor.execute('''
            SELECT * FROM scan_results
            ORDER BY created_at DESC LIMIT ? OFFSET ?
        ''', (per_page, offset))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        total_engines = (row['malicious_count'] or 0) + (row['suspicious_count'] or 0) + \
                       (row['harmless_count'] or 0) + (row['undetected_count'] or 0) + (row['timeout_count'] or 0)
        
        results.append({
            'id': row['id'],
            'scan_type': row['scan_type'],
            'target_name': row['target_name'],
            'file_hash': row['file_hash'],
            'file_size': row['file_size'],
            'malicious_count': row['malicious_count'] or 0,
            'suspicious_count': row['suspicious_count'] or 0,
            'harmless_count': row['harmless_count'] or 0,
            'undetected_count': row['undetected_count'] or 0,
            'timeout_count': row['timeout_count'] or 0,
            'total_engines': total_engines,
            'status': row['status'],
            'vt_link': row['vt_link'],
            'created_at': row['created_at'],
            'threat_level': calculate_threat_level(row['malicious_count'] or 0, row['suspicious_count'] or 0)
                          if row['status'] == 'completed' else 'unknown'
        })
    
    return jsonify({
        'success': True,
        'results': results,
        'total': total,
        'pages': total_pages,
        'current_page': page
    })


# SocketIO events

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('initial_data', {
        'stats': stats,
        'recent_predictions': list(prediction_queue),
        'monitoring_active': monitoring_active
    })


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join_chat')
def handle_join_chat(data):
    """Join chat room for real-time updates."""
    from flask_socketio import join_room
    user_id = data.get('user_id', 'default')
    join_room(user_id)
    print(f'User {user_id} joined chat')

@socketio.on('chat_message')
def handle_chat_message(data):
    """Handle chat message via WebSocket."""
    from flask_socketio import emit
    
    agent = get_ai_agent()
    user_id = data.get('user_id', 'default')
    query = data.get('message', '')
    
    if not agent:
        emit('chat_response', {
            'status': 'error',
            'response': 'AI assistant not available. Please check GROQ_API_KEY.'
        }, room=user_id)
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
            'status': 'success',
            'response': result.get('response', ''),
            'tools_used': result.get('tools_used', []),
            'processing_time': result.get('processing_time', 0)
        }, room=user_id)
    except Exception as e:
        logger.error(f"WebSocket chat error: {e}")
        emit('chat_response', {
            'status': 'error',
            'response': f'Error: {str(e)}'
        }, room=user_id)


if __name__ == '__main__':
    print("=" * 60)
    print(" AEGIS DLP - Unified Data Loss Prevention Platform")
    print("=" * 60)
    print()
    print("Server starting on http://localhost:5000")
    print()
    print("Integrated Systems:")
    print("  1. Anomaly Detection (MLP Model)")
    print("  2. Data Classification (RoBERTa Model)")
    print("  3. Phishing Detection (RoBERTa + YARA)")
    print("  4. File Encryption (AES-256 Fernet)")
    print("  5. File Monitoring (Watchdog)")
    print("  6. AI Security Assistant (Groq + ChromaDB)")
    print("  7. Malware Scanner (VirusTotal API)")
    print()
    
    # Pre-load the data classifier to avoid restart issues
    print("Pre-loading Data Classification Model...")
    try:
        from modules.data_classifier import get_classifier
        _ = get_classifier()  # Initialize classifier once
        print("✓ Data Classification Model loaded!")
    except Exception as e:
        print(f"⚠ Warning: Could not pre-load classifier: {e}")
        print("  Classification will load on first scan")
    
    # Pre-load the phishing classifier
    if PHISHING_AVAILABLE:
        print("Pre-loading Phishing Detection Model...")
        try:
            from modules.body_classifier import predict_body_label
            _ = predict_body_label("Test email content")
            print("✓ Phishing Detection Model loaded!")
        except Exception as e:
            print(f"⚠ Warning: Could not pre-load phishing classifier: {e}")
    else:
        print("⚠ Phishing Detection not available (missing dependencies)")
    
    print()
    print("Required Files:")
    print("  Anomaly Detection:")
    print("    - mlp_ids_model.pkl")
    print("    - scaler.pkl")
    print("    - label_encoders.pkl")
    print("    - feature_info.pkl")
    print("  Data Classification:")
    print("    - data_classifier.py")
    print("    - RoBERTa model (configured in data_classifier.py)")
    print("  Phishing Detection:")
    print("    - body_classifier.py")
    print("    - roberta_lora_phishing_detector.pt")
    print("    - top-1m.csv (trusted domains)")
    print("    - awesome-yara/rules/ (YARA rules)")
    print()
    print("=" * 60)
    
    # Run with reloader disabled to prevent crashes during classification
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)

