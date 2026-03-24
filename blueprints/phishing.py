"""
Phishing Detection Routes
===========================
Handles email phishing detection with multi-layered classification:
- AI body classifier (RoBERTa)
- URL analysis against trusted domain list
- YARA attachment scanning
- Content heuristics
- Sender trust analysis

Supports Gmail and Outlook OAuth for email fetching.
"""

from flask import Blueprint, jsonify, request, render_template, redirect, url_for, session, flash, send_file, current_app
import os
import io
import re
import json
import sqlite3
import base64
import logging
import numpy as np
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

phishing_bp = Blueprint('phishing', __name__)

# ---- Optional Dependency Imports ----
PHISHING_AVAILABLE = False
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
    import requests as http_requests
    PHISHING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Some phishing detection dependencies not available: {e}")

# ---- Configuration ----

_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

YARA_RULES_DIR = os.path.join(_base_dir, 'data', 'yara_rules', 'rules')
TEMP_DIR = os.path.join(_base_dir, 'temp')
PHISHING_DB = os.path.join(_base_dir, 'databases', 'emails.db')
FEEDBACK_DB_PATH = os.path.join(_base_dir, 'databases', 'feedback.db')
TRUSTED_CSV_PATH = os.path.join(_base_dir, 'data', 'top-1m.csv')

PUBLIC_EMAIL_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'icloud.com', 'mail.com', 'protonmail.com', 'yandex.com'
}

# Google Gmail API credentials
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5000/phishing/callback')
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Server-side store for PKCE code verifiers (cookie sessions lose them across OAuth redirects)
import threading as _threading
_pkce_store = {}       # {state: (code_verifier, timestamp)}
_pkce_lock = _threading.Lock()

def _pkce_save(state, code_verifier):
    """Store a PKCE code_verifier keyed by OAuth state (server-side)."""
    import time
    with _pkce_lock:
        # Clean up entries older than 10 minutes
        now = time.time()
        expired = [k for k, (_, ts) in _pkce_store.items() if now - ts > 600]
        for k in expired:
            del _pkce_store[k]
        _pkce_store[state] = (code_verifier, now)

def _pkce_pop(state):
    """Retrieve and remove a PKCE code_verifier by OAuth state."""
    with _pkce_lock:
        entry = _pkce_store.pop(state, None)
        return entry[0] if entry else None

# Outlook API credentials
OUTLOOK_CLIENT_ID = os.environ.get('OUTLOOK_CLIENT_ID')
OUTLOOK_CLIENT_SECRET = os.environ.get('OUTLOOK_CLIENT_SECRET')
OUTLOOK_REDIRECT_URI = os.environ.get('OUTLOOK_REDIRECT_URI', 'http://localhost:5000/phishing/callback_outlook')
OUTLOOK_SCOPES = ['https://graph.microsoft.com/Mail.Read']

# ---- Trusted Domains Loading ----
trusted_set = set()
if PHISHING_AVAILABLE:
    try:
        import pandas as pd
        df = pd.read_csv(TRUSTED_CSV_PATH, header=None)
        trusted_set = set(str(x).strip().lower() for x in df[0].dropna()
                         if str(x).strip().lower() not in PUBLIC_EMAIL_PROVIDERS)
        logger.info(f"Loaded {len(trusted_set)} trusted entries from {TRUSTED_CSV_PATH}")
    except Exception as e:
        logger.warning(f"Could not load trusted domains: {e}")

# ---- YARA Rules ----
yara_rules = None

def initialize_yara_rules():
    global yara_rules
    if not PHISHING_AVAILABLE:
        return
    if not os.path.exists(YARA_RULES_DIR):
        logger.warning(f"YARA rules directory not found: {YARA_RULES_DIR}")
        return
    try:
        rule_files = []
        for root, dirs, files in os.walk(YARA_RULES_DIR):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    rule_path = os.path.join(root, file)
                    try:
                        with open(rule_path, 'r') as f:
                            yara.compile(source=f.read())
                        rule_files.append((os.path.splitext(os.path.basename(file))[0], rule_path))
                    except Exception:
                        continue
        if rule_files:
            yara_rules = yara.compile(filepaths={rn: rp for rn, rp in rule_files})
            logger.info(f"YARA rules loaded: {len(rule_files)} rule files")
    except Exception as e:
        logger.warning(f"Error loading YARA rules: {e}")

# ---- Database Initialization ----
def init_phishing_db():
    conn = sqlite3.connect(PHISHING_DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS Email (
        id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT, sender TEXT,
        receiver TEXT, subject TEXT, body TEXT, category TEXT,
        confidence_score REAL, needs_review INTEGER DEFAULT 0,
        explanation TEXT, features TEXT, urls TEXT, provider TEXT,
        user_email TEXT, received_date INTEGER, has_feedback INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS Attachment (
        id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, data BLOB,
        email_id INTEGER, sensitivity TEXT, content_type TEXT, yara_result TEXT,
        FOREIGN KEY (email_id) REFERENCES Email(id))''')
    conn.commit()
    conn.close()

def init_feedback_db():
    conn = sqlite3.connect(FEEDBACK_DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS Feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email_id INTEGER,
        user_email TEXT, provider TEXT, original_category TEXT,
        corrected_category TEXT, feedback_reason TEXT,
        email_subject TEXT, email_sender TEXT, email_body_preview TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def get_phishing_db_connection():
    conn = sqlite3.connect(PHISHING_DB)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize on import
init_feedback_db()
if PHISHING_AVAILABLE:
    init_phishing_db()
    initialize_yara_rules()

# ---- OAuth Helpers ----
def get_google_client_config():
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
    return build('gmail', 'v1', credentials=credentials)

# ---- Content Processing Helpers ----
def clean_preview_text(html_content, max_length=200):
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, 'html.parser')
    for tag in soup.find_all(True):
        tag.unwrap()
    text = soup.get_text(separator=' ', strip=True)
    text = ' '.join(text.split())
    return text[:max_length] + "..." if len(text) > max_length else text

def extract_text_from_pdf(pdf_data):
    text = ''
    reader = PyPDF2.PdfReader(io.BytesIO(pdf_data))
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text += page_text + '\n'
    return text

def extract_text_from_docx(docx_data):
    doc = Document(io.BytesIO(docx_data))
    return "\n".join([para.text for para in doc.paragraphs])

def classify_text_attachment(text):
    try:
        if not text or text.strip() == '':
            return 'non-sensitive'
        try:
            from phishing_document_classifier import classify_text_content
            return classify_text_content(text)
        except Exception:
            return 'non-sensitive'
    except Exception:
        return 'non-sensitive'

# Image classification model
_cached_image_model = None

def _load_image_model():
    global _cached_image_model
    if _cached_image_model is not None:
        return _cached_image_model
    image_model_path = os.path.join(_base_dir, 'image_model.h5')
    if not os.path.exists(image_model_path):
        return None
    try:
        import tensorflow as tf
        import h5py
        import tempfile
        import shutil

        def convert_keras3_config_to_keras2(config):
            if isinstance(config, dict):
                new_config = {}
                for key, value in config.items():
                    if key == 'dtype' and isinstance(value, dict) and value.get('class_name') == 'DTypePolicy':
                        new_config[key] = value.get('config', {}).get('name', 'float32')
                    elif key == 'batch_shape':
                        new_config['batch_input_shape'] = value
                    elif key in ['kernel_initializer', 'bias_initializer', 'kernel_regularizer',
                                 'bias_regularizer', 'activity_regularizer'] and isinstance(value, dict):
                        if 'class_name' in value:
                            new_config[key] = {'class_name': value.get('class_name', ''), 'config': value.get('config', {})}
                        else:
                            new_config[key] = convert_keras3_config_to_keras2(value)
                    else:
                        new_config[key] = convert_keras3_config_to_keras2(value)
                return new_config
            elif isinstance(config, list):
                return [convert_keras3_config_to_keras2(item) for item in config]
            return config

        with tempfile.NamedTemporaryFile(suffix='.h5', delete=False) as tmp_file:
            temp_path = tmp_file.name
        shutil.copy2(image_model_path, temp_path)
        with h5py.File(temp_path, 'r+') as f:
            if 'model_config' in f.attrs:
                model_config_str = f.attrs['model_config']
                if isinstance(model_config_str, bytes):
                    model_config_str = model_config_str.decode('utf-8')
                model_config = json.loads(model_config_str)
                converted_config = convert_keras3_config_to_keras2(model_config)
                f.attrs['model_config'] = json.dumps(converted_config).encode('utf-8')
        _cached_image_model = tf.keras.models.load_model(temp_path, compile=False)
        try:
            os.remove(temp_path)
        except Exception:
            pass
        return _cached_image_model
    except Exception as e:
        logger.error(f"Error loading image model: {e}")
        return None

def classify_image_attachment(image_data):
    try:
        if not PHISHING_AVAILABLE:
            return 'non-sensitive'
        image = Image.open(io.BytesIO(image_data))
        if image.mode == 'RGBA':
            image = image.convert('RGB')
        image = image.resize((150, 150))
        image_array = np.array(image) / 255.0
        image_array = np.expand_dims(image_array, axis=0)
        image_model = _load_image_model()
        if image_model is not None:
            prediction = image_model.predict(image_array, verbose=0)
            return 'sensitive' if prediction[0] > 0.5 else 'non-sensitive'
        return 'non-sensitive'
    except Exception:
        return 'non-sensitive'

# ---- URL & Email Analysis ----
def extract_and_classify_urls(subject, body):
    if not PHISHING_AVAILABLE:
        return []
    try:
        soup = BeautifulSoup(body or '', 'html.parser')
        plain_text_body = soup.get_text(separator=' ', strip=True)
        text = f"{subject or ''} {plain_text_body}"
        url_pattern = re.compile(r'(https?://[\w\.-]+\.\w+[\w\.:/?=&%-]*|www\.[\w\.-]+\.\w+[\w\.:/?=&%-]*)', re.IGNORECASE)
        urls = url_pattern.findall(text)
        url_list = []
        for url in urls:
            normalized_url = 'http://' + url if url.lower().startswith('www.') else url
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
                status = "Safe" if normalized_domain in trusted_set else "Potentially Phishing"
                url_info.append({"url": url, "domain": normalized_domain, "status": status})
            except Exception:
                continue
        return url_info
    except Exception:
        return []

def scan_attachment_with_yara(attachment_data, filename):
    if not PHISHING_AVAILABLE or yara_rules is None:
        return {'status': 'skipped', 'message': 'YARA scanning not available'}
    try:
        os.makedirs(TEMP_DIR, exist_ok=True)
        temp_file_path = os.path.join(TEMP_DIR, f"temp_{filename}")
        with open(temp_file_path, 'wb') as f:
            f.write(attachment_data)
        matches = yara_rules.match(temp_file_path)
        os.remove(temp_file_path)
        if matches:
            match_details = [f"{match.rule}" for match in matches]
            return {'status': 'unsafe', 'message': f"Malicious patterns detected: {', '.join(match_details)}", 'details': match_details}
        return {'status': 'safe', 'message': "No malicious patterns detected"}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def is_trusted_email_or_domain(email):
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
    if not isinstance(sender, str):
        return ""
    domain_match = re.search(r'@([\w\.-]+\.\w+)', sender.strip())
    return domain_match.group(1).lower() if domain_match else ""

# ---- Core Classification ----
def classify_email(email_id, sender_email, subject, content, attachments=None):
    if not PHISHING_AVAILABLE:
        return "Unknown", 0.0, [], True, {}
    try:
        SAFE_THRESHOLD = 0.90
        PHISHING_THRESHOLD = 0.35
        if is_trusted_email_or_domain(sender_email):
            return "Safe", 100.0, [], False, {}
        text_for_language = f"{subject or ''} {content or ''}".strip()
        if not text_for_language:
            return "Unknown", 0.0, [], True, {}
        try:
            detected_lang = detect(text_for_language)
            if detected_lang != 'en':
                return "Unknown", 50.0, [], True, {}
        except Exception:
            pass
        factors = {'ai_model_prediction': 0.0, 'url_analysis': 0.0, 'attachment_analysis': 0.0, 'content_analysis': 0.0, 'sender_trust': 0.0}
        try:
            label, conf, probs = predict_body_label(text_for_language)
            if isinstance(probs, dict) and 'Phishing' in probs:
                phish_prob = float(probs['Phishing'])
            else:
                phish_prob = float(conf) if label.lower() == 'phishing' else float(1.0 - conf)
            factors['ai_model_prediction'] = max(0.0, min(1.0, phish_prob))
        except Exception:
            pass
        urls = extract_and_classify_urls(subject, content)
        if any(u['status'] == 'Potentially Phishing' for u in urls):
            factors['url_analysis'] = 0.7
        if attachments:
            for att in attachments:
                if len(att) >= 2:
                    yara_result = scan_attachment_with_yara(att[1], att[0])
                    if yara_result.get('status') == 'unsafe':
                        factors['attachment_analysis'] = 1.0
                        break
        content_lower = (content or '').lower()
        suspicious_keywords = ['urgent', 'verify', 'security alert', 'password', 'click here', 'suspended', 'confirm']
        if any(kw in content_lower for kw in suspicious_keywords):
            factors['content_analysis'] = 0.4
        suspicious_tlds = ['.xyz', '.biz', '.info', '.top', '.loan', '.click']
        normalized_domain = extract_domain(sender_email)
        if any(normalized_domain.endswith(tld) for tld in suspicious_tlds):
            factors['sender_trust'] = 0.5
        weights = {'ai_model_prediction': 0.40, 'url_analysis': 0.25, 'attachment_analysis': 0.15, 'content_analysis': 0.10, 'sender_trust': 0.10}
        weighted_score = sum(factors.get(k, 0.0) * w for k, w in weights.items())
        model_confidence = max(0.0, min(1.0, weighted_score))
        
        # Single-factor escalation: if ANY factor is extremely high,
        # escalate to Phishing regardless of weighted average.
        # This prevents a low overall weighted score from masking a
        # clear signal in one channel (e.g., YARA match = 1.0).
        SINGLE_FACTOR_THRESHOLD = 0.85
        single_factor_escalation = any(
            v >= SINGLE_FACTOR_THRESHOLD for v in factors.values()
        )
        
        needs_review = False
        if single_factor_escalation:
            # At least one factor is very confident — force Phishing
            category = "Phishing"
            model_confidence = max(model_confidence, max(factors.values()))
        elif model_confidence >= SAFE_THRESHOLD:
            category = "Safe"
        elif model_confidence >= PHISHING_THRESHOLD:
            category = "Phishing"
        else:
            category = "Safe"
            needs_review = True
        confidence = round(model_confidence * 100, 2)
        mapping = {'ai_model_prediction': 'AI Body Analysis', 'url_analysis': 'URL Analysis', 'attachment_analysis': 'Attachment Analysis', 'content_analysis': 'Content Analysis', 'sender_trust': 'Sender Trust'}
        explanation = [(mapping[k], v) for k, v in factors.items() if k in mapping and v > 0]
        return category, confidence, explanation, needs_review, factors
    except Exception:
        return "Unknown", 0.0, [], True, {}

# ---- Email Processing ----
def process_gmail_message(service, message_id):
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
            if part.get('filename'):
                if part['body'].get('attachmentId'):
                    att_id = part['body']['attachmentId']
                    att = service.users().messages().attachments().get(userId='me', messageId=message_id, id=att_id).execute()
                    data = base64.urlsafe_b64decode(att['data'])
                    file_type = part.get('mimeType')
                    sensitivity = 'non-sensitive'
                    if file_type and file_type.startswith('image/'):
                        sensitivity = classify_image_attachment(data)
                    elif file_type == 'application/pdf':
                        sensitivity = classify_text_attachment(extract_text_from_pdf(data))
                    elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                        sensitivity = classify_text_attachment(extract_text_from_docx(data))
                    elif file_type == 'text/plain':
                        sensitivity = classify_text_attachment(data.decode('utf-8', errors='ignore'))
                    attachments.append({'filename': part['filename'], 'data': data, 'sensitivity': sensitivity, 'content_type': file_type})
        if not (html_content or plain_content) and msg['payload'].get('body', {}).get('data'):
            plain_content = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8', errors='ignore')
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
            'message_id': message_id, 'sender': sender, 'receiver': receiver,
            'subject': subject, 'body': body, 'category': category,
            'confidence_score': confidence, 'explanation': explanation,
            'needs_review': needs_review, 'features': features,
            'attachments': attachments, 'urls': urls
        }
    except Exception as e:
        logger.error(f"Error processing Gmail message {message_id}: {e}")
        return None

def process_outlook_email(email):
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
        body = ' '.join(soup.get_text(separator=' ', strip=True).split())
        if body.startswith(subject):
            body = body[len(subject):].strip()
        urls = extract_and_classify_urls(subject, body)
        attachments = []
        if 'attachments' in email:
            for attachment in email['attachments']:
                att_data = base64.b64decode(attachment.get('contentBytes', ''))
                content_type = attachment.get('contentType', '')
                sensitivity = 'non-sensitive'
                if content_type.startswith('image/'):
                    sensitivity = classify_image_attachment(att_data)
                elif content_type == 'application/pdf':
                    sensitivity = classify_text_attachment(extract_text_from_pdf(att_data))
                elif content_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                    sensitivity = classify_text_attachment(extract_text_from_docx(att_data))
                elif content_type == 'text/plain':
                    sensitivity = classify_text_attachment(att_data.decode('utf-8', errors='ignore'))
                attachments.append({'filename': attachment.get('name', 'unknown'), 'data': att_data, 'sensitivity': sensitivity, 'content_type': content_type})
        category, confidence, explanation, needs_review, features = classify_email(email['id'], sender, subject, body, attachments)
        return {
            'message_id': email['id'], 'sender': sender, 'receiver': receiver,
            'subject': subject, 'body': body, 'category': category,
            'confidence_score': confidence, 'explanation': explanation,
            'needs_review': needs_review, 'features': features,
            'attachments': attachments, 'urls': urls
        }
    except Exception as e:
        logger.error(f"Error processing Outlook email: {e}")
        return None

def _get_event_helpers():
    from blueprints.shared_state import app_state
    if app_state.EVENT_BUS_AVAILABLE and app_state.event_bus:
        try:
            from modules.event_bus.events import EventType, Severity
            from modules.event_bus import phishing_event
            return app_state.event_bus, EventType, Severity, phishing_event
        except Exception:
            pass
    return None, None, None, None

def fetch_and_process_gmail_emails(service, user_email, num_emails):
    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=num_emails).execute()
        messages = results.get('messages', [])
        conn = get_phishing_db_connection()
        for msg in messages:
            try:
                message_id = msg['id']
                cursor = conn.execute('SELECT id FROM Email WHERE message_id = ? AND user_email = ?', (message_id, user_email))
                if cursor.fetchone():
                    continue
                msg_full = service.users().messages().get(userId='me', id=message_id, format='full').execute()
                received_date = int(msg_full.get('internalDate', 0))
                email_data = process_gmail_message(service, message_id)
                if email_data is None:
                    continue
                conn.execute('''INSERT INTO Email (message_id, sender, receiver, subject, body, category,
                    confidence_score, needs_review, explanation, features, urls, provider, user_email, received_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (email_data['message_id'], email_data['sender'], email_data['receiver'],
                     email_data['subject'], email_data['body'], email_data['category'],
                     email_data['confidence_score'], 1 if email_data['needs_review'] else 0,
                     json.dumps(email_data.get('explanation', [])),
                     json.dumps(email_data.get('features', {})),
                     json.dumps(email_data.get('urls', [])), 'gmail', user_email, received_date))
                email_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                for att in email_data.get('attachments', []):
                    conn.execute('INSERT INTO Attachment (filename, data, email_id, sensitivity, content_type) VALUES (?, ?, ?, ?, ?)',
                                 (att['filename'], att['data'], email_id, att['sensitivity'], att['content_type']))
                conn.commit()
                bus, EventType, Severity, phishing_event = _get_event_helpers()
                if bus:
                    try:
                        category = email_data.get('category', 'Unknown')
                        is_phishing = category.lower() in ('phishing', 'suspicious')
                        conf = email_data.get('confidence_score', 0)
                        sev = Severity.CRITICAL if (is_phishing and conf > 90) else (Severity.HIGH if is_phishing else Severity.INFO)
                        evt = phishing_event(event_type=EventType.PHISH_DETECTED if is_phishing else EventType.PHISH_SAFE,
                            severity=sev, email_id=message_id, subject=email_data.get('subject', '')[:100],
                            sender=email_data.get('sender', 'unknown')[:100],
                            confidence=conf if isinstance(conf, (int, float)) else 0.0, provider='gmail', classification=category)
                        bus.publish(evt)
                    except Exception:
                        pass
            except Exception as e:
                logger.error(f"Error processing email {msg.get('id')}: {e}")
        conn.close()
    except Exception as e:
        logger.error(f"Error fetching Gmail emails: {e}")

def fetch_and_process_outlook_emails(access_token, user_email, num_emails):
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = http_requests.get('https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages',
            headers=headers, params={'$top': num_emails, '$orderby': 'receivedDateTime desc', '$expand': 'attachments'})
        if response.status_code != 200:
            return
        messages = response.json().get('value', [])
        conn = get_phishing_db_connection()
        for email in messages:
            try:
                message_id = email['id']
                cursor = conn.execute('SELECT id FROM Email WHERE message_id = ? AND user_email = ?', (message_id, user_email))
                if cursor.fetchone():
                    continue
                received_date_str = email.get('receivedDateTime', '1970-01-01T00:00:00Z')
                try:
                    received_date = int(datetime.strptime(received_date_str.replace('Z', ''), '%Y-%m-%dT%H:%M:%S').timestamp() * 1000)
                except Exception:
                    received_date = 0
                email_data = process_outlook_email(email)
                if email_data is None:
                    continue
                conn.execute('''INSERT OR IGNORE INTO Email (message_id, sender, receiver, subject, body, category,
                    confidence_score, needs_review, explanation, features, urls, provider, user_email, received_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (email_data['message_id'], email_data['sender'], email_data['receiver'],
                     email_data['subject'], email_data['body'], email_data['category'],
                     email_data['confidence_score'], 1 if email_data['needs_review'] else 0,
                     json.dumps(email_data.get('explanation', [])),
                     json.dumps(email_data.get('features', {})),
                     json.dumps(email_data.get('urls', [])), 'outlook', user_email, received_date))
                email_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                for att in email_data.get('attachments', []):
                    conn.execute('INSERT INTO Attachment (filename, data, email_id, sensitivity, content_type) VALUES (?, ?, ?, ?, ?)',
                                 (att['filename'], att['data'], email_id, att['sensitivity'], att['content_type']))
                conn.commit()
                bus, EventType, Severity, phishing_event = _get_event_helpers()
                if bus:
                    try:
                        category = email_data.get('category', 'Unknown')
                        is_phishing = category.lower() in ('phishing', 'suspicious')
                        conf = email_data.get('confidence_score', 0)
                        sev = Severity.CRITICAL if (is_phishing and conf > 90) else (Severity.HIGH if is_phishing else Severity.INFO)
                        evt = phishing_event(event_type=EventType.PHISH_DETECTED if is_phishing else EventType.PHISH_SAFE,
                            severity=sev, email_id=message_id, subject=email_data.get('subject', '')[:100],
                            sender=email_data.get('sender', 'unknown')[:100],
                            confidence=conf if isinstance(conf, (int, float)) else 0.0, provider='outlook', classification=category)
                        bus.publish(evt)
                    except Exception:
                        pass
            except Exception as e:
                logger.error(f"Error processing Outlook email {email.get('id')}: {e}")
        conn.close()
    except Exception as e:
        logger.error(f"Error fetching Outlook emails: {e}")

# ==== ROUTES ====

@phishing_bp.route('/phishing-detection')
def phishing_detection():
    return render_template('phishing_detection.html')

@phishing_bp.route('/api/phishing/analyze', methods=['POST'])
def analyze_email_manual():
    if not PHISHING_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'Phishing detection not available'})
    try:
        data = request.json
        subject = data.get('subject', '')
        sender = data.get('sender', '')
        body = data.get('body', '')
        if not body.strip():
            return jsonify({'status': 'error', 'message': 'Email body is required'})
        category, confidence, explanation, needs_review, factors = classify_email('manual', sender, subject, body)
        urls = extract_and_classify_urls(subject, body)
        bus, EventType, Severity, phishing_event = _get_event_helpers()
        if bus:
            try:
                is_phishing = category.lower() in ('phishing', 'suspicious')
                evt = phishing_event(event_type=EventType.PHISH_DETECTED if is_phishing else EventType.PHISH_SAFE,
                    severity=Severity.HIGH if is_phishing else Severity.INFO,
                    email_id='manual_analysis', subject=subject[:100] if subject else 'Manual analysis',
                    sender=sender[:100] if sender else 'Unknown',
                    confidence=confidence if isinstance(confidence, (int, float)) else 0.0)
                bus.publish(evt)
            except Exception:
                pass
        return jsonify({'status': 'success', 'result': {'category': category, 'confidence': confidence, 'explanation': explanation, 'needs_review': needs_review, 'factors': factors, 'urls': urls}})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@phishing_bp.route('/phishing/set-email-count')
def set_phishing_email_count():
    count = request.args.get('count', 10, type=int)
    provider = request.args.get('provider', 'gmail')
    session['phishing_email_count'] = count
    if provider == 'gmail':
        return redirect(url_for('phishing.phishing_authorize_gmail'))
    return redirect(url_for('phishing.phishing_authorize_outlook'))

@phishing_bp.route('/phishing/authorize_gmail')
def phishing_authorize_gmail():
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing.phishing_detection'))
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Gmail API credentials not configured.', 'error')
        return redirect(url_for('phishing.phishing_detection'))
    try:
        import secrets, hashlib
        flow = Flow.from_client_config(get_google_client_config(), scopes=GMAIL_SCOPES, redirect_uri=GOOGLE_REDIRECT_URI)
        # Generate PKCE code_verifier and challenge (required by Google OAuth2)
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('ascii')).digest()
        ).rstrip(b'=').decode('ascii')
        authorization_url, state = flow.authorization_url(
            access_type='offline', include_granted_scopes='true', prompt='consent',
            code_challenge=code_challenge,
            code_challenge_method='S256'
        )
        session['oauth_state'] = state
        # Store code_verifier SERVER-SIDE (cookie sessions lose it across OAuth redirects)
        _pkce_save(state, code_verifier)
        logger.info(f"Gmail authorize - state: {state[:20]}... verifier saved server-side")
        return redirect(authorization_url)
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('phishing.phishing_detection'))

@phishing_bp.route('/callback')
@phishing_bp.route('/phishing/callback')
def phishing_gmail_callback():
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing.phishing_detection'))
    try:
        num_emails = session.get('phishing_email_count', 10)
        state = request.args.get('state') or session.get('oauth_state')
        flow = Flow.from_client_config(get_google_client_config(), scopes=GMAIL_SCOPES, state=state, redirect_uri=GOOGLE_REDIRECT_URI)
        
        # Retrieve PKCE code_verifier from SERVER-SIDE store (not cookie session)
        code_verifier = _pkce_pop(state) if state else None
        
        # Extract the authorization code from the callback URL
        auth_code = request.args.get('code')
        if not auth_code:
            flash('No authorization code received from Google.', 'error')
            return redirect(url_for('phishing.phishing_detection'))
        
        logger.info(f"Gmail callback - redirect_uri: {GOOGLE_REDIRECT_URI}")
        logger.info(f"Gmail callback - state: {state[:20] if state else 'None'}... code_verifier present: {bool(code_verifier)}")
        flow.fetch_token(code=auth_code, code_verifier=code_verifier)
        credentials = flow.credentials
        service = build_gmail_service(credentials)
        try:
            profile = service.users().getProfile(userId='me').execute()
            user_email = profile.get('emailAddress', 'unknown_user')
        except Exception:
            user_email = 'unknown_user'
        session['phishing_user_email'] = user_email
        session['phishing_provider'] = 'gmail'
        logger.info(f"Gmail OAuth success for {user_email}, fetching {num_emails} emails...")
        flash(f'Successfully connected! Fetching {num_emails} emails...', 'success')
        fetch_and_process_gmail_emails(service, user_email, num_emails)
        return redirect(url_for('phishing.phishing_dashboard'))
    except Exception as e:
        logger.error(f"Gmail callback error: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('phishing.phishing_detection'))

@phishing_bp.route('/phishing/authorize_outlook')
def phishing_authorize_outlook():
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing.phishing_detection'))
    if not OUTLOOK_CLIENT_ID or not OUTLOOK_CLIENT_SECRET:
        flash('Outlook API credentials not configured.', 'error')
        return redirect(url_for('phishing.phishing_detection'))
    try:
        auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
        params = {'client_id': OUTLOOK_CLIENT_ID, 'response_type': 'code', 'redirect_uri': OUTLOOK_REDIRECT_URI,
                  'response_mode': 'query', 'scope': ' '.join(OUTLOOK_SCOPES), 'state': os.urandom(16).hex()}
        session['outlook_state'] = params['state']
        return redirect(auth_url + '&'.join([f"{k}={v}" for k, v in params.items()]))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('phishing.phishing_detection'))

@phishing_bp.route('/callback_outlook')
@phishing_bp.route('/phishing/callback_outlook')
def phishing_outlook_callback():
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing.phishing_detection'))
    try:
        code = request.args.get('code')
        if not code:
            flash('Authorization failed — no code received', 'error')
            return redirect(url_for('phishing.phishing_detection'))
        num_emails = session.get('phishing_email_count', 10)
        data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': OUTLOOK_REDIRECT_URI,
                'client_id': OUTLOOK_CLIENT_ID, 'client_secret': OUTLOOK_CLIENT_SECRET}
        logger.info(f"Outlook callback - redirect_uri: {OUTLOOK_REDIRECT_URI}")
        token_response = http_requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=data)
        if token_response.status_code != 200:
            error_desc = token_response.json().get('error_description', 'Unknown error')
            logger.error(f"Outlook token error: {error_desc}")
            flash(f'Token error: {error_desc}', 'error')
            return redirect(url_for('phishing.phishing_detection'))
        access_token = token_response.json().get('access_token')
        headers = {'Authorization': f'Bearer {access_token}'}
        user_response = http_requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
        user_email = user_response.json().get('userPrincipalName', 'unknown_user') if user_response.status_code == 200 else 'unknown_user'
        session['phishing_user_email'] = user_email
        session['phishing_provider'] = 'outlook'
        logger.info(f"Outlook OAuth success for {user_email}, fetching {num_emails} emails...")
        flash(f'Successfully connected! Fetching {num_emails} emails...', 'success')
        fetch_and_process_outlook_emails(access_token, user_email, num_emails)
        return redirect(url_for('phishing.phishing_dashboard'))
    except Exception as e:
        logger.error(f"Outlook callback error: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('phishing.phishing_detection'))

@phishing_bp.route('/phishing/dashboard')
def phishing_dashboard():
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    try:
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Email WHERE user_email = ? ORDER BY created_at DESC', (user_email,))
        emails = [dict(row) for row in cursor.fetchall()]
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE user_email = ?", (user_email,))
        total = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE category = 'Safe' AND user_email = ?", (user_email,))
        safe = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE category = 'Phishing' AND user_email = ?", (user_email,))
        phishing = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE needs_review = 1 AND user_email = ?", (user_email,))
        review = cursor.fetchone()['count']
        conn.close()
        return render_template('phishing_dashboard.html', emails=emails, stats={'total': total, 'safe': safe, 'phishing': phishing, 'review': review}, user_email=user_email, provider=provider)
    except Exception as e:
        logger.error(f"Phishing dashboard error: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('phishing.phishing_detection'))

@phishing_bp.route('/api/phishing/stats')
def get_phishing_stats():
    try:
        conn = sqlite3.connect(PHISHING_DB)
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
        return jsonify({'total': total, 'safe': safe, 'phishing': phishing, 'needs_review': review})
    except Exception as e:
        return jsonify({'error': str(e)})

@phishing_bp.route('/phishing/email/<int:email_id>')
def phishing_email_details(email_id):
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    try:
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Email WHERE id = ? AND user_email = ?', (email_id, user_email))
        email_row = cursor.fetchone()
        if not email_row:
            flash('Email not found!', 'error')
            return redirect(url_for('phishing.phishing_detection'))
        email = dict(email_row)
        try:
            email['explanation'] = json.loads(email['explanation']) if email.get('explanation') else []
            email['features'] = json.loads(email['features']) if email.get('features') else {}
            email['urls'] = json.loads(email['urls']) if email.get('urls') else []
        except Exception:
            email['explanation'], email['features'], email['urls'] = [], {}, []
        cursor.execute('SELECT * FROM Attachment WHERE email_id = ?', (email_id,))
        attachments = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return render_template('email_details.html', email=email, attachments=attachments, modified_body=email.get('body', ''), provider=provider)
    except Exception as e:
        logger.error(f"Email details error for id={email_id}: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error loading email details: {str(e)}', 'error')
        return redirect(url_for('phishing.phishing_detection'))

@phishing_bp.route('/phishing/feedback/<int:email_id>', methods=['POST'])
def submit_phishing_feedback(email_id):
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    try:
        correct_category = request.form.get('correct_category')
        feedback_reason = request.form.get('feedback_reason', '')
        if correct_category not in ['Safe', 'Phishing']:
            flash('Invalid category selected', 'error')
            return redirect(url_for('phishing.phishing_email_details', email_id=email_id))
        user_conn = get_phishing_db_connection()
        cursor = user_conn.cursor()
        cursor.execute('SELECT * FROM Email WHERE id = ? AND user_email = ?', (email_id, user_email))
        email_row = cursor.fetchone()
        if not email_row:
            flash('Email not found', 'error')
            return redirect(url_for('phishing.phishing_dashboard'))
        email = dict(email_row)
        original_category = email.get('category', 'Unknown')
        feedback_conn = sqlite3.connect(FEEDBACK_DB_PATH)
        feedback_conn.execute('''INSERT INTO Feedback (email_id, user_email, provider, original_category,
            corrected_category, feedback_reason, email_subject, email_sender, email_body_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (email_id, user_email, provider, original_category, correct_category, feedback_reason,
             email.get('subject', ''), email.get('sender', ''), email.get('body', '')[:500] if email.get('body') else ''))
        feedback_conn.commit()
        feedback_conn.close()
        user_conn.execute('UPDATE Email SET category = ? WHERE id = ?', (correct_category, email_id))
        user_conn.commit()
        user_conn.close()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('phishing.phishing_email_details', email_id=email_id))
    except Exception as e:
        flash('Error submitting feedback', 'error')
        return redirect(url_for('phishing.phishing_email_details', email_id=email_id))

@phishing_bp.route('/phishing/attachment/<int:attachment_id>/download')
def download_attachment(attachment_id):
    try:
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Attachment WHERE id = ?', (attachment_id,))
        attachment = cursor.fetchone()
        conn.close()
        if not attachment:
            flash('Attachment not found', 'error')
            return redirect(url_for('phishing.phishing_dashboard'))
        file_data = io.BytesIO(attachment['data'])
        content_type = attachment['content_type'] or 'application/octet-stream'
        return send_file(file_data, mimetype=content_type, as_attachment=True, download_name=attachment['filename'])
    except Exception as e:
        flash('Error downloading attachment', 'error')
        return redirect(url_for('phishing.phishing_dashboard'))

@phishing_bp.route('/phishing/attachment/<int:attachment_id>/scan')
def scan_attachment(attachment_id):
    try:
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Attachment WHERE id = ?', (attachment_id,))
        attachment = cursor.fetchone()
        if not attachment:
            return jsonify({'status': 'error', 'message': 'Attachment not found'})
        scan_result = {'status': 'clean', 'matches': []}
        if yara_rules and attachment['data']:
            try:
                matches = yara_rules.match(data=attachment['data'])
                if matches:
                    scan_result = {'status': 'malicious', 'matches': [str(m) for m in matches]}
            except Exception:
                pass
        cursor.execute('UPDATE Attachment SET yara_result = ? WHERE id = ?', (json.dumps(scan_result), attachment_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'result': scan_result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@phishing_bp.route('/api/phishing/emails')
def get_phishing_emails():
    try:
        conn = sqlite3.connect(PHISHING_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Email ORDER BY created_at DESC LIMIT 100')
        emails = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'status': 'success', 'emails': emails})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@phishing_bp.route('/api/phishing/feedback')
def get_all_feedback():
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

@phishing_bp.route('/api/phishing/user-databases')
def get_user_databases():
    try:
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        cursor.execute('''SELECT provider, user_email, COUNT(*) as email_count FROM Email
            WHERE user_email IS NOT NULL GROUP BY provider, user_email''')
        users = [{'provider': row['provider'], 'user_email': row['user_email'], 'email_count': row['email_count']}
                 for row in cursor.fetchall()]
        conn.close()
        return jsonify({'status': 'success', 'users': users})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


logger.info("✅ Phishing Detection blueprint loaded")
