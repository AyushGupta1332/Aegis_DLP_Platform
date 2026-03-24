"""
Data Classification Service using RoBERTa Model
Scans files and directories to classify sensitive vs non-sensitive content
"""

import os
import torch
import pandas as pd
import numpy as np
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from peft import LoraConfig, get_peft_model
from torch.nn.functional import softmax
import chardet
import docx
import PyPDF2
from pathlib import Path
import warnings

# Try to import nltk tokenizer, fallback to simple split if not available
try:
    from nltk.tokenize import sent_tokenize
    # Try to download punkt if needed
    try:
        import nltk
        nltk.download('punkt', quiet=True)
        nltk.download('punkt_tab', quiet=True)
    except:
        pass
except:
    # Fallback sentence tokenizer
    def sent_tokenize(text):
        return [s.strip() for s in text.split('.') if s.strip()]

warnings.filterwarnings("ignore")
os.environ['TRANSFORMERS_VERBOSITY'] = 'error'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

# ---- PII Regex Pre-Pass (runs BEFORE transformer inference) ----
import re as _re

PII_PATTERNS = {
    # ── Global / US Patterns ──────────────────────────────────────
    'ssn':          _re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card':  _re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?'     # Visa
        r'|5[1-5][0-9]{14}'                  # MasterCard
        r'|3[47][0-9]{13}'                   # Amex
        r'|6(?:011|5[0-9]{2})[0-9]{12}'      # Discover
        r'|(?:6521|6522)[0-9]{12}'           # RuPay (India)
        r')\b'),
    'iban':         _re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'),
    'phone_us':     _re.compile(r'\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'),
    'email_addr':   _re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),

    # ── Indian Government IDs ─────────────────────────────────────
    # Aadhaar — 12 digits, usually formatted as 4-4-4 or plain
    # First digit is 2-9 (never 0 or 1 per UIDAI spec)
    'aadhaar':      _re.compile(
        r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'),

    # PAN Card — 5 uppercase + 4 digits + 1 uppercase (e.g., ABCDE1234F)
    # 4th char indicates holder type: C=Company, P=Person, H=HUF, etc.
    'pan_card':     _re.compile(
        r'\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b'),

    # Indian Passport — One uppercase letter + 7 digits (e.g., J8369854)
    # First letter: A-Z (series varies by passport office)
    'passport_in':  _re.compile(
        r'\b[A-PR-WY][0-9]{7}\b'),

    # Voter ID (EPIC) — 3 uppercase letters + 7 digits (e.g., ABC1234567)
    'voter_id':     _re.compile(
        r'\b[A-Z]{3}\d{7}\b'),

    # Driving License — State code (2 chars) + optional dash + 2-digit RTO
    #   + optional dash + year (2 or 4 digits) + 7 digits
    # e.g., DL-0420110012345, MH1220190001234, KA0120201234567
    'driving_license_in': _re.compile(
        r'\b[A-Z]{2}[\s-]?\d{2}[\s-]?(?:19|20)\d{2}[\s-]?\d{7}\b'),

    # GSTIN — 15-char alphanumeric GST Identification Number
    # Format: 2-digit state code + PAN (10 chars) + 1 entity + Z + checksum
    'gstin':        _re.compile(
        r'\b\d{2}[A-Z]{5}\d{4}[A-Z]\dZ[A-Z0-9]\b'),

    # Indian Phone Number — +91 / 0 prefix + 10 digits (mobile starts with 6-9)
    'phone_in':     _re.compile(
        r'\b(?:\+91[\s.-]?|0)?[6-9]\d{4}[\s.-]?\d{5}\b'),

    # ── Indian Financial ──────────────────────────────────────────
    # UPI ID — e.g., name@upi, name@paytm, name@ybl
    'upi_id':       _re.compile(
        r'\b[A-Za-z0-9._-]+@[A-Za-z]{2,}\b'),

    # IFSC Code — 4 letter bank code + 0 + 6 alphanumeric (e.g., SBIN0001234)
    'ifsc_code':    _re.compile(
        r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),

    # Indian Bank Account Number — 9 to 18 digits (most banks)
    'bank_account_in': _re.compile(
        r'\b\d{9,18}\b'),  # broad — weighted lower in scoring
}

# Patterns that are highly specific — a single match means PII is present
# Three-band confidence thresholds
CONFIDENCE_HIGH = 0.75   # Auto-classify (high confidence)
CONFIDENCE_LOW  = 0.40   # Auto-classify as non-sensitive
# Between LOW and HIGH → flag for human review

# Patterns that are highly specific — a single match means PII is present
_HIGH_CONFIDENCE_PATTERNS = {
    'aadhaar', 'pan_card', 'ssn', 'credit_card', 'gstin',
    'driving_license_in', 'passport_in', 'voter_id', 'iban',
}

# Broad patterns that can false-positive on random numbers/text.
# These only count when at least 2 other PII types are also found.
_LOW_CONFIDENCE_PATTERNS = {
    'bank_account_in', 'upi_id',
}

def pii_pre_scan(text: str) -> dict:
    """Scan text for PII patterns with tiered confidence.
    
    High-confidence patterns (Aadhaar, PAN, SSN, credit card, etc.)
    trigger instant classification.  Broad patterns (bank account
    numbers, UPI IDs) are only included when ≥2 other PII types are
    already found — this avoids false positives from random digit
    sequences.
    
    Returns dict of pattern_name -> match_count (only confirmed hits).
    """
    if not text:
        return {}
    
    sample = text[:50000]  # cap scan length
    raw_hits = {}
    for name, pattern in PII_PATTERNS.items():
        matches = pattern.findall(sample)
        if matches:
            raw_hits[name] = len(matches)
    
    # Separate into high-confidence and low-confidence buckets
    confirmed = {k: v for k, v in raw_hits.items() if k in _HIGH_CONFIDENCE_PATTERNS}
    tentative = {k: v for k, v in raw_hits.items()
                 if k in _LOW_CONFIDENCE_PATTERNS}
    
    # Medium-confidence patterns (phone, email, IFSC) — always included
    medium = {k: v for k, v in raw_hits.items()
              if k not in _HIGH_CONFIDENCE_PATTERNS and k not in _LOW_CONFIDENCE_PATTERNS}
    confirmed.update(medium)
    
    # Only promote low-confidence hits when ≥2 other distinct PII types found
    if len(confirmed) >= 2 and tentative:
        confirmed.update(tentative)
    
    return confirmed

class DataClassifier:
    def __init__(self, model_path):
        """Initialize the RoBERTa classification model"""
        print(f"[DataClassifier] Initializing with model path: {model_path}")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"[DataClassifier] Using device: {self.device}")
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        self.load_model()
    
    def load_model(self):
        """Load RoBERTa model with LoRA configuration"""
        try:
            print("[DataClassifier] Loading RoBERTa tokenizer...")
            self.tokenizer = RobertaTokenizer.from_pretrained("roberta-base")
            print("[DataClassifier] Loading RoBERTa base model...")
            # Suppress safetensors LOAD REPORT (UNEXPECTED/MISSING keys are expected
            # when loading a base LM checkpoint for sequence classification + LoRA)
            import io, sys
            _old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                base_model = RobertaForSequenceClassification.from_pretrained("roberta-base", num_labels=2)
            finally:
                sys.stdout = _old_stdout
            
            print("[DataClassifier] Configuring LoRA...")
            lora_config = LoraConfig(
                task_type="SEQ_CLS",
                r=8,
                lora_alpha=16,
                lora_dropout=0.1,
                bias="none"
            )
            
            print("[DataClassifier] Applying LoRA to model...")
            self.model = get_peft_model(base_model, lora_config)
            
            print(f"[DataClassifier] Loading model weights from: {self.model_path}")
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
            self.model.to(self.device)
            self.model.eval()
            
            print("[DataClassifier] ✓ RoBERTa model loaded successfully!")
        except Exception as e:
            print(f"[DataClassifier] ERROR loading model: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    # ========== FILE EXTRACTION FUNCTIONS ==========
    
    def safe_read_csv(self, file_path):
        """Read CSV with automatic encoding detection"""
        try:
            with open(file_path, 'rb') as f:
                encoding = chardet.detect(f.read(10000))['encoding']
            return pd.read_csv(file_path, encoding=encoding)
        except:
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    return pd.read_csv(file_path, encoding=encoding)
                except:
                    continue
            return pd.read_csv(file_path, encoding='utf-8', errors='ignore')
    
    def analyze_tabular_data(self, df):
        """Analyze tabular data and create descriptive sentences"""
        if df.empty:
            return ["Empty dataset with no data"]
        
        sentences = []
        df = df.head(1000) if len(df) > 1000 else df
        df = df.iloc[:, :50] if len(df.columns) > 50 else df
        
        # Create descriptive sentences from data
        for idx, row in df.head(10).iterrows():
            row_data = []
            for col, val in row.items():
                if pd.notna(val):
                    val_str = str(val)[:100]
                    row_data.append(f"{col}: {val_str}")
            if row_data:
                sentence = "Record contains " + ", ".join(row_data[:5])
                sentences.append(sentence)
        
        sentences.append(f"Dataset has {len(df)} rows and {len(df.columns)} columns")
        
        # Check for sensitive column names
        sensitive_keywords = ['name', 'email', 'phone', 'address', 'ssn', 'id', 'password', 'salary', 'credit', 'account']
        sensitive_cols = [col for col in df.columns if any(keyword in col.lower() for keyword in sensitive_keywords)]
        
        if sensitive_cols:
            sentences.append(f"Dataset contains potentially sensitive columns: {', '.join(sensitive_cols[:10])}")
        
        return sentences[:20]
    
    def extract_text_comprehensive(self, file_path):
        """Extract text from various file formats"""
        file_path = Path(file_path)
        extension = file_path.suffix.lower()
        text = ""

        if extension == '.txt':
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        text = f.read()[:50000]
                    break
                except:
                    continue
                    
        elif extension == '.docx':
            try:
                doc = docx.Document(file_path)
                paragraphs = [para.text for para in doc.paragraphs if para.text.strip()][:100]
                text = "\n\n".join(paragraphs)
            except:
                text = "Error reading DOCX file"
        
        elif extension == '.pdf':
            try:
                with open(file_path, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    pages_to_read = min(len(pdf_reader.pages), 20)
                    for i in range(pages_to_read):
                        try:
                            page_text = pdf_reader.pages[i].extract_text()
                            if page_text:
                                text += page_text + "\n\n"
                        except:
                            continue
            except:
                text = "Error reading PDF file"
                
        elif extension == '.csv':
            try:
                df = self.safe_read_csv(file_path)
                if df is not None:
                    df = df.head(1000)
                    sentences = self.analyze_tabular_data(df)
                    text = ". ".join(sentences) + "."
                else:
                    text = "Error reading CSV file"
            except:
                text = "Error processing CSV file"
        
        elif extension in ['.xlsx', '.xls']:
            try:
                df = pd.read_excel(file_path, nrows=1000)
                sentences = self.analyze_tabular_data(df)
                text = ". ".join(sentences) + "."
            except:
                text = "Error reading Excel file: contains tabular data"
        
        return text[:20000] if text else ""
    
    # ========== CLASSIFICATION FUNCTIONS ==========
    
    def safe_tokenize(self, text, max_length=512):
        """Safely tokenize text"""
        try:
            text = str(text)[:10000]
            return self.tokenizer(text, truncation=True, padding=True, max_length=max_length, return_tensors="pt")
        except:
            return {
                'input_ids': torch.zeros((1, max_length), dtype=torch.long),
                'attention_mask': torch.zeros((1, max_length), dtype=torch.long)
            }
    
    def classify_single_text(self, text):
        """Classify a single piece of text"""
        try:
            if not text or not text.strip():
                return 0, 0.5
            
            inputs = self.safe_tokenize(text, max_length=512)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = softmax(logits, dim=1)
                pred = torch.argmax(probs, dim=1).item()
                conf = probs.max().item()
                
            return pred, conf
        except:
            return 0, 0.5
    
    def classify_with_majority_voting(self, text, token_threshold=500, majority_threshold=0.8):
        """Classify text using majority voting for long documents"""
        try:
            if not text or not text.strip():
                return 0, 0.5
            
            text = text[:20000]
            
            # Get token count
            try:
                token_count = len(self.tokenizer.encode(text[:10000], add_special_tokens=False))
            except:
                token_count = len(text.split()) * 1.3
            
            # Single classification for short texts
            if token_count <= token_threshold:
                pred, conf = self.classify_single_text(text)
                return pred, conf
            
            # Majority voting for long texts
            try:
                sentences = sent_tokenize(text)
            except:
                sentences = [s.strip() for s in text.split('.') if s.strip()]
            
            if not sentences:
                return self.classify_single_text(text[:2000])
            
            meaningful_sentences = [s for s in sentences if len(s.strip()) > 10]
            if not meaningful_sentences:
                meaningful_sentences = sentences
            
            max_sentences = 50
            if len(meaningful_sentences) > max_sentences:
                meaningful_sentences = meaningful_sentences[:max_sentences]
            
            sensitive_count = 0
            total_confidence = 0
            
            for sentence in meaningful_sentences:
                pred, conf = self.classify_single_text(sentence)
                if pred == 1:
                    sensitive_count += 1
                total_confidence += conf
            
            total_sentences = len(meaningful_sentences)
            
            # Use majority threshold
            required_sensitive_count = total_sentences * majority_threshold
            
            if sensitive_count >= required_sensitive_count:
                final_prediction = 1
            else:
                final_prediction = 0
            
            avg_confidence = total_confidence / total_sentences if total_sentences > 0 else 0.5
            
            return final_prediction, avg_confidence
            
        except:
            return 0, 0.5
    
    def classify_file(self, file_path, progress_callback=None):
        """Classify a single file with PII pre-scan and confidence banding."""
        try:
            file_path = Path(file_path)
            
            # Extract text
            text = self.extract_text_comprehensive(file_path)
            
            if not text or not text.strip():
                return {
                    'filename': file_path.name,
                    'path': str(file_path),
                    'classification': 'Non-Sensitive',
                    'confidence': 0.5,
                    'error': 'No text could be extracted'
                }
            
            # ---- PII Regex Pre-Pass (fast, runs before transformer) ----
            pii_hits = pii_pre_scan(text)
            if pii_hits:
                result = {
                    'filename': file_path.name,
                    'path': str(file_path),
                    'classification': 'Sensitive',
                    'confidence': 100.0,
                    'file_size': file_path.stat().st_size,
                    'file_type': file_path.suffix,
                    'pii_detected': pii_hits,
                    'needs_review': False,
                    'confidence_band': 'high',
                }
                if progress_callback:
                    progress_callback(result)
                return result
            
            # ---- Transformer Classification ----
            pred, conf = self.classify_with_majority_voting(text, token_threshold=500)
            
            # ---- Three-Band Confidence Enforcement ----
            needs_review = False
            if conf >= CONFIDENCE_HIGH:
                confidence_band = 'high'
            elif conf >= CONFIDENCE_LOW:
                confidence_band = 'medium'
                needs_review = True  # Human should verify
            else:
                confidence_band = 'low'
            
            result = {
                'filename': file_path.name,
                'path': str(file_path),
                'classification': 'Sensitive' if pred == 1 else 'Non-Sensitive',
                'confidence': float(conf * 100),
                'file_size': file_path.stat().st_size,
                'file_type': file_path.suffix,
                'needs_review': needs_review,
                'confidence_band': confidence_band,
            }
            
            if progress_callback:
                progress_callback(result)
            
            return result
            
        except Exception as e:
            return {
                'filename': file_path.name if isinstance(file_path, Path) else str(file_path),
                'path': str(file_path),
                'classification': 'Error',
                'confidence': 0.0,
                'error': str(e)
            }
    
    def scan_directory(self, directory_path, allowed_extensions=None, progress_callback=None):
        """Scan entire directory for files"""
        if allowed_extensions is None:
            allowed_extensions = {'.txt', '.docx', '.pdf', '.csv', '.xlsx', '.xls'}
        
        directory_path = Path(directory_path)
        
        if not directory_path.exists():
            raise ValueError(f"Directory does not exist: {directory_path}")
        
        # Get all files
        all_files = []
        for ext in allowed_extensions:
            all_files.extend(directory_path.glob(f'**/*{ext}'))
        
        results = []
        total_files = len(all_files)
        
        for idx, file_path in enumerate(all_files):
            result = self.classify_file(file_path, progress_callback)
            results.append(result)
            
            if progress_callback:
                progress_callback({
                    'type': 'progress',
                    'current': idx + 1,
                    'total': total_files,
                    'percentage': ((idx + 1) / total_files) * 100
                })
        
        return results


# Global classifier instance
classifier = None

def get_classifier():
    """Get or create classifier instance"""
    global classifier
    if classifier is None:
        # Use relative path from project root
        import os
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, 'models', 'data_classification', 'best_roberta_model_2.2M_1_Epoc.pt')
        classifier = DataClassifier(model_path)
    return classifier

