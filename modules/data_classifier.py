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
            base_model = RobertaForSequenceClassification.from_pretrained("roberta-base", num_labels=2)
            
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
        """Classify a single file"""
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
            
            # Classify
            pred, conf = self.classify_with_majority_voting(text, token_threshold=500)
            
            result = {
                'filename': file_path.name,
                'path': str(file_path),
                'classification': 'Sensitive' if pred == 1 else 'Non-Sensitive',
                'confidence': float(conf * 100),
                'file_size': file_path.stat().st_size,
                'file_type': file_path.suffix
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

