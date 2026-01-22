"""
Quick test script to verify data_classifier can be imported and initialized
Run this to test if the RoBERTa model can load
"""

import sys
import os

print("=" * 60)
print("TESTING DATA CLASSIFIER")
print("=" * 60)

# Test 1: Import modules
print("\n[TEST 1] Importing required modules...")
try:
    import torch
    print("  ✓ torch")
    import transformers
    print("  ✓ transformers")
    import peft
    print("  ✓ peft")
    import pandas as pd
    print("  ✓ pandas")
    import docx
    print("  ✓ python-docx")
    import PyPDF2
    print("  ✓ PyPDF2")
    print("[TEST 1] PASSED - All dependencies installed")
except ImportError as e:
    print(f"[TEST 1] FAILED - Missing dependency: {e}")
    sys.exit(1)

# Test 2: Import data_classifier
print("\n[TEST 2] Importing data_classifier module...")
try:
    from data_classifier import DataClassifier
    print("[TEST 2] PASSED - Module imported successfully")
except Exception as e:
    print(f"[TEST 2] FAILED - Error importing: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 3: Check model file exists
print("\n[TEST 3] Checking model file...")
model_path = r"D:\VS code\Data Gathering Text CLassification\Models\best_roberta_model_2.2M_1_Epoc.pt"
if os.path.exists(model_path):
    size_mb = os.path.getsize(model_path) / (1024 * 1024)
    print(f"  ✓ Model file found: {model_path}")
    print(f"  ✓ Size: {size_mb:.1f} MB")
    print("[TEST 3] PASSED")
else:
    print(f"  ✗ Model file NOT found: {model_path}")
    print("[TEST 3] FAILED")
    print("\nPlease update the model path in data_classifier.py (line 334)")
    sys.exit(1)

# Test 4: Initialize classifier (this will take time)
print("\n[TEST 4] Initializing classifier (this may take 30-60 seconds)...")
print("  (Loading RoBERTa model...)")
try:
    classifier = DataClassifier(model_path)
    print("[TEST 4] PASSED - Classifier initialized successfully!")
except Exception as e:
    print(f"[TEST 4] FAILED - Error initializing: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("ALL TESTS PASSED! ✓")
print("The data classifier is working correctly.")
print("=" * 60)
