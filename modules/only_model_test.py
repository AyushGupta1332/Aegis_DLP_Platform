# test_mlp_model.py - Standalone Testing Script for MLP IDS Model

import pandas as pd
import numpy as np
import pickle
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print(" MLP IDS MODEL - TESTING SCRIPT")
print("="*70)

# Load Model and Preprocessors
def load_model():
    """Load the trained MLP model and all preprocessing components"""
    try:
        print("\n[1/4] Loading MLP model...")
        with open('mlp_ids_model.pkl', 'rb') as f:
            model = pickle.load(f)
        print("✓ Model loaded successfully")
        
        print("[2/4] Loading scaler...")
        with open('scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        print("✓ Scaler loaded successfully")
        
        print("[3/4] Loading label encoders...")
        with open('label_encoders.pkl', 'rb') as f:
            label_encoders = pickle.load(f)
        print("✓ Label encoders loaded successfully")
        
        print("[4/4] Loading feature info...")
        with open('feature_info.pkl', 'rb') as f:
            feature_info = pickle.load(f)
        print("✓ Feature info loaded successfully")
        
        return model, scaler, label_encoders, feature_info
    except Exception as e:
        print(f"\n❌ Error loading model components: {e}")
        return None, None, None, None


# Load Test Dataset
def load_test_data(filepath):
    """Load the test dataset from CSV"""
    try:
        print(f"\n[Loading Data] Reading test dataset from: {filepath}")
        df = pd.read_csv(filepath)
        print(f"✓ Dataset loaded successfully")
        print(f"  - Total samples: {len(df)}")
        print(f"  - Features: {df.shape[1]}")
        print(f"  - Columns: {list(df.columns)}")
        return df
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")
        return None


# Preprocess and Predict
def test_model(model, scaler, label_encoders, feature_info, test_df):
    """
    Preprocess test data and generate predictions
    
    Args:
        model: Trained MLP model
        scaler: StandardScaler for feature scaling
        label_encoders: Dictionary of LabelEncoders for categorical features
        feature_info: Dictionary containing feature information
        test_df: Test dataset DataFrame
    
    Returns:
        predictions, probabilities, ground_truth (if available)
    """
    try:
        print("\n" + "="*70)
        print(" PREPROCESSING AND PREDICTION")
        print("="*70)
        
        # Check if ground truth labels exist
        has_labels = 'anomaly' in test_df.columns
        
        if has_labels:
            print("\n[Ground Truth] Labels found in dataset - evaluation metrics will be calculated")
            y_true = test_df['anomaly'].values
            X_test = test_df.drop(['label', 'anomaly'], axis=1, errors='ignore')
        else:
            print("\n[No Labels] No ground truth found - only predictions will be generated")
            y_true = None
            X_test = test_df.drop(['label', 'anomaly'], axis=1, errors='ignore')
        
        print(f"\n[Features] Total features for prediction: {X_test.shape[1]}")
        
        # Encode categorical features
        print("\n[Encoding] Processing categorical features...")
        X_test_encoded = X_test.copy()
        categorical_cols = feature_info['categorical_cols']
        
        for col in categorical_cols:
            if col in X_test_encoded.columns:
                le = label_encoders[col]
                # Handle unseen categories by mapping to -1
                X_test_encoded[col] = X_test_encoded[col].astype(str).apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                )
                print(f"  ✓ Encoded: {col}")
        
        # Scale features
        print("\n[Scaling] Applying StandardScaler transformation...")
        X_test_scaled = scaler.transform(X_test_encoded)
        print("✓ Features scaled successfully")
        
        # Make predictions
        print("\n[Prediction] Running MLP model inference...")
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)
        
        print(f"✓ Predictions completed for {len(y_pred)} samples")
        
        return y_pred, y_pred_proba, y_true, X_test
        
    except Exception as e:
        print(f"\n❌ Error during prediction: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None


# Evaluate Results
def evaluate_results(y_true, y_pred, y_pred_proba):
    """Calculate and display evaluation metrics"""
    print("\n" + "="*70)
    print(" EVALUATION METRICS")
    print("="*70)
    
    # Class distribution
    unique, counts = np.unique(y_pred, return_counts=True)
    print("\n[Prediction Distribution]")
    for label, count in zip(unique, counts):
        label_name = "Normal" if label == 0 else "Anomaly"
        percentage = (count / len(y_pred)) * 100
        print(f"  {label_name}: {count} samples ({percentage:.2f}%)")
    
    if y_true is not None:
        print("\n[Accuracy Score]")
        accuracy = accuracy_score(y_true, y_pred)
        print(f"  Overall Accuracy: {accuracy*100:.2f}%")
        
        print("\n[Classification Report]")
        print(classification_report(y_true, y_pred, 
                                   target_names=['Normal', 'Anomaly'],
                                   digits=4))
        
        print("[Confusion Matrix]")
        cm = confusion_matrix(y_true, y_pred)
        print(f"\n                Predicted")
        print(f"              Normal  Anomaly")
        print(f"Actual Normal   {cm[0][0]:6d}  {cm[0][1]:7d}")
        print(f"      Anomaly   {cm[1][0]:6d}  {cm[1][1]:7d}")
        
        # Per-class metrics
        precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, average=None)
        print("\n[Per-Class Metrics]")
        print(f"{'Class':<10} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Support':<10}")
        print("-" * 60)
        for i, class_name in enumerate(['Normal', 'Anomaly']):
            print(f"{class_name:<10} {precision[i]:<12.4f} {recall[i]:<12.4f} {f1[i]:<12.4f} {support[i]:<10.0f}")


# Save Predictions
def save_predictions(test_df, y_pred, y_pred_proba, output_file='predictions_mlp.csv'):
    """Save predictions to CSV file"""
    try:
        print("\n" + "="*70)
        print(" SAVING RESULTS")
        print("="*70)
        
        output_df = test_df.copy()
        output_df['predicted_class'] = y_pred
        output_df['predicted_label'] = ['Normal' if p == 0 else 'Anomaly' for p in y_pred]
        output_df['normal_probability'] = y_pred_proba[:, 0]
        output_df['anomaly_probability'] = y_pred_proba[:, 1]
        
        output_df.to_csv(output_file, index=False)
        print(f"\n✓ Predictions saved to: {output_file}")
        print(f"  - Total records: {len(output_df)}")
        print(f"  - Columns: {list(output_df.columns)}")
        
    except Exception as e:
        print(f"\n❌ Error saving predictions: {e}")


# Main Testing Function
def main():
    """Main testing workflow"""
    
    # Step 1: Load model components
    model, scaler, label_encoders, feature_info = load_model()
    
    if model is None:
        print("\n❌ Failed to load model. Exiting...")
        return
    
    # Step 2: Load test dataset
    test_file = input("\n[Input] Enter test dataset filepath (e.g., 'test_data.csv'): ").strip()
    test_df = load_test_data(test_file)
    
    if test_df is None:
        print("\n❌ Failed to load test data. Exiting...")
        return
    
    # Step 3: Run predictions
    y_pred, y_pred_proba, y_true, X_test = test_model(
        model, scaler, label_encoders, feature_info, test_df
    )
    
    if y_pred is None:
        print("\n❌ Prediction failed. Exiting...")
        return
    
    # Step 4: Evaluate results
    evaluate_results(y_true, y_pred, y_pred_proba)
    
    # Step 5: Save predictions
    save_choice = input("\n[Save] Save predictions to CSV? (yes/no): ").strip().lower()
    if save_choice in ['yes', 'y']:
        output_file = input("[Output] Enter output filename (default: 'predictions_mlp.csv'): ").strip()
        if not output_file:
            output_file = 'predictions_mlp.csv'
        save_predictions(test_df, y_pred, y_pred_proba, output_file)
    
    print("\n" + "="*70)
    print(" TESTING COMPLETED SUCCESSFULLY")
    print("="*70 + "\n")


if __name__ == '__main__':
    main()
