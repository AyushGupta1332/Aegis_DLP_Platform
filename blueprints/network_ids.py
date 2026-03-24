"""
Network IDS (Anomaly Detection) Routes
=======================================
Handles the Network Intrusion Detection System powered by MLP Neural Network.
Includes model loading, prediction, traffic monitoring, and API routes.
"""

from flask import Blueprint, jsonify, request, render_template, redirect, url_for
import threading
import subprocess
import time
import os
import pickle
import pandas as pd
import numpy as np
from collections import deque
import logging

logger = logging.getLogger(__name__)

network_ids_bp = Blueprint('network_ids', __name__)

# ---- MLP Model Loading ----

def load_mlp_model():
    try:
        logger.info("Loading MLP model and preprocessors...")
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        models_dir = os.path.join(base_dir, 'models', 'anomaly_detection')
        
        model_path = os.path.join(models_dir, 'mlp_ids_model.pkl')
        scaler_path = os.path.join(models_dir, 'scaler.pkl')
        encoders_path = os.path.join(models_dir, 'label_encoders.pkl')
        features_path = os.path.join(models_dir, 'feature_info.pkl')
        
        if not os.path.exists(model_path):
            logger.error(f"Model file not found at {model_path}")
            return None, None, None, None
        
        with open(model_path, 'rb') as f:
            mlp_model = pickle.load(f)
        with open(scaler_path, 'rb') as f:
            mlp_scaler = pickle.load(f)
        with open(encoders_path, 'rb') as f:
            mlp_label_encoders = pickle.load(f)
        with open(features_path, 'rb') as f:
            mlp_feature_info = pickle.load(f)
        
        logger.info("✓ MLP model loaded successfully!")
        return mlp_model, mlp_scaler, mlp_label_encoders, mlp_feature_info
    except Exception as e:
        logger.error(f"Error loading MLP model: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None


# Load model at import time
mlp_model, mlp_scaler, mlp_label_encoders, mlp_feature_info = load_mlp_model()


def _get_state():
    """Get shared state from app_state singleton."""
    from blueprints.shared_state import app_state
    return app_state


def predict_samples(df):
    """Run MLP predictions on DataFrame samples."""
    state = _get_state()
    
    if mlp_model is None:
        logger.warning("MLP Model not loaded!")
        return []
    
    try:
        X_test = df.drop(['label', 'anomaly'], axis=1, errors='ignore')
        X_test_encoded = X_test.copy()
        categorical_cols = mlp_feature_info['categorical_cols']
        
        for col in categorical_cols:
            if col in X_test_encoded.columns:
                le = mlp_label_encoders[col]
                X_test_encoded[col] = X_test_encoded[col].astype(str).apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                )
        
        X_test_scaled = mlp_scaler.transform(X_test_encoded)
        y_pred = mlp_model.predict(X_test_scaled)
        y_pred_proba = mlp_model.predict_proba(X_test_scaled)[:, 1]
        
        results = []
        for i, pred in enumerate(y_pred):
            confidence = y_pred_proba[i] if pred == 1 else (1 - y_pred_proba[i])
            result = {
                'prediction': 'Normal' if pred == 0 else 'Anomaly',
                'confidence': float(confidence * 100),
                'timestamp': time.strftime('%d %b %Y, %I:%M:%S %p')
            }
            results.append(result)
            
            state.stats['total_samples'] += 1
            if pred == 0:
                state.stats['normal_count'] += 1
            else:
                state.stats['anomaly_count'] += 1
            
            # ---- Model Drift Detection (rolling window) ----
            if not hasattr(state, '_drift_window'):
                state._drift_window = deque(maxlen=500)
            state._drift_window.append(1 if pred == 1 else 0)
            if len(state._drift_window) >= 100:
                anomaly_rate = sum(state._drift_window) / len(state._drift_window)
                if anomaly_rate > 0.40:
                    logger.warning(
                        "MODEL DRIFT: Anomaly rate %.1f%% over last %d predictions "
                        "(threshold 40%%). Model may need retraining.",
                        anomaly_rate * 100, len(state._drift_window)
                    )
                elif anomaly_rate < 0.005:
                    logger.warning(
                        "MODEL DRIFT: Anomaly rate %.2f%% over last %d predictions "
                        "(near zero). Model may miss real threats.",
                        anomaly_rate * 100, len(state._drift_window)
                    )
        
        return results
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return []


def monitor_and_predict():
    """Monitor thread function - reads CSV, runs predictions, emits results."""
    state = _get_state()
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, 'data')
    csv_file = os.path.join(data_dir, 'ids_capture.csv')
    
    normal_batch_counter = 0
    batch_counter = 0
    
    while state.monitoring_active:
        try:
            if os.path.exists(csv_file):
                df = pd.read_csv(csv_file)
                current_rows = len(df)
                
                if current_rows > state.last_processed_rows:
                    new_df = df.iloc[state.last_processed_rows:current_rows]
                    
                    if len(new_df) > 0:
                        batch_size = 10
                        for i in range(0, len(new_df), batch_size):
                            if not state.monitoring_active:
                                break
                            
                            batch = new_df.iloc[i:i+batch_size]
                            predictions = predict_samples(batch)
                            
                            batch_normal_count = 0
                            
                            for j, pred in enumerate(predictions):
                                state.prediction_queue.append(pred)
                                state.socketio.emit('new_prediction', pred)
                                
                                if state.EVENT_BUS_AVAILABLE and state.event_bus:
                                    try:
                                        from modules.event_bus.events import EventType, Severity
                                        from modules.event_bus import network_event
                                        
                                        row_idx = i + j
                                        if row_idx < len(batch):
                                            row = batch.iloc[j]
                                            protocol = str(row.get('protocol_type', 'unknown')) if 'protocol_type' in batch.columns else 'unknown'
                                            service = str(row.get('service', 'unknown')) if 'service' in batch.columns else 'unknown'
                                            src_bytes = int(row.get('src_bytes', 0)) if 'src_bytes' in batch.columns else 0
                                            dst_bytes = int(row.get('dst_bytes', 0)) if 'dst_bytes' in batch.columns else 0
                                        else:
                                            protocol = service = 'unknown'
                                            src_bytes = dst_bytes = 0
                                        
                                        is_anomaly = pred['prediction'] == 'Anomaly'
                                        confidence = pred.get('confidence', 0)
                                        
                                        if is_anomaly:
                                            severity = Severity.CRITICAL if confidence > 90 else (Severity.HIGH if confidence > 75 else Severity.MEDIUM)
                                            evt = network_event(
                                                event_type=EventType.NET_ANOMALY,
                                                severity=severity,
                                                anomaly_score=round(confidence, 1),
                                                protocol=protocol,
                                                service=service,
                                                src_bytes=src_bytes,
                                                dst_bytes=dst_bytes,
                                                message=f"Network anomaly detected ({protocol}/{service}) — {confidence:.1f}% confidence",
                                            )
                                            state.event_bus.publish(evt)
                                        else:
                                            batch_normal_count += 1
                                    except Exception:
                                        pass
                            
                            normal_batch_counter += batch_normal_count
                            if normal_batch_counter >= 50 and state.EVENT_BUS_AVAILABLE and state.event_bus:
                                try:
                                    from modules.event_bus.events import EventType, Severity
                                    from modules.event_bus import network_event
                                    evt = network_event(
                                        event_type=EventType.NET_NORMAL,
                                        severity=Severity.INFO,
                                        packet_count=normal_batch_counter,
                                        message=f"{normal_batch_counter} normal packets analyzed — no anomalies",
                                    )
                                    state.event_bus.publish(evt)
                                    normal_batch_counter = 0
                                except Exception:
                                    pass
                            
                            state.socketio.emit('stats_update', state.stats)
                            
                            batch_counter += 1
                            if batch_counter % 20 == 0 and state.EVENT_BUS_AVAILABLE and state.event_bus:
                                try:
                                    from modules.event_bus.events import EventType, Severity
                                    from modules.event_bus import network_event
                                    evt = network_event(
                                        event_type=EventType.NET_STATS_UPDATE,
                                        severity=Severity.INFO,
                                        message=f"IDS Stats — {state.stats['total_samples']} analyzed, {state.stats['anomaly_count']} anomalies, {state.stats['normal_count']} normal",
                                        total_samples=state.stats['total_samples'],
                                        anomaly_count=state.stats['anomaly_count'],
                                        normal_count=state.stats['normal_count'],
                                    )
                                    state.event_bus.publish(evt)
                                except Exception:
                                    pass
                    
                    state.last_processed_rows = current_rows
            
            time.sleep(2)
            
        except Exception as e:
            logger.error(f"Monitor error: {e}")
            time.sleep(2)
    
    # Final stats on stop
    if state.EVENT_BUS_AVAILABLE and state.event_bus and state.stats['total_samples'] > 0:
        try:
            from modules.event_bus.events import EventType, Severity
            from modules.event_bus import network_event
            evt = network_event(
                event_type=EventType.NET_STATS_UPDATE,
                severity=Severity.INFO,
                message=f"IDS Session complete — {state.stats['total_samples']} packets, {state.stats['anomaly_count']} anomalies detected",
                total_samples=state.stats['total_samples'],
                anomaly_count=state.stats['anomaly_count'],
                normal_count=state.stats['normal_count'],
            )
            state.event_bus.publish(evt)
        except Exception:
            pass
    
    logger.info("Monitor and predict thread exiting")


def run_monitor():
    """Run packet capture in a SUBPROCESS (not in-process).
    
    Scapy's sniff() requires raw socket privileges and can crash the
    host process on capture errors.  By running it as a subprocess we:
    1. Isolate privilege escalation to the child process
    2. Prevent capture crashes from taking down Flask
    3. Allow the child to be killed without affecting the main app
    
    Communication uses the existing CSV file that monitor_and_predict()
    already polls.
    """
    state = _get_state()
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        monitor_script = os.path.join(base_dir, 'modules', 'monitor.py')
        data_dir = os.path.join(base_dir, 'data')
        csv_file = os.path.join(data_dir, 'ids_capture.csv')
        
        # Launch monitor.py as a separate process with CLI args
        state.ids_capture_process = subprocess.Popen(
            ['python', monitor_script, '--samples', '1000000', '--output', csv_file],
            cwd=base_dir,
            stdin=subprocess.DEVNULL,
        )
        logger.info(f"Packet capture subprocess started (PID {state.ids_capture_process.pid})")
        
        # Wait for subprocess to finish (or be killed by stop_monitoring)
        state.ids_capture_process.wait()
    except Exception as e:
        logger.error(f"Capture subprocess error: {e}")
    finally:
        state.ids_capture_process = None
        logger.info("Capture subprocess finished")


# ---- Routes ----

@network_ids_bp.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@network_ids_bp.route('/anomaly-detection')
def anomaly_detection():
    """Anomaly detection dashboard"""
    return render_template('anomaly_detection.html')

@network_ids_bp.route('/data-classification')
def data_classification():
    """Data classification scanner"""
    return render_template('data_classification.html')

@network_ids_bp.route('/device-monitoring')
def device_monitoring():
    """Unified Device Monitoring & File Transfer Control - Redirect to home"""
    return redirect(url_for('unified_monitoring.unified_monitoring_home'))


@network_ids_bp.route('/api/start', methods=['POST'])
def start_monitoring():
    state = _get_state()
    
    if not state.monitoring_active:
        state.monitoring_active = True
        
        # Reset stats and tracking
        state.stats['total_samples'] = 0
        state.stats['normal_count'] = 0
        state.stats['anomaly_count'] = 0
        state.last_processed_rows = 0
        state.prediction_queue.clear()
        
        # Delete old CSV file for fresh start
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data')
        csv_file = os.path.join(data_dir, 'ids_capture.csv')
        if os.path.exists(csv_file):
            try:
                os.remove(csv_file)
                logger.info(f"Cleared old capture file: {csv_file}")
            except Exception as e:
                logger.warning(f"Could not delete old CSV: {e}")
        
        # Start traffic generator
        try:
            traffic_script = os.path.join(base_dir, 'modules', 'traffic.py')
            state.traffic_gen_process = subprocess.Popen(['python', traffic_script], cwd=base_dir)
            time.sleep(2)
            logger.info("Traffic generator started")
        except Exception as e:
            logger.error(f"Traffic generator error: {e}")
        
        # Start monitor in background thread
        try:
            state.monitor_thread = threading.Thread(target=run_monitor, daemon=True)
            state.monitor_thread.start()
            logger.info("Monitor thread started")
        except Exception as e:
            logger.error(f"Monitor start error: {e}")
        
        # Start prediction thread
        pred_thread = threading.Thread(target=monitor_and_predict, daemon=True)
        pred_thread.start()
        logger.info("Prediction thread started")
        
        state.publish_event_bus(
            _event_type('SYSTEM_MODULE_STARTED'),
            severity=_severity('MEDIUM'),
            module='Network Anomaly Detection',
            message='Network IDS monitoring started — traffic capture & anomaly detection active'
        )
        
        return jsonify({'status': 'started', 'message': 'Monitoring started successfully'})
    
    return jsonify({'status': 'already_running', 'message': 'Monitoring is already active'})


@network_ids_bp.route('/api/stop', methods=['POST'])
def stop_monitoring():
    state = _get_state()
    
    state.monitoring_active = False
    
    # Stop packet capture subprocess
    if hasattr(state, 'ids_capture_process') and state.ids_capture_process:
        try:
            logger.info("Terminating capture subprocess...")
            state.ids_capture_process.terminate()
            try:
                state.ids_capture_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                state.ids_capture_process.kill()
            state.ids_capture_process = None
            logger.info("Capture subprocess stopped")
        except Exception as e:
            logger.error(f"Error stopping capture subprocess: {e}")
            state.ids_capture_process = None
    
    # Legacy in-process fallback (backward compat)
    if hasattr(state, 'ids_capture_instance') and state.ids_capture_instance:
        try:
            state.ids_capture_instance.stop()
        except Exception:
            pass
        state.ids_capture_instance = None
    
    # Stop traffic generator
    if state.traffic_gen_process:
        try:
            logger.info("Stopping traffic generator...")
            state.traffic_gen_process.terminate()
            try:
                state.traffic_gen_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                state.traffic_gen_process.kill()
            state.traffic_gen_process = None
            logger.info("Traffic generator stopped")
        except Exception as e:
            logger.error(f"Error stopping traffic generator: {e}")
            state.traffic_gen_process = None
    
    state.publish_event_bus(
        _event_type('SYSTEM_MODULE_STOPPED'),
        severity=_severity('INFO'),
        module='Network Anomaly Detection',
        message='Network IDS monitoring stopped'
    )
    
    return jsonify({'status': 'stopped', 'message': 'Monitoring stopped'})


@network_ids_bp.route('/api/stats', methods=['GET'])
def get_stats():
    state = _get_state()
    return jsonify(state.stats)


@network_ids_bp.route('/api/recent', methods=['GET'])
def get_recent_predictions():
    state = _get_state()
    return jsonify(list(state.prediction_queue))


def _event_type(name):
    """Safely get EventType enum value."""
    try:
        from modules.event_bus.events import EventType
        return getattr(EventType, name)
    except Exception:
        return None


def _severity(name):
    """Safely get Severity enum value."""
    try:
        from modules.event_bus.events import Severity
        return getattr(Severity, name)
    except Exception:
        return None


logger.info("✅ Network IDS blueprint loaded")
