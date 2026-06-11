"""
ML Engine for anomaly detection using Isolation Forest
Trains on login hour patterns and detects anomalies
"""
import pandas as pd
import pickle
import os
from sklearn.ensemble import IsolationForest
from config import MODEL_PATH, BASELINE_DATA
from logger import get_logger

log = get_logger("ml_engine")


def train():
    """
    Train ML model on baseline data or load pre-trained model.
    
    Returns:
        model: Trained IsolationForest model for anomaly detection
    """
    try:
        # Try to load existing model
        if os.path.exists(MODEL_PATH):
            log.info(f"Loading pre-trained model from {MODEL_PATH}")
            with open(MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            return model
        
        # Train new model if doesn't exist
        log.info(f"Training new model from baseline data: {BASELINE_DATA}")
        if not os.path.exists(BASELINE_DATA):
            log.error(f"Baseline data not found at {BASELINE_DATA}")
            raise FileNotFoundError(f"Baseline data not found at {BASELINE_DATA}")
        
        df = pd.read_csv(BASELINE_DATA)
        df['hour'] = pd.to_datetime(df['time']).dt.hour
        
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(df[['hour']])
        
        # Save model for future use
        os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(model, f)
        log.info(f"Model trained and saved to {MODEL_PATH}")
        
        return model
    except Exception as e:
        log.error(f"Error training model: {str(e)}")
        raise


def detect(model, hour):
    """
    Detect if the given hour is anomalous based on trained model.
    
    Args:
        model: Trained IsolationForest model
        hour: Hour of the day (0-23)
    
    Returns:
        int: -1 if anomaly detected, 1 if normal
    """
    try:
        if not isinstance(hour, int) or hour < 0 or hour > 23:
            log.warning(f"Invalid hour value: {hour}")
            return 1  # Return normal if invalid
        
        df = pd.DataFrame([[hour]], columns=["hour"])
        prediction = model.predict(df)[0]
        
        if prediction == -1:
            log.warning(f"Anomaly detected at hour {hour}")
        
        return prediction
    except Exception as e:
        log.error(f"Error detecting anomaly: {str(e)}")
        return 1  # Return normal if error occurs