# basic_detector.py
# Simple ML model to start with
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np

class ThreatDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
    
    def detect_anomalies(self, data):
        # Simple anomaly detection
        try:
            # Select only numeric columns for analysis
            numeric_columns = data.select_dtypes(include=[np.number]).columns
            if len(numeric_columns) == 0:
                return np.ones(len(data))  # Return all normal if no numeric data
                
            features = data[numeric_columns].fillna(0)
            predictions = self.model.fit_predict(features)
            return predictions
        except Exception as e:
            print(f"Anomaly detection error: {e}")
            return np.ones(len(data))  # Return all normal on error