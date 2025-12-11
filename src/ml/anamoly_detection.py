import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
import joblib
from datetime import datetime, timedelta

class AdvancedAnomalyDetection:
    def __init__(self):
        self.models = {}
        self.features = [
            'login_frequency', 'after_hours_activity', 'data_access_count',
            'failed_logins', 'file_downloads', 'network_connections'
        ]
    
    def train_behavioral_baseline(self, company_id, historical_data):
        """Train behavioral baseline for anomaly detection"""
        # Isolation Forest for anomaly detection
        iso_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        features = historical_data[self.features]
        iso_forest.fit(features)
        
        # Save model
        model_path = f"models/{company_id}_behavioral_model.pkl"
        joblib.dump(iso_forest, model_path)
        self.models[company_id] = iso_forest
        
        return True
    
    def detect_anomalies(self, company_id, current_activity):
        """Detect behavioral anomalies"""
        if company_id not in self.models:
            return []
        
        model = self.models[company_id]
        features = current_activity[self.features]
        
        # Predict anomalies (-1 for anomalies, 1 for normal)
        predictions = model.predict(features)
        anomaly_scores = model.decision_function(features)
        
        # Return anomalies with scores
        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            if pred == -1:
                anomalies.append({
                    'user_id': current_activity.iloc[i]['user_id'],
                    'anomaly_score': abs(score),
                    'timestamp': datetime.now(),
                    'features': current_activity.iloc[i][self.features].to_dict()
                })
        
        return anomalies

class UEBAEngine:
    """User Entity Behavior Analytics"""
    def __init__(self):
        self.behavior_profiles = {}
    
    def analyze_user_behavior(self, user_events):
        """Analyze user behavior patterns"""
        # Calculate behavioral metrics
        metrics = {
            'login_pattern': self._analyze_login_pattern(user_events),
            'access_pattern': self._analyze_access_pattern(user_events),
            'data_flow': self._analyze_data_flow(user_events),
            'peer_comparison': self._compare_with_peers(user_events)
        }
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(metrics)
        
        return {
            'metrics': metrics,
            'risk_score': risk_score,
            'anomalies': self._detect_behavioral_anomalies(metrics)
        }