"""
Integration between your existing ensemble_anomaly_detector and the dashboard
"""
import sys
import os
import pandas as pd
import numpy as np
import streamlit as st

# Add the src directory to path to import your existing models
sys.path.append(os.path.join(os.path.dirname(__file__), '../../src'))

try:
    from models.ensemble_anomaly_detector import EnsembleAnomalyDetector
    ML_AVAILABLE = True
except ImportError as e:
    st.error(f"ML models not available: {e}")
    ML_AVAILABLE = False

class MLIntegration:
    def __init__(self):
        self.ml_model = None
        self.is_trained = False
        
    def initialize_model(self, contamination=0.05):
        """Initialize your existing ensemble model"""
        if not ML_AVAILABLE:
            st.warning("ML models not available - using synthetic risk scores")
            return False
            
        try:
            self.ml_model = EnsembleAnomalyDetector(
                contamination=contamination,
                random_state=42
            )
            return True
        except Exception as e:
            st.error(f"Failed to initialize ML model: {e}")
            return False
    
    def prepare_features(self, activity_data):
        """
        Prepare features from activity data for ML model
        This should match the feature engineering in your existing pipeline
        """
        features = []
        
        # Basic activity features (adjust based on your feature_engineering_ttp.py)
        if 'activity' in activity_data.columns:
            activity_dummies = pd.get_dummies(activity_data['activity'], prefix='activity')
            features.append(activity_dummies)
        
        # Temporal features
        if 'timestamp' in activity_data.columns:
            activity_data['timestamp'] = pd.to_datetime(activity_data['timestamp'])
            activity_data['hour'] = activity_data['timestamp'].dt.hour
            activity_data['day_of_week'] = activity_data['timestamp'].dt.dayofweek
            activity_data['is_weekend'] = activity_data['day_of_week'] >= 5
            activity_data['is_after_hours'] = (activity_data['hour'] < 6) | (activity_data['hour'] > 18)
            
            features.append(activity_data[['hour', 'day_of_week', 'is_weekend', 'is_after_hours']])
        
        # User behavior features (if available)
        user_metrics = activity_data.groupby('user').agg({
            'risk_score': ['count', 'mean', 'std']  # Basic metrics
        }).reset_index()
        
        user_metrics.columns = ['user', 'activity_count', 'avg_risk', 'risk_std']
        user_metrics = user_metrics.fillna(0)
        
        # Merge user metrics back
        activity_with_metrics = activity_data.merge(user_metrics, on='user', how='left')
        features.append(activity_with_metrics[['activity_count', 'avg_risk', 'risk_std']])
        
        # Combine all features
        if features:
            feature_df = pd.concat(features, axis=1)
            # Fill any NaN values
            feature_df = feature_df.fillna(0)
            return feature_df
        else:
            # Fallback to basic features
            return pd.DataFrame({
                'synthetic_feature_1': np.random.random(len(activity_data)),
                'synthetic_feature_2': np.random.random(len(activity_data))
            })
    
    def train_model(self, activity_data):
        """Train the ensemble model on historical data"""
        if not self.ml_model:
            st.error("ML model not initialized")
            return False
            
        try:
            features = self.prepare_features(activity_data)
            self.ml_model.fit(features)
            self.is_trained = True
            st.success("✅ ML model trained successfully")
            return True
        except Exception as e:
            st.error(f"Model training failed: {e}")
            return False
    
    def predict_risk_scores(self, activity_data):
        """Use your ensemble model to predict risk scores"""
        if not self.is_trained:
            st.warning("ML model not trained - using synthetic scores")
            return self._get_synthetic_scores(activity_data)
            
        try:
            features = self.prepare_features(activity_data)
            anomaly_scores = self.ml_model.predict_proba(features)
            
            # Convert anomaly scores (0-1) to risk scores (0-100)
            risk_scores = anomaly_scores * 100
            
            return risk_scores
        except Exception as e:
            st.error(f"Prediction failed: {e}")
            return self._get_synthetic_scores(activity_data)
    
    def _get_synthetic_scores(self, activity_data):
        """Fallback synthetic risk scoring"""
        # Your existing risk scoring logic or basic synthetic scores
        base_scores = np.random.uniform(0, 100, len(activity_data))
        
        # Enhance with some basic rules (similar to your existing logic)
        if 'activity' in activity_data.columns:
            high_risk_activities = ["Data Export", "USB Connection", "Database Query"]
            for i, activity in enumerate(activity_data['activity']):
                if activity in high_risk_activities:
                    base_scores[i] = min(base_scores[i] + 30, 100)
        
        return base_scores