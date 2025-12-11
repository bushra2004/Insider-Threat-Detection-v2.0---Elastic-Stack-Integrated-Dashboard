"""
Enhanced data loader that uses your existing data_integration.py
"""
import sys
import os
import pandas as pd
import numpy as np
import streamlit as st

class EnhancedDataLoader:
    def __init__(self):
        self.data_integration = None
        self.initialize_data_integration()

    def initialize_data_integration(self):
        """Initialize your existing data integration system"""
        try:
            # Add project root to path
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            sys.path.append(project_root)

            from data_integration import (
                load_sysmon_data,
                create_advanced_features,
                detect_anomalies,
                get_system_status,
                detect_tor_usage
            )
            self.data_integration = {
                'load_sysmon_data': load_sysmon_data,
                'create_advanced_features': create_advanced_features,
                'detect_anomalies': detect_anomalies,
                'get_system_status': get_system_status,
                'detect_tor_usage': detect_tor_usage 
            }
            st.success("✅ Enhanced data integration initialized")
            return True
        except ImportError as e:
            st.warning(f"Enhanced data integration not available: {e}")
            return False
        except Exception as e:
            st.error(f"Failed to initialize data integration: {e}")
            return False

    def load_enhanced_data(self):
        """Load data using your advanced data integration"""
        if not self.data_integration:
            st.warning("Using basic data loader - enhanced features unavailable")
            return self.load_basic_data()

        try:
            # Load Sysmon data using your existing function
            sysmon_data = self.data_integration['load_sysmon_data']()

            if not sysmon_data.empty:
                st.success(f"✅ Loaded {len(sysmon_data)} Sysmon events")

                # Apply advanced feature engineering 
                enhanced_data = self.data_integration['create_advanced_features'](sysmon_data)

                # Run anomaly detection
                final_data = self.data_integration['detect_anomalies'](enhanced_data)

                # Convert to dashboard format        
                dashboard_data = self.convert_to_dashboard_format(final_data)
                return dashboard_data
            else:
                st.warning("No Sysmon data found - using basic data")
                return self.load_basic_data()        

        except Exception as e:
            st.error(f"Enhanced data loading failed: {e}")
            return self.load_basic_data()

    def convert_to_dashboard_format(self, enhanced_data):
        """Convert your enhanced data to dashboard format"""
        dashboard_data = []

        for idx, row in enhanced_data.iterrows():    
            # Map your Sysmon data to dashboard format
            record = {
                'timestamp': row.get('UtcTime', pd.Timestamp.now()),
                'user': row.get('User', 'Unknown'),  
                'activity': self.map_event_to_activity(row),
                'risk_score': self.calculate_risk_score(row),
                'severity': self.get_severity_level(row),
                'department': 'IT',
                'location': 'Corporate Network',     
                'device': row.get('Hostname', 'Unknown'),
                'anomaly_score': row.get('anomaly_score', 0),
                'is_anomaly': row.get('anomaly_label', 1) == -1,
                'raw_event': row.to_dict()
            }
            dashboard_data.append(record)

        return pd.DataFrame(dashboard_data)

    def map_event_to_activity(self, event_row):      
        """Map Sysmon EventID to human-readable activity"""
        event_id = event_row.get('EventID')
        event_mapping = {
            1: "Process Creation",
            3: "Network Connection",
            5: "Process Terminated",
            7: "Image Loaded",
            8: "CreateRemoteThread",
            10: "Process Access",
            11: "File Created",
            12: "Registry Event",
            13: "Registry Value Set"
        }
        return event_mapping.get(event_id, f"Event {event_id}")

    def calculate_risk_score(self, event_row):       
        """Calculate risk score based on anomaly detection and event type"""
        base_score = 0

        # Start with anomaly score (0-1 scale, convert to 0-100)
        anomaly_score = event_row.get('anomaly_score', 0)
        base_score = anomaly_score * 100

        # Adjust based on event type
        event_id = event_row.get('EventID')
        high_risk_events = [8, 10]  # CreateRemoteThread, Process Access
        medium_risk_events = [1, 3, 7]  # Process Creation, Network, Image Load

        if event_id in high_risk_events:
            base_score = min(base_score + 40, 100)   
        elif event_id in medium_risk_events:
            base_score = min(base_score + 20, 100)   

        return base_score

    def get_severity_level(self, event_row):
        """Get severity level based on risk score""" 
        risk_score = self.calculate_risk_score(event_row)
        if risk_score >= 80:
            return "High"
        elif risk_score >= 50:
            return "Medium"
        else:
            return "Low"

    def load_basic_data(self):
        """Fallback to basic data loading"""
        try:
            from .data_loader import DataLoader      
            basic_loader = DataLoader()
            real_data = basic_loader.load_sysmon_data()
            if real_data is not None:
                return real_data
        except:
            pass

        # Ultimate fallback - synthetic data
        try:
            from InsiderThreatDataGenerator import InsiderThreatDataGenerator
            generator = InsiderThreatDataGenerator()     
            return generator.generate_activity_data()
        except:
            # Create simple synthetic data as last resort
            return pd.DataFrame({
                'timestamp': [pd.Timestamp.now()],
                'user': ['fallback_user'],
                'activity': ['Fallback Activity'],
                'risk_score': [50],
                'severity': ['Medium']
            })

    def get_system_metrics(self):
        """Get system metrics using your existing function"""
        if self.data_integration:
            return self.data_integration['get_system_status']()
        return {"status": "Unknown", "message": "Data integration not available"}

    def get_tor_detection(self):
        """Get Tor usage detection"""
        if self.data_integration:
            return self.data_integration['detect_tor_usage']()
        return []