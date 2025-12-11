"""
Data loader for the dashboard - FIXED VERSION
"""
import sys
import os
import pandas as pd
import numpy as np
import streamlit as st

class DataLoader:  # CHANGED FROM EnhancedDataLoader to DataLoader
    def __init__(self):
        self.data_sources = {
            'sysmon': 'data/logs/sysmon_logs.csv',
            'combined': 'data/logs/combined_logs.csv', 
            'processed': 'data/processed.csv'
        }
    
    def load_sysmon_data(self):
        """Load Sysmon data - SIMPLE VERSION"""
        try:
            file_path = self.data_sources['sysmon']
            if os.path.exists(file_path):
                df = pd.read_csv(file_path)
                st.success(f"✅ Loaded {len(df)} Sysmon records")
                return df
            else:
                st.warning(f"Sysmon data not found at {file_path}")
                return None
        except Exception as e:
            st.error(f"Error loading Sysmon data: {e}")
            return None
    
    def load_processed_data(self):
        """Load processed data"""
        try:
            file_path = self.data_sources['processed']
            if os.path.exists(file_path):
                df = pd.read_csv(file_path)
                st.success(f"✅ Loaded {len(df)} processed records")
                return df
            else:
                st.warning("Processed data not found")
                return None
        except Exception as e:
            st.error(f"Error loading processed data: {e}")
            return None

# Keep the helper functions
def safe_read_csv(file_path):
    """Safely read CSV file with error handling"""
    try:
        if os.path.exists(file_path):
            return pd.read_csv(file_path)
        return None
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def diagnose_csv_file(file_path):
    """Diagnose CSV file issues"""
    if not os.path.exists(file_path):
        return f"File not found: {file_path}"
    
    try:
        df = pd.read_csv(file_path)
        return f"File OK: {len(df)} rows, {len(df.columns)} columns"
    except Exception as e:
        return f"Error: {e}"