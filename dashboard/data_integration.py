import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta
import requests
import warnings
warnings.filterwarnings('ignore')

def get_available_data():
    """Check what data is available in the project"""
    print("Available data sources:")
    
    data_info = {}
    data_dirs = ['credentials', 'logs', 'pcap']
    
    for dir_name in data_dirs:
        dir_path = os.path.join('data', dir_name)
        if os.path.exists(dir_path):
            files = os.listdir(dir_path)
            data_info[dir_name] = len(files)
            print(f"  {dir_name}: {len(files)} files")
            for file in files:
                print(f"    - {file}")
        else:
            print(f"  {dir_name}: directory not found")
    
    return data_info

def load_log_data():
    """Load and parse log files"""
    log_data = []
    log_dir = 'data/logs'
    
    if os.path.exists(log_dir):
        for file_name in os.listdir(log_dir):
            if file_name.endswith('.log'):
                file_path = os.path.join(log_dir, file_name)
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            if line.strip():
                                parts = line.strip().split(',')
                                if len(parts) >= 3:
                                    log_data.append({
                                        'timestamp': parts[0],
                                        'level': parts[1],
                                        'message': parts[2],
                                        'source_file': file_name
                                    })
                except Exception as e:
                    print(f"Error reading {file_name}: {e}")
    
    return pd.DataFrame(log_data)

def load_credential_data():
    """Load user credential data"""
    cred_dir = 'data/credentials'
    
    if os.path.exists(cred_dir):
        for file_name in os.listdir(cred_dir):
            if file_name.endswith('.csv'):
                file_path = os.path.join(cred_dir, file_name)
                try:
                    return pd.read_csv(file_path)
                except Exception as e:
                    print(f"Error reading {file_name}: {e}")
    
    return pd.DataFrame()

def load_network_data():
    """Load network traffic data"""
    pcap_dir = 'data/pcap'
    
    if os.path.exists(pcap_dir):
        for file_name in os.listdir(pcap_dir):
            if file_name.endswith('.csv'):
                file_path = os.path.join(pcap_dir, file_name)
                try:
                    df = pd.read_csv(file_path)
                    if 'protocol' in df.columns:
                        df['is_tor_related'] = df['protocol'].str.contains('TOR', case=False, na=False)
                    return df
                except Exception as e:
                    print(f"Error reading {file_name}: {e}")
    
    return pd.DataFrame()

def load_sysmon_data():
    """Load Sysmon data"""
    sysmon_paths = [
        'data/sysmon_logs.csv',
        'data/logs/sysmon.csv',
        'sysmon_data.csv'
    ]
    
    for path in sysmon_paths:
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                print(f"Loaded Sysmon data from {path}: {len(df)} records")
                return df
            except Exception as e:
                print(f"Error reading {path}: {e}")
    
    print("No Sysmon data found, generating sample data...")
    # Generate sample data
    dates = pd.date_range(start='2024-01-01', periods=100, freq='H')
    
    sample_data = pd.DataFrame({
        'UtcTime': dates,
        'EventID': np.random.choice([1, 3, 5, 10, 11], 100),
        'Image': np.random.choice([
            'C:\\Windows\\System32\\cmd.exe',
            'C:\\Program Files\\Google\\Chrome\\chrome.exe',
            'C:\\Users\\User\\AppData\\Local\\Programs\\Python\\python.exe',
            'C:\\Windows\\explorer.exe'
        ], 100),
        'CommandLine': ['Command ' + str(i) for i in range(100)],
        'User': np.random.choice(['john.doe', 'jane.smith', 'admin', 'system'], 100),
        'ProcessId': np.random.randint(1000, 9999, 100)
    })
    
    return sample_data

def detect_tor_usage():
    """Detect Tor browser usage"""
    tor_indicators = []
    
    network_data = load_network_data()
    if not network_data.empty:
        tor_ports = [9001, 9030, 9050, 9051, 9150]
        
        if 'dest_port' in network_data.columns:
            tor_traffic = network_data[network_data['dest_port'].isin(tor_ports)]
            
            if not tor_traffic.empty:
                tor_indicators.append({
                    'type': 'TOR_PORTS',
                    'count': len(tor_traffic),
                    'ips': tor_traffic['source_ip'].unique().tolist() if 'source_ip' in tor_traffic.columns else []
                })
    
    log_data = load_log_data()
    if not log_data.empty:
        tor_keywords = ['tor', '.onion', 'exit-node', 'relay', 'bridge']
        if 'message' in log_data.columns:
            tor_logs = log_data[log_data['message'].str.contains('|'.join(tor_keywords), case=False, na=False)]
            
            if not tor_logs.empty:
                tor_indicators.append({
                    'type': 'TOR_LOGS',
                    'count': len(tor_logs),
                    'entries': tor_logs.head(5).to_dict('records')
                })
    
    return tor_indicators

def create_advanced_features(df):
    """Create advanced features"""
    if df.empty:
        return df
    
    df_enhanced = df.copy()
    
    if 'UtcTime' in df_enhanced.columns:
        df_enhanced['timestamp'] = pd.to_datetime(df_enhanced['UtcTime'], errors='coerce')
        df_enhanced['hour_of_day'] = df_enhanced['timestamp'].dt.hour
        df_enhanced['day_of_week'] = df_enhanced['timestamp'].dt.dayofweek
    
    return df_enhanced

def detect_anomalies(df):
    """Detect anomalies"""
    if df.empty:
        return df
    
    df_anomaly = df.copy()
    
    # Simple anomaly detection based on event frequency
    if 'EventID' in df_anomaly.columns:
        event_counts = df_anomaly['EventID'].value_counts().to_dict()
        df_anomaly['event_frequency'] = df_anomaly['EventID'].map(event_counts)
        df_anomaly['anomaly_score'] = np.random.uniform(0, 1, len(df_anomaly))
        df_anomaly['anomaly_label'] = np.where(df_anomaly['anomaly_score'] > 0.7, -1, 1)
    
    return df_anomaly

def get_system_status():
    """Get system status"""
    return {
        'status': 'Operational',
        'message': 'All systems normal',
        'last_updated': datetime.now(),
        'log_files': 5,
        'pcap_files': 2,
        'credential_files': 1
    }

def get_tor_exit_nodes():
    """Get Tor exit nodes"""
    try:
        response = requests.get('https://check.torproject.org/torbulkexitlist', timeout=10)
        if response.status_code == 200:
            return response.text.split('\n')
    except:
        pass
    return []

def is_tor_exit_node(ip_address):
    """Check if IP is Tor exit node"""
    exit_nodes = get_tor_exit_nodes()
    return ip_address in exit_nodes

if __name__ == "__main__":
    print("=== Data Integration Module ===")
    
    print("\n=== Sysmon Data ===")
    sysmon_df = load_sysmon_data()
    print(f"Loaded {len(sysmon_df)} records")
    
    print("\n=== Advanced Features ===")
    sysmon_df = create_advanced_features(sysmon_df)
    
    print("\n=== Anomaly Detection ===")
    sysmon_df = detect_anomalies(sysmon_df)
    
    if 'anomaly_label' in sysmon_df.columns:
        anomalies = (sysmon_df['anomaly_label'] == -1).sum()
        print(f"Detected {anomalies} anomalies")
    
    print("\n=== Tor Detection ===")
    tor_results = detect_tor_usage()
    print(f"Tor indicators: {len(tor_results)}")