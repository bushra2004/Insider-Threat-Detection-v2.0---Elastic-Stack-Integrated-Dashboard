import pandas as pd
import numpy as np
import requests
import time
from datetime import datetime
import logging

class TorMonitor:
    def __init__(self):
        self.tor_exit_nodes = []
        self.last_update = None
        self.logger = logging.getLogger('TorMonitor')
        
    def update_exit_nodes(self):
        """Update list of Tor exit nodes"""
        try:
            response = requests.get('https://check.torproject.org/torbulkexitlist', timeout=30)
            if response.status_code == 200:
                self.tor_exit_nodes = response.text.strip().split('\n')
                self.last_update = datetime.now()
                self.logger.info(f"Updated Tor exit nodes list: {len(self.tor_exit_nodes)} nodes")
                return True
        except Exception as e:
            self.logger.error(f"Failed to update Tor exit nodes: {e}")
        return False
    
    def check_ip(self, ip_address):
        """Check if IP is a Tor exit node"""
        if not self.tor_exit_nodes or (datetime.now() - self.last_update).days > 1:
            self.update_exit_nodes()
        
        return ip_address in self.tor_exit_nodes
    
    def analyze_network_traffic(self, network_data):
        """Analyze network traffic for Tor usage"""
        if network_data.empty:
            return pd.DataFrame()
        
        # Add Tor detection columns
        network_data['is_tor_exit'] = network_data['source_ip'].apply(self.check_ip)
        network_data['is_tor_destination'] = network_data['dest_ip'].apply(self.check_ip)
        
        # Detect Tor-related ports
        tor_ports = [9001, 9030, 9050, 9051, 9150]
        network_data['is_tor_port'] = network_data['dest_port'].isin(tor_ports) | network_data['source_port'].isin(tor_ports)
        
        return network_data
    
    def generate_tor_report(self, network_data, log_data):
        """Generate comprehensive Tor usage report"""
        report = {
            'timestamp': datetime.now(),
            'tor_traffic_detected': False,
            'exit_nodes_contacted': [],
            'tor_ports_used': [],
            'suspicious_activity': []
        }
        
        # Analyze network data
        tor_analysis = self.analyze_network_traffic(network_data)
        
        if not tor_analysis.empty:
            tor_traffic = tor_analysis[tor_analysis['is_tor_exit'] | 
                                      tor_analysis['is_tor_destination'] | 
                                      tor_analysis['is_tor_port']]
            
            if not tor_traffic.empty:
                report['tor_traffic_detected'] = True
                report['exit_nodes_contacted'] = tor_traffic['dest_ip'].unique().tolist()
                report['tor_ports_used'] = tor_traffic['dest_port'].unique().tolist()
        
        # Analyze log data for Tor-related activity
        if not log_data.empty:
            tor_keywords = ['tor', '.onion', 'exit-node', 'relay', 'bridge']
            tor_logs = log_data[log_data['message'].str.contains('|'.join(tor_keywords), case=False, na=False)]
            
            if not tor_logs.empty:
                report['suspicious_activity'] = tor_logs.to_dict('records')
        
        return report

# Singleton instance
tor_monitor = TorMonitor()