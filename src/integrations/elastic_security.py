# src/integrations/elastic_security.py
from elasticsearch import Elasticsearch
import pandas as pd
from datetime import datetime, timedelta

class ElasticSecurityClient:
    """Elastic Security SIEM Integration"""
    
    def __init__(self, host="localhost", port=9200):
        self.es = Elasticsearch([f"{host}:{port}"])
    
    def get_security_alerts(self, hours=24):
        """Get security alerts from Elastic Security"""
        try:
            # Query for security alerts
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                            {"term": {"event.category": "intrusion_detection"}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 1000
            }
            
            response = self.es.search(index="logs-*", body=query)
            
            alerts = []
            for hit in response['hits']['hits']:
                source = hit['_source']
                
                alert = {
                    'timestamp': source.get('@timestamp'),
                    'rule_name': source.get('rule', {}).get('name'),
                    'rule_description': source.get('rule', {}).get('description'),
                    'severity': source.get('event', {}).get('severity'),
                    'user': source.get('user', {}).get('name'),
                    'source_ip': source.get('source', {}).get('ip'),
                    'destination_ip': source.get('destination', {}).get('ip'),
                    'action': source.get('event', {}).get('action'),
                    'log_source': 'elastic_security'
                }
                
                # Map Elastic severity to our format
                severity_map = {
                    'low': 'Low', 'medium': 'Medium', 
                    'high': 'High', 'critical': 'Critical'
                }
                alert['severity_label'] = severity_map.get(alert['severity'].lower(), 'Low')
                
                # Calculate risk score
                risk_map = {'low': 30, 'medium': 50, 'high': 75, 'critical': 90}
                alert['risk_score'] = risk_map.get(alert['severity'].lower(), 30)
                
                alerts.append(alert)
            
            return pd.DataFrame(alerts)
            
        except Exception as e:
            print(f"Elastic Security error: {e}")
            return pd.DataFrame()