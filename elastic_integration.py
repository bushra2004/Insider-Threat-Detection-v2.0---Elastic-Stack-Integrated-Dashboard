
from elasticsearch import Elasticsearch, helpers
import json
from datetime import datetime
import pandas as pd

class QuickElasticIntegration:
    def __init__(self):
        self.es = Elasticsearch(['http://localhost:9200'])
        self.index = "insider-threat-realtime"
        
    def setup_index(self):
        """Quick index setup"""
        if not self.es.indices.exists(index=self.index):
            self.es.indices.create(index=self.index, ignore=400)
        print(f"Index ready: {self.index}")
    
    def ingest_from_csv(self, csv_file="sysmon_users.csv"):
        """Quick data ingestion"""
        df = pd.read_csv(csv_file)
        records = df.to_dict('records')
        
        actions = []
        for i, record in enumerate(records):
            # Add timestamp and enrich
            record['timestamp'] = datetime.now().isoformat()
            record['ingested_at'] = datetime.now().isoformat()
            record['source'] = 'sysmon'
            
            actions.append({
                "_index": self.index,
                "_source": record
            })
        
        helpers.bulk(self.es, actions)
        print(f"Ingested {len(actions)} records to Elasticsearch")
        return True
    
    def create_kibana_dashboard(self):
        """Export Kibana dashboard config"""
        dashboard_config = {
            "title": "Insider Threat Dashboard",
            "visualizations": [
                {
                    "type": "metric",
                    "title": "Total Threats Detected",
                    "metricField": "severity"
                },
                {
                    "type": "pie",
                    "title": "Threats by Department",
                    "splitField": "department"
                }
            ]
        }
        
        with open("kibana_dashboard.json", "w") as f:
            json.dump(dashboard_config, f, indent=2)
        print("Kibana dashboard config saved")

# Quick usage
if __name__ == "__main__":
    integrator = QuickElasticIntegration()
    integrator.setup_index()
    integrator.ingest_from_csv()