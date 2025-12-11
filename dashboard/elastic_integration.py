"""
Quick Elasticsearch Integration for Insider Threat Detection
"""
from elasticsearch import Elasticsearch, helpers
import pandas as pd
from datetime import datetime
import json
import os

class QuickElasticIntegration:
    """Minimal Elasticsearch integration for industry-ready demo"""
    
    def __init__(self, hosts=['http://localhost:9200']):
        self.es = Elasticsearch(hosts)
        self.index_name = "insider-threat-realtime"
        
    def setup_index(self):
        """Create index with minimal settings"""
        if not self.es.indices.exists(index=self.index_name):
            mapping = {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                },
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "user": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "severity": {"type": "integer"},
                        "department": {"type": "keyword"},
                        "risk_score": {"type": "float"},
                        "anomaly_detected": {"type": "boolean"},
                        "source": {"type": "keyword"}
                    }
                }
            }
            self.es.indices.create(index=self.index_name, body=mapping)
        return True
    
    def ingest_sample_data(self, num_records=10):
        """Ingest sample threat data"""
        import random
        import string
        
        departments = ["IT", "HR", "Finance", "Engineering", "Sales"]
        actions = ["login", "file_download", "data_export", "admin_access", "after_hours_access"]
        
        records = []
        for i in range(num_records):
            user = f"user{random.randint(100, 999)}@company.com"
            record = {
                "timestamp": datetime.now().isoformat(),
                "user": user,
                "action": random.choice(actions),
                "severity": random.randint(1, 10),
                "department": random.choice(departments),
                "risk_score": round(random.uniform(0.1, 0.99), 2),
                "anomaly_detected": random.random() > 0.7,
                "source": "sample_data"
            }
            records.append(record)
        
        # Bulk ingest
        actions = [
            {
                "_index": self.index_name,
                "_source": record
            }
            for record in records
        ]
        
        helpers.bulk(self.es, actions)
        print(f"✅ Ingested {num_records} sample records")
        return records
    
    def get_threat_summary(self):
        """Get summary statistics"""
        try:
            # Count total documents
            count = self.es.count(index=self.index_name)['count']
            
            # Average severity
            query = {
                "aggs": {
                    "avg_severity": {"avg": {"field": "severity"}},
                    "by_department": {
                        "terms": {"field": "department.keyword"}
                    }
                }
            }
            
            result = self.es.search(index=self.index_name, body=query, size=0)
            
            summary = {
                "total_threats": count,
                "avg_severity": result['aggregations']['avg_severity']['value'],
                "departments": [
                    {"dept": bucket['key'], "count": bucket['doc_count']}
                    for bucket in result['aggregations']['by_department']['buckets']
                ]
            }
            
            return summary
        except Exception as e:
            return {"error": str(e)}

def quick_test():
    """Quick test function"""
    print("🧪 Testing Elasticsearch Integration...")
    
    integrator = QuickElasticIntegration()
    
    # Test connection
    if integrator.es.ping():
        print("✅ Connected to Elasticsearch")
        
        # Setup index
        integrator.setup_index()
        print("✅ Index configured")
        
        # Get current count
        count = integrator.es.count(index=integrator.index_name)['count']
        print(f"📊 Current documents: {count}")
        
        # Ingest sample if empty
        if count < 5:
            integrator.ingest_sample_data(5)
        
        # Get summary
        summary = integrator.get_threat_summary()
        print(f"📈 Threat Summary: {summary}")
        
    else:
        print("❌ Cannot connect to Elasticsearch")
        print("Make sure Elasticsearch is running on localhost:9200")

if __name__ == "__main__":
    quick_test()
