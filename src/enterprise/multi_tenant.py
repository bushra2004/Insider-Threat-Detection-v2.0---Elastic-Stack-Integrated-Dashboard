from elasticsearch import Elasticsearch
import psycopg2
from datetime import datetime

class MultiTenantManager:
    def __init__(self):
        self.es = Elasticsearch(['http://localhost:9200'])
        self.companies = {}
    
    def register_company(self, company_data):
        """Register new company with isolated data"""
        company_id = self._generate_company_id(company_data['name'])
        
        # Create company-specific indices
        self._create_company_indices(company_id)
        
        # Store company config
        self.companies[company_id] = {
            'name': company_data['name'],
            'config': company_data.get('config', {}),
            'indices': {
                'threat_events': f"threat-events-{company_id}",
                'user_behavior': f"user-behavior-{company_id}",
                'audit_logs': f"audit-logs-{company_id}"
            },
            'created_at': datetime.now()
        }
        return company_id
    
    def _create_company_indices(self, company_id):
        """Create Elasticsearch indices for company"""
        indices = [
            f"threat-events-{company_id}",
            f"user-behavior-{company_id}", 
            f"audit-logs-{company_id}"
        ]
        
        for index in indices:
            if not self.es.indices.exists(index=index):
                mapping = {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "company_id": {"type": "keyword"},
                            "user_id": {"type": "keyword"},
                            "event_type": {"type": "keyword"},
                            "risk_score": {"type": "integer"},
                            "description": {"type": "text"}
                        }
                    }
                }
                self.es.indices.create(index=index, body=mapping)
    
    def get_company_data(self, company_id, query):
        """Get data for specific company"""
        index = self.companies[company_id]['indices']['threat_events']
        query['query']['bool']['must'].append({
            "term": {"company_id": company_id}
        })
        return self.es.search(index=index, body=query)