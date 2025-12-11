"""
ELK Stack Integration for Streamlit Dashboard
"""
import requests
import pandas as pd
import streamlit as st
from datetime import datetime, timedelta
import json

class ELKIntegration:
    def __init__(self, elasticsearch_host="http://localhost:9200", kibana_host="http://localhost:5601"):
        self.es_host = elasticsearch_host
        self.kibana_host = kibana_host
        self.index_pattern = "insider-threat-*"
        
    def check_elasticsearch_connection(self):
        """Check if Elasticsearch is running"""
        try:
            response = requests.get(f"{self.es_host}/_cluster/health", timeout=5)
            if response.status_code == 200:
                return True, "✅ Elasticsearch connected"
            else:
                return False, f"❌ Elasticsearch error: {response.text}"
        except Exception as e:
            return False, f"❌ Cannot connect to Elasticsearch: {e}"
    
    def search_threats(self, query=None, size=100):
        """Search for threats in Elasticsearch"""
        try:
            if query is None:
                query = {
                    "query": {
                        "match_all": {}
                    },
                    "sort": [
                        {
                            "timestamp": {
                                "order": "desc"
                            }
                        }
                    ],
                    "size": size
                }
            
            response = requests.post(
                f"{self.es_host}/{self.index_pattern}/_search",
                json=query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                hits = response.json()['hits']['hits']
                data = [hit['_source'] for hit in hits]
                return pd.DataFrame(data)
            else:
                st.error(f"Search failed: {response.text}")
                return pd.DataFrame()
                
        except Exception as e:
            st.error(f"Search error: {e}")
            return pd.DataFrame()
    
    def get_high_risk_events(self, threshold=70):
        """Get high risk events from Elasticsearch"""
        query = {
            "query": {
                "range": {
                    "risk_score": {
                        "gte": threshold
                    }
                }
            },
            "sort": [
                {
                    "risk_score": {
                        "order": "desc"
                    }
                }
            ],
            "size": 50
        }
        return self.search_threats(query)
    
    def get_threat_statistics(self):
        """Get threat statistics from Elasticsearch"""
        try:
            query = {
                "size": 0,
                "aggs": {
                    "severity_distribution": {
                        "terms": {
                            "field": "severity.keyword",
                            "size": 10
                        }
                    },
                    "risk_score_stats": {
                        "stats": {
                            "field": "risk_score"
                        }
                    },
                    "top_users": {
                        "terms": {
                            "field": "user.keyword",
                            "size": 10
                        }
                    }
                }
            }
            
            response = requests.post(
                f"{self.es_host}/{self.index_pattern}/_search",
                json=query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()['aggregations']
            else:
                return {}
                
        except Exception as e:
            st.error(f"Statistics error: {e}")
            return {}
    
    def create_kibana_dashboard_link(self):
        """Generate Kibana dashboard link"""
        return f"{self.kibana_host}/app/dashboards"
    
    def get_real_time_alerts(self):
        """Get real-time alerts from Elasticsearch"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "risk_score": {
                                    "gte": 70
                                }
                            }
                        },
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now-1h"
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [
                {
                    "timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "size": 20
        }
        return self.search_threats(query)
    
    def send_data_to_elasticsearch(self, data):
        """Send data from Streamlit to Elasticsearch"""
        try:
            if isinstance(data, pd.DataFrame):
                data = data.to_dict('records')
            
            for record in data:
                response = requests.post(
                    f"{self.es_host}/insider-threat-logs/_doc",
                    json=record,
                    headers={'Content-Type': 'application/json'}
                )
                if response.status_code not in [200, 201]:
                    st.error(f"Failed to send data: {response.text}")
            
            st.success(f"✅ Sent {len(data)} records to Elasticsearch")
            return True
        except Exception as e:
            st.error(f"Error sending data to Elasticsearch: {e}")
            return False

def create_elk_dashboard_tab():
    """Create ELK-specific dashboard tab"""
    st.subheader("🐘 ELK Stack Integration")
    
    elk = ELKIntegration()
    
    # Connection status
    col1, col2, col3 = st.columns(3)
    
    with col1:
        connected, message = elk.check_elasticsearch_connection()
        if connected:
            st.success(message)
        else:
            st.warning(message)
            st.info("To use ELK features, start Elasticsearch first:")
            st.code("docker-compose -f elk/docker-compose.elk.yml up -d")
    
    with col2:
        if connected:
            stats = elk.get_threat_statistics()
            if stats and 'severity_distribution' in stats:
                total_events = sum([bucket['doc_count'] for bucket in stats['severity_distribution']['buckets']])
                st.metric("Events in ELK", total_events)
            else:
                st.metric("Events in ELK", 0)
    
    with col3:
        if connected:
            kibana_link = elk.create_kibana_dashboard_link()
            st.markdown(f"[📊 Open Kibana]({kibana_link})", unsafe_allow_html=True)
    
    if connected:
        # Real-time alerts
        st.subheader("🚨 ELK Real-time Alerts")
        alerts = elk.get_real_time_alerts()
        if not alerts.empty:
            for _, alert in alerts.head(5).iterrows():
                severity = alert.get('severity', 'Low')
                severity_color = {
                    "Critical": "#ff4444",
                    "High": "#ffaa00", 
                    "Medium": "#ffdd00",
                    "Low": "#44ff44"
                }.get(severity, '#888888')
                
                st.markdown(f"""
                <div style="border-left: 4px solid {severity_color}; padding: 10px; margin: 5px 0; background-color: #f8f9fa; border-radius: 4px;">
                    <strong>{severity} Risk Event</strong><br>
                    User: {alert.get('user', 'Unknown')} | 
                    Score: {alert.get('risk_score', 0)} | 
                    Time: {alert.get('timestamp', 'Unknown')}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No recent high-risk alerts in ELK")
        
        # Threat statistics
        st.subheader("📈 ELK Threat Intelligence")
        stats = elk.get_threat_statistics()
        
        if stats:
            col1, col2 = st.columns(2)
            
            with col1:
                severity_data = stats.get('severity_distribution', {}).get('buckets', [])
                if severity_data:
                    severity_df = pd.DataFrame(severity_data)
                    fig = px.pie(
                        severity_df, 
                        values='doc_count', 
                        names='key',
                        title='Threat Severity Distribution (ELK)',
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No severity data in ELK")
            
            with col2:
                risk_stats = stats.get('risk_score_stats', {})
                if risk_stats:
                    col2a, col2b, col2c = st.columns(3)
                    with col2a:
                        st.metric("Avg Risk", f"{risk_stats.get('avg', 0):.1f}")
                    with col2b:
                        st.metric("Max Risk", f"{risk_stats.get('max', 0):.1f}")
                    with col2c:
                        st.metric("Total Events", risk_stats.get('count', 0))
                else:
                    st.info("No risk statistics in ELK")
        
        # Data export to ELK
        st.subheader("📤 Export to ELK")
        if st.button("Export Current Data to Elasticsearch"):
            if 'data' in st.session_state:
                success = elk.send_data_to_elasticsearch(st.session_state.data)
                if success:
                    st.success("Data exported to ELK successfully!")
            else:
                st.warning("No data available to export")
    
    else:
        # ELK setup instructions
        st.subheader("🚀 ELK Stack Setup Instructions")
        
        st.markdown("""
        ### To enable ELK features:
        
        1. **Install Docker Desktop** on your Windows machine
        2. **Create ELK directory** in your project:
        ```bash
        mkdir elk
        ```
        3. **Create docker-compose.elk.yml** in the elk directory
        4. **Start ELK stack**:
        ```bash
        cd elk
        docker-compose up -d
        ```
        5. **Access services**:
           - Kibana: http://localhost:5601
           - Elasticsearch: http://localhost:9200
        
        ### Benefits of ELK Integration:
        - ✅ **Real-time data processing**
        - ✅ **Advanced search capabilities**  
        - ✅ **Historical data retention**
        - ✅ **Kibana visualizations**
        - ✅ **Enterprise scalability**
        """)
        
        with st.expander("View docker-compose.elk.yml content"):
            st.code("""
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.9.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - elastic_data:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.9.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  elastic_data:
""", language="yaml")

def elk_available():
    """Check if ELK integration is available"""
    try:
        elk = ELKIntegration()
        connected, _ = elk.check_elasticsearch_connection()
        return connected
    except:
        return False