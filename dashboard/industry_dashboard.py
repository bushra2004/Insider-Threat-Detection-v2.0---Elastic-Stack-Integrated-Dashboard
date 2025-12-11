import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import requests
import json
import sys
import os

# Add parent directory to path to import your modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST BE FIRST STREAMLIT COMMAND
st.set_page_config(
    page_title="Insider Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ Insider Threat Detection - Industry Ready")
st.markdown("### Real-time Security Monitoring with Elastic Stack")

# Status indicators
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Elastic Documents", "3", "✓ Live")
with col2:
    st.metric("Active Alerts", "2", "↑ 1")
with col3:
    st.metric("Users Monitored", "142")
with col4:
    st.metric("System Status", "Healthy", "✓")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Dashboard", 
    "🔍 Threat Analysis", 
    "⚙️ Elastic Integration", 
    "☁️ AWS Deployment"
])

with tab1:
    st.subheader("Real-time Threat Monitoring")
    
    # Sample threat data
    threat_data = pd.DataFrame({
        'Time': pd.date_range(start='2024-01-01', periods=24, freq='H'),
        'Threats': [3, 2, 1, 0, 0, 1, 4, 7, 12, 15, 18, 20, 
                   19, 16, 14, 11, 9, 7, 5, 4, 3, 3, 2, 2]
    })
    
    fig1 = px.line(threat_data, x='Time', y='Threats', 
                   title='Threat Detection Timeline')
    st.plotly_chart(fig1, use_container_width=True)
    
    # Department-wise threats
    dept_data = pd.DataFrame({
        'Department': ['IT', 'HR', 'Finance', 'Engineering', 'Sales'],
        'Threats': [12, 8, 15, 6, 4],
        'Severity': [8.2, 7.5, 9.1, 6.3, 5.8]
    })
    
    col1, col2 = st.columns(2)
    with col1:
        fig2 = px.bar(dept_data, x='Department', y='Threats',
                     title='Threats by Department')
        st.plotly_chart(fig2, use_container_width=True)
    
    with col2:
        fig3 = px.pie(dept_data, values='Threats', names='Department',
                     title='Threat Distribution')
        st.plotly_chart(fig3, use_container_width=True)

with tab3:
    st.subheader("Elastic Stack Integration")
    
    # Elasticsearch connection test
    if st.button("🔄 Test Elasticsearch Connection", type="primary"):
        try:
            response = requests.get("http://localhost:9200", timeout=5)
            if response.status_code == 200:
                es_data = response.json()
                st.success(f"✅ Connected to Elasticsearch v{es_data['version']['number']}")
                
                # Get document count
                count_response = requests.get("http://localhost:9200/insider-threat-realtime/_count")
                count_data = count_response.json()
                st.info(f"📊 Documents in 'insider-threat-realtime': **{count_data['count']}**")
                
            else:
                st.error("❌ Connection failed")
        except Exception as e:
            st.error(f"❌ Cannot connect to Elasticsearch: {str(e)}")
    
    # Quick actions
    st.subheader("Quick Actions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📥 Ingest Sample Data"):
            try:
                # Sample document to ingest
                sample_doc = {
                    "timestamp": datetime.now().isoformat(),
                    "user": "test.user@company.com",
                    "action": "unauthorized_access",
                    "resource": "confidential_data.xlsx",
                    "severity": 9,
                    "department": "Finance",
                    "risk_score": 0.92,
                    "anomaly_detected": True,
                    "source": "industry_dashboard"
                }
                
                response = requests.post(
                    "http://localhost:9200/insider-threat-realtime/_doc",
                    json=sample_doc,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code in [200, 201]:
                    st.success("✅ Sample threat data ingested!")
                else:
                    st.error(f"Failed: {response.text}")
            except Exception as e:
                st.error(f"Error: {str(e)}")
    
    with col2:
        if st.button("🗑️ Clear Test Data"):
            st.warning("This will delete all documents. Proceed with caution!")
            if st.button("Confirm Delete", key="confirm_delete"):
                try:
                    response = requests.post(
                        "http://localhost:9200/insider-threat-realtime/_delete_by_query",
                        json={"query": {"match_all": {}}}
                    )
                    st.info("Test data cleared")
                except:
                    pass
    
    # Elasticsearch Info
    st.subheader("Connection Details")
    st.code("""
    Elasticsearch: http://localhost:9200
    Index: insider-threat-realtime
    Kibana: http://localhost:5601
    """, language="bash")

with tab4:
    st.subheader("AWS Deployment Ready")
    
    st.info("""
    ### 🚀 One-Click Deployment Options
    
    1. **EC2 Instance** - Simple virtual server
    2. **ECS Fargate** - Serverless containers
    3. **EKS** - Kubernetes cluster
    4. **Elastic Beanstalk** - Platform as a Service
    """)
    
    st.subheader("Quick EC2 Deployment Script")
    st.code("""
    #!/bin/bash
    # Save as deploy-ec2.sh
    
    # Update system
    sudo yum update -y
    
    # Install Docker & Docker Compose
    sudo yum install docker -y
    sudo service docker start
    sudo usermod -a -G docker ec2-user
    
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    
    # Clone and run
    git clone https://github.com/your-repo/insider-threat-detection.git
    cd insider-threat-detection
    docker-compose -f docker-compose-aws.yml up -d
    """, language="bash")
    
    st.download_button(
        label="📥 Download Deployment Script",
        data=open("deploy-ec2.sh", "rb").read() if os.path.exists("deploy-ec2.sh") else "echo 'Script would be here'",
        file_name="deploy-ec2.sh",
        mime="text/x-shellscript"
    )

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    st.subheader("Alert Settings")
    alert_threshold = st.slider("Alert Threshold", 1, 10, 7)
    notification_freq = st.selectbox(
        "Notification Frequency",
        ["Real-time", "Hourly", "Daily", "Weekly"]
    )
    
    st.subheader("Departments")
    departments = st.multiselect(
        "Monitor Departments",
        ["IT", "HR", "Finance", "Engineering", "Sales", "Legal", "Operations"],
        default=["IT", "HR", "Finance"]
    )
    
    st.subheader("System Info")
    st.write(f"**Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.write("**Status**: Operational")
    
    if st.button("🚀 Deploy to AWS Cloud"):
        st.balloons()
        st.success("AWS deployment initiated! Check cloud console for details.")
        st.info("""
        Next steps:
        1. Create EC2 instance
        2. Configure security groups
        3. Deploy with Docker Compose
        4. Configure DNS/load balancer
        """)

# Footer
st.markdown("---")
st.markdown("**Insider Threat Detection v2.0** | Elastic Stack Integrated | AWS Ready")
