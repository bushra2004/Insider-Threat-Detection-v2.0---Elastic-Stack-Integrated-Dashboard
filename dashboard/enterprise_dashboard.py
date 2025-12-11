# dashboard/enterprise_dashboard.py - COMPATIBLE VERSION
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import json
import os
import re
import hashlib
from typing import Dict, List, Optional
import io
import base64
import warnings

warnings.filterwarnings('ignore')

# ============================================
# ENTERPRISE CONFIGURATION
# ============================================

ENTERPRISE_CONFIG = {
    "company_name": "Insider Threat Detection",
    "departments": ["IT", "HR", "Finance", "Engineering", "Security", "Operations"],
    "alert_levels": {
        "Critical": {"min_score": 80, "color": "#DC2626"},
        "High": {"min_score": 60, "color": "#EA580C"},
        "Medium": {"min_score": 40, "color": "#F59E0B"},
        "Low": {"min_score": 0, "color": "#10B981"}
    },
    "compliance_frameworks": ["NIST CSF", "MITRE ATT&CK", "ISO 27001", "GDPR"],
    "elk_host": "http://localhost:9200",
    "kibana_url": "http://localhost:5601",
}

# ============================================
# PAGE CONFIGURATION
# ============================================

st.set_page_config(
    page_title="Insider Threat Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# CYBER THEME CSS STYLING
# ============================================

st.markdown("""
<style>
    .stApp {
        background: #0a0a0a;
        color: #00ff41;
        font-family: 'Courier New', monospace;
    }
    
    .cyber-header {
        background: rgba(0, 255, 65, 0.1);
        padding: 2rem;
        border-radius: 5px;
        color: #00ff41;
        text-align: center;
        margin-bottom: 2rem;
        border: 1px solid #00ff41;
    }
    
    .cyber-card {
        background: rgba(0, 0, 0, 0.7);
        padding: 1rem;
        border-radius: 5px;
        border: 1px solid #00ff41;
        color: #00ff41;
        margin: 0.5rem;
    }
    
    .alert-critical {
        border-color: #ff0033 !important;
        background: rgba(255, 0, 51, 0.1) !important;
    }
    
    .alert-high {
        border-color: #ff6600 !important;
        background: rgba(255, 102, 0, 0.1) !important;
    }
    
    .alert-medium {
        border-color: #ffcc00 !important;
        background: rgba(255, 204, 0, 0.1) !important;
    }
    
    .alert-low {
        border-color: #00ff41 !important;
        background: rgba(0, 255, 65, 0.1) !important;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #00ff41 0%, #008f11 100%);
        color: #000000 !important;
        border: 1px solid #00ff41;
        border-radius: 3px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# DATA GENERATION FUNCTIONS
# ============================================

def generate_sample_threats(num=100):
    """Generate sample threat data"""
    np.random.seed(42)
    
    threats = []
    for i in range(num):
        threat = {
            "id": f"THR{i:04d}",
            "timestamp": (datetime.now() - timedelta(hours=np.random.randint(0, 72))).isoformat(),
            "user": f"user{np.random.randint(1000, 9999)}@company.com",
            "action": np.random.choice(["Unauthorized Access", "Data Export", "Suspicious Login", 
                                       "File Modification", "Process Execution"]),
            "severity": np.random.choice(["Critical", "High", "Medium", "Low"]),
            "department": np.random.choice(ENTERPRISE_CONFIG["departments"]),
            "risk_score": np.random.randint(10, 95),
            "status": np.random.choice(["Investigating", "Contained", "Resolved", "Pending"]),
            "source_ip": f"192.168.{np.random.randint(1,254)}.{np.random.randint(1,254)}",
            "destination_ip": f"10.0.{np.random.randint(1,254)}.{np.random.randint(1,254)}"
        }
        threats.append(threat)
    
    return pd.DataFrame(threats)

def generate_sysmon_sample(num=50):
    """Generate sample Sysmon data"""
    events = []
    for i in range(num):
        event = {
            "timestamp": (datetime.now() - timedelta(minutes=np.random.randint(0, 1440))).strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": np.random.choice(["Process Creation", "Network Connection", "File Creation", 
                                          "Process Termination", "Registry Event"]),
            "process_name": np.random.choice(["powershell.exe", "cmd.exe", "chrome.exe", "explorer.exe", 
                                            "svchost.exe", "code.exe"]),
            "user": f"user{np.random.randint(1, 100)}",
            "source_ip": f"192.168.{np.random.randint(1,254)}.{np.random.randint(1,254)}",
            "dest_ip": f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
            "port": np.random.choice([80, 443, 22, 3389, 445]),
            "risk_score": np.random.randint(10, 90),
            "severity": ["Low", "Medium", "High", "Critical"][min(int(np.random.randint(0, 100) / 25), 3)]
        }
        events.append(event)
    
    return pd.DataFrame(events)

# ============================================
# MAIN DASHBOARD CLASS
# ============================================

class InsiderThreatDashboard:
    """Main dashboard class"""
    
    def __init__(self):
        # Initialize session state
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = True  # Auto-login for demo
        if 'current_user' not in st.session_state:
            st.session_state.current_user = {
                "username": "soc_analyst",
                "role": "Security Analyst",
                "department": "Security"
            }
        if 'threat_data' not in st.session_state:
            st.session_state.threat_data = generate_sample_threats(150)
        if 'sysmon_data' not in st.session_state:
            st.session_state.sysmon_data = generate_sysmon_sample(75)
    
    def create_header(self):
        """Create dashboard header"""
        user = st.session_state.current_user
        
        st.markdown(f"""
        <div class="cyber-header">
            <h1>🛡️ {ENTERPRISE_CONFIG["company_name"]}</h1>
            <p>Real-time Threat Intelligence & Monitoring</p>
            <div style="margin-top: 1rem; display: flex; justify-content: center; gap: 15px;">
                <span style="background: rgba(0,255,65,0.2); padding: 5px 15px; border-radius: 20px; border: 1px solid #00ff41;">
                    👤 {user['username']}
                </span>
                <span style="background: rgba(0,255,65,0.2); padding: 5px 15px; border-radius: 20px; border: 1px solid #00ff41;">
                    🏢 {user['department']}
                </span>
                <span style="background: rgba(0,255,65,0.2); padding: 5px 15px; border-radius: 20px; border: 1px solid #00ff41;">
                    ⚡ SYSTEM ONLINE
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    def create_sidebar(self):
        """Create dashboard sidebar"""
        with st.sidebar:
            st.markdown("### 🗺️ NAVIGATION")
            
            tab = st.radio(
                "Select Section",
                ["📊 Dashboard", "🔍 Threat Analysis", "📡 Sysmon Logs", 
                 "📈 Analytics", "⚙️ Configuration"],
                label_visibility="collapsed"
            )
            
            st.session_state.current_tab = tab
            
            st.markdown("---")
            
            st.markdown("### ⚡ QUICK ACTIONS")
            if st.button("🔄 Refresh Data", use_container_width=True):
                st.session_state.threat_data = generate_sample_threats(150)
                st.session_state.sysmon_data = generate_sysmon_sample(75)
                st.rerun()
            
            if st.button("📥 Export Report", use_container_width=True):
                st.info("Report generation started...")
            
            if st.button("🚨 Test Alert", use_container_width=True):
                st.success("Test alert sent!")
            
            st.markdown("---")
            
            # System Status
            st.markdown("### 🔌 SYSTEM STATUS")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Threats", len(st.session_state.threat_data))
            with col2:
                critical = len(st.session_state.threat_data[
                    st.session_state.threat_data['severity'] == 'Critical'
                ])
                st.metric("Critical", critical, delta_color="inverse")
    
    def create_dashboard_tab(self):
        """Create main dashboard"""
        st.header("📊 REAL-TIME THREAT DASHBOARD")
        
        # Metrics Row
        col1, col2, col3, col4, col5 = st.columns(5)
        
        df = st.session_state.threat_data
        
        with col1:
            critical = len(df[df['severity'] == 'Critical'])
            st.markdown(f"""
            <div class="cyber-card alert-critical">
                <h3>🚨 CRITICAL</h3>
                <h2>{critical}</h2>
                <p>Immediate action</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            high = len(df[df['severity'] == 'High'])
            st.markdown(f"""
            <div class="cyber-card alert-high">
                <h3>⚠️ HIGH</h3>
                <h2>{high}</h2>
                <p>Investigation needed</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="cyber-card">
                <h3>📈 TOTAL</h3>
                <h2>{len(df)}</h2>
                <p>Threats detected</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            avg_risk = df['risk_score'].mean()
            st.markdown(f"""
            <div class="cyber-card">
                <h3>⚡ AVG RISK</h3>
                <h2>{avg_risk:.1f}</h2>
                <p>Average score</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col5:
            active = len(df[df['status'] == 'Investigating'])
            st.markdown(f"""
            <div class="cyber-card">
                <h3>🔍 ACTIVE</h3>
                <h2>{active}</h2>
                <p>Under investigation</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Threat Distribution")
            
            # Severity distribution
            severity_counts = df['severity'].value_counts().reset_index()
            severity_counts.columns = ['Severity', 'Count']
            
            fig = px.pie(severity_counts, values='Count', names='Severity',
                        title="Threats by Severity Level",
                        color='Severity',
                        color_discrete_map={
                            'Critical': '#DC2626',
                            'High': '#EA580C',
                            'Medium': '#F59E0B',
                            'Low': '#10B981'
                        })
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📈 Risk Timeline")
            
            # Group by hour
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            timeline = df.groupby('hour').agg({
                'risk_score': 'mean',
                'id': 'count'
            }).reset_index()
            
            fig = px.line(timeline, x='hour', y='risk_score',
                         title="Average Risk Score by Hour",
                         markers=True)
            fig.update_traces(line=dict(color='#00ff41', width=3))
            st.plotly_chart(fig, use_container_width=True)
        
        # Recent Threats Table
        st.subheader("🚨 RECENT THREATS")
        
        recent_threats = df.sort_values('timestamp', ascending=False).head(10)
        
        for _, threat in recent_threats.iterrows():
            severity_color = ENTERPRISE_CONFIG['alert_levels'][threat['severity']]['color']
            
            st.markdown(f"""
            <div style="
                background: rgba(0,0,0,0.7);
                border-left: 4px solid {severity_color};
                padding: 1rem;
                border-radius: 5px;
                margin: 0.5rem 0;
                color: #00ff41;
                border: 1px solid {severity_color};
            ">
                <strong>{threat['action']}</strong><br>
                <small>User: {threat['user']} | Severity: {threat['severity']} | Risk: {threat['risk_score']}</small><br>
                Department: {threat['department']} | Status: {threat['status']}
            </div>
            """, unsafe_allow_html=True)
    
    def create_threat_analysis_tab(self):
        """Create threat analysis tab"""
        st.header("🔍 THREAT ANALYSIS")
        
        df = st.session_state.threat_data
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            severity_filter = st.multiselect(
                "Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"]
            )
        
        with col2:
            department_filter = st.multiselect(
                "Department",
                options=ENTERPRISE_CONFIG["departments"],
                default=ENTERPRISE_CONFIG["departments"]
            )
        
        with col3:
            risk_min, risk_max = st.slider(
                "Risk Score Range",
                0, 100,
                (60, 100)
            )
        
        # Apply filters
        filtered_df = df[
            (df['severity'].isin(severity_filter)) &
            (df['department'].isin(department_filter)) &
            (df['risk_score'] >= risk_min) &
            (df['risk_score'] <= risk_max)
        ]
        
        st.metric("Filtered Threats", len(filtered_df))
        
        # Detailed table
        st.dataframe(
            filtered_df[[
                'timestamp', 'user', 'action', 'severity', 
                'department', 'risk_score', 'status'
            ]].sort_values('risk_score', ascending=False),
            use_container_width=True
        )
        
        # Department Analysis
        st.subheader("🏢 DEPARTMENT ANALYSIS")
        
        dept_analysis = filtered_df.groupby('department').agg({
            'risk_score': 'mean',
            'id': 'count'
        }).rename(columns={'id': 'threat_count'}).reset_index()
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.bar(dept_analysis, x='department', y='threat_count',
                        title="Threats by Department",
                        color='threat_count',
                        color_continuous_scale='reds')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.bar(dept_analysis, x='department', y='risk_score',
                        title="Average Risk Score by Department",
                        color='risk_score',
                        color_continuous_scale='reds')
            st.plotly_chart(fig, use_container_width=True)
    
    def create_sysmon_tab(self):
        """Create Sysmon analysis tab"""
        st.header("📡 SYSMON LOG ANALYSIS")
        
        # File upload
        uploaded_file = st.file_uploader("Upload Sysmon CSV", type=['csv'])
        
        if uploaded_file is not None:
            # Load uploaded data
            sysmon_df = pd.read_csv(uploaded_file)
            st.success(f"✅ Loaded {len(sysmon_df)} Sysmon events")
            st.session_state.uploaded_sysmon = sysmon_df
        elif hasattr(st.session_state, 'uploaded_sysmon'):
            sysmon_df = st.session_state.uploaded_sysmon
        else:
            # Use sample data
            sysmon_df = st.session_state.sysmon_data
            st.info("Using sample Sysmon data. Upload a CSV file for real analysis.")
        
        # Statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Events", len(sysmon_df))
        with col2:
            unique_ips = len(set(list(sysmon_df['source_ip'].unique()) + 
                               list(sysmon_df['dest_ip'].unique())))
            st.metric("Unique IPs", unique_ips)
        with col3:
            unique_processes = len(sysmon_df['process_name'].unique())
            st.metric("Processes", unique_processes)
        with col4:
            high_risk = len(sysmon_df[sysmon_df['severity'].isin(['High', 'Critical'])])
            st.metric("High Risk", high_risk)
        
        # Event Type Analysis
        st.subheader("📊 EVENT TYPE DISTRIBUTION")
        
        event_counts = sysmon_df['event_type'].value_counts().reset_index()
        event_counts.columns = ['Event Type', 'Count']
        
        fig = px.pie(event_counts, values='Count', names='Event Type',
                    title="Sysmon Event Types", hole=0.3)
        st.plotly_chart(fig, use_container_width=True)
        
        # Top Processes
        st.subheader("🔝 TOP PROCESSES")
        
        top_processes = sysmon_df['process_name'].value_counts().head(10).reset_index()
        top_processes.columns = ['Process', 'Count']
        
        fig = px.bar(top_processes, x='Count', y='Process', orientation='h',
                    title="Most Frequent Processes", color='Count',
                    color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)
        
        # Raw Data
        with st.expander("📋 VIEW RAW DATA"):
            st.dataframe(sysmon_df, use_container_width=True)
    
    def create_analytics_tab(self):
        """Create analytics tab"""
        st.header("📈 ADVANCED ANALYTICS")
        
        df = st.session_state.threat_data
        
        # Time Series Analysis
        st.subheader("⏰ TIME SERIES ANALYSIS")
        
        # Convert timestamp and group by day
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        daily_counts = df.groupby('date').size().reset_index()
        daily_counts.columns = ['Date', 'Threat Count']
        
        fig = px.line(daily_counts, x='Date', y='Threat Count',
                     title="Daily Threat Count",
                     markers=True)
        st.plotly_chart(fig, use_container_width=True)
        
        # User Risk Analysis
        st.subheader("👤 USER RISK PROFILING")
        
        user_risk = df.groupby('user').agg({
            'risk_score': 'mean',
            'id': 'count'
        }).rename(columns={'id': 'threat_count'}).reset_index()
        
        # Top 10 risky users
        top_risky_users = user_risk.sort_values('risk_score', ascending=False).head(10)
        
        fig = px.bar(top_risky_users, x='user', y='risk_score',
                    title="Top 10 Riskiest Users",
                    color='threat_count',
                    color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)
        
        # Correlation Analysis
        st.subheader("🔗 CORRELATION ANALYSIS")
        
        # Create correlation matrix
        numeric_df = df[['risk_score']].copy()
        if 'port' in df.columns:
            numeric_df['port'] = df['port']
        
        # Add department as numeric (for demo)
        dept_mapping = {dept: i for i, dept in enumerate(ENTERPRISE_CONFIG["departments"])}
        numeric_df['dept_numeric'] = df['department'].map(dept_mapping)
        
        if not numeric_df.empty and len(numeric_df.columns) > 1:
            corr_matrix = numeric_df.corr()
            
            fig = px.imshow(corr_matrix,
                           title="Correlation Matrix",
                           color_continuous_scale='RdBu',
                           text_auto=True)
            st.plotly_chart(fig, use_container_width=True)
    
    def create_configuration_tab(self):
        """Create configuration tab"""
        st.header("⚙️ CONFIGURATION")
        
        # Alert Settings
        st.subheader("🚨 ALERT SETTINGS")
        
        col1, col2 = st.columns(2)
        
        with col1:
            critical_threshold = st.slider(
                "Critical Threshold",
                min_value=0, max_value=100,
                value=80
            )
            
            email_alerts = st.checkbox("Email Alerts", value=True)
        
        with col2:
            high_threshold = st.slider(
                "High Threshold",
                min_value=0, max_value=100,
                value=60
            )
            
            slack_alerts = st.checkbox("Slack Integration", value=False)
        
        # Departments to Monitor
        st.subheader("🏢 MONITORED DEPARTMENTS")
        
        departments = ENTERPRISE_CONFIG["departments"]
        selected_depts = st.multiselect(
            "Select departments to monitor",
            options=departments,
            default=departments
        )
        
        # ELK Configuration
        st.subheader("🔗 ELK STACK CONFIGURATION")
        
        elk_host = st.text_input("Elasticsearch Host", value="http://localhost:9200")
        kibana_url = st.text_input("Kibana URL", value="http://localhost:5601")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save Configuration", use_container_width=True):
                st.success("Configuration saved!")
        
        with col2:
            if st.button("🔄 Reset to Defaults", use_container_width=True, type="secondary"):
                st.info("Configuration reset to defaults")
    
    def run(self):
        """Main dashboard runner"""
        # Auto-login for demo
        if not st.session_state.authenticated:
            st.session_state.authenticated = True
            st.rerun()
        
        # Create interface
        self.create_header()
        self.create_sidebar()
        
        # Show selected tab
        tab = st.session_state.get('current_tab', '📊 Dashboard')
        
        if tab == "📊 Dashboard":
            self.create_dashboard_tab()
        elif tab == "🔍 Threat Analysis":
            self.create_threat_analysis_tab()
        elif tab == "📡 Sysmon Logs":
            self.create_sysmon_tab()
        elif tab == "📈 Analytics":
            self.create_analytics_tab()
        elif tab == "⚙️ Configuration":
            self.create_configuration_tab()

# ============================================
# MAIN APPLICATION
# ============================================

def main():
    """Main application entry point"""
    
    # Initialize dashboard
    dashboard = InsiderThreatDashboard()
    
    # Run the dashboard
    dashboard.run()

if __name__ == "__main__":
    main()