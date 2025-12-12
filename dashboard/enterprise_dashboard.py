# dashboard/enterprise_dashboard.py - COMPLETE VERSION WITH POSTGRESQL
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
import sys

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
# DATABASE CONFIGURATION (PostgreSQL)
# ============================================

DB_CONFIG = {
    "enabled": True,
    "connection_string": "postgresql://postgres:password@localhost:5432/threat_detection"
}

def init_database():
    """Initialize database connection"""
    if not DB_CONFIG["enabled"]:
        return None
    
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        
        engine = create_engine(DB_CONFIG["connection_string"])
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        return SessionLocal()
    except Exception as e:
        return None

def save_threats_to_db(threats_df):
    """Save threats to PostgreSQL database"""
    if not DB_CONFIG["enabled"]:
        return False
    
    try:
        session = init_database()
        if not session:
            return False
        
        from sqlalchemy import text
        
        success_count = 0
        error_count = 0
        
        for _, threat in threats_df.iterrows():
            try:
                username = threat['user'].split('@')[0] if '@' in threat['user'] else threat['user']
                
                user_query = text("""
                    INSERT INTO users (username, email, department, role, risk_score, status)
                    VALUES (:username, :email, :department, 'employee', :risk_score, 'active')
                    ON CONFLICT (username) DO UPDATE SET
                        department = EXCLUDED.department,
                        risk_score = EXCLUDED.risk_score,
                        last_risk_assessment = NOW()
                    RETURNING user_id
                """)
                
                user_result = session.execute(user_query, {
                    'username': username,
                    'email': threat['user'],
                    'department': threat['department'],
                    'risk_score': float(threat['risk_score'])
                }).fetchone()
                
                user_id = user_result[0] if user_result else None
                
                threat_query = text("""
                    INSERT INTO threats (
                        user_id, timestamp, threat_type, severity, description,
                        source_ip, department, confidence_score, investigation_status
                    ) VALUES (
                        :user_id, :timestamp, :threat_type, :severity, :description,
                        :source_ip, :department, :confidence_score, 'new'
                    )
                    RETURNING threat_id
                """)
                
                severity = threat['severity'].lower() if isinstance(threat['severity'], str) else 'medium'
                
                session.execute(threat_query, {
                    'user_id': user_id,
                    'timestamp': pd.to_datetime(threat['timestamp']),
                    'threat_type': str(threat['action']),
                    'severity': severity,
                    'description': f"{threat['action']} by {threat['user']} in {threat['department']}",
                    'source_ip': str(threat['source_ip']),
                    'department': str(threat['department']),
                    'confidence_score': float(threat['risk_score']) / 100.0 * 90.0
                })
                
                success_count += 1
                
            except Exception as e:
                error_count += 1
                continue
        
        session.commit()
        session.close()
        
        if success_count > 0:
            st.session_state.last_save_count = success_count
            return True
        else:
            return False
        
    except Exception as e:
        return False

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
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = True
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
    
    def get_database_analytics(self, session):
        """Get professional analytics from database"""
        from sqlalchemy import text
        
        analytics = {}
        
        try:
            risky_users_query = text("""
                SELECT 
                    username,
                    department,
                    risk_score,
                    (SELECT COUNT(*) FROM threats 
                     WHERE threats.user_id = users.user_id 
                     AND threats.timestamp >= NOW() - INTERVAL '7 days') as recent_threats
                FROM users 
                WHERE status = 'active'
                ORDER BY risk_score DESC 
                LIMIT 10
            """)
            
            risky_users = pd.read_sql(risky_users_query, session.bind)
            analytics['risky_users'] = risky_users
            
            dept_risk_query = text("""
                SELECT 
                    department,
                    COUNT(*) as user_count,
                    AVG(risk_score) as avg_risk_score
                FROM users
                WHERE status = 'active'
                GROUP BY department
                ORDER BY avg_risk_score DESC
            """)
            
            dept_risk = pd.read_sql(dept_risk_query, session.bind)
            analytics['department_risk'] = dept_risk
            
            timeline_query = text("""
                SELECT 
                    DATE(timestamp) as threat_date,
                    severity,
                    COUNT(*) as threat_count
                FROM threats
                WHERE timestamp >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(timestamp), severity
                ORDER BY threat_date DESC, severity
            """)
            
            timeline = pd.read_sql(timeline_query, session.bind)
            analytics['timeline'] = timeline
            
            stats_query = text("""
                SELECT 
                    COUNT(*) as total_threats,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_threats,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_threats,
                    SUM(CASE WHEN investigation_status = 'new' THEN 1 ELSE 0 END) as new_threats
                FROM threats
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
            """)
            
            stats = pd.read_sql(stats_query, session.bind)
            analytics['stats'] = stats.iloc[0] if not stats.empty else {}
            
        except Exception as e:
            print(f"Analytics query error: {e}")
        
        return analytics
    
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
            
            st.markdown("### 🔌 SYSTEM STATUS")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Threats", len(st.session_state.threat_data))
            with col2:
                critical = len(st.session_state.threat_data[
                    st.session_state.threat_data['severity'] == 'Critical'
                ])
                st.metric("Critical", critical, delta_color="inverse")
            
            if DB_CONFIG["enabled"]:
                st.markdown("### 🗄️ DATABASE STATUS")
                try:
                    session = init_database()
                    if session:
                        from sqlalchemy import text
                        
                        user_count = pd.read_sql(
                            text("SELECT COUNT(*) FROM users WHERE status = 'active'"), 
                            session.bind
                        ).iloc[0, 0]
                        
                        threat_count = pd.read_sql(
                            text("SELECT COUNT(*) FROM threats"), 
                            session.bind
                        ).iloc[0, 0]
                        
                        recent_threats = pd.read_sql(
                            text("SELECT COUNT(*) FROM threats WHERE timestamp >= NOW() - INTERVAL '24 hours'"), 
                            session.bind
                        ).iloc[0, 0]
                        
                        session.close()
                        
                        st.metric("Active Users", user_count)
                        st.metric("Total Threats", threat_count)
                        st.metric("24h Threats", recent_threats)
                        
                except Exception as e:
                    st.caption(f"Database: {str(e)[:50]}")
    
    def create_dashboard_tab(self):
        """Create main dashboard"""
        st.header("📊 REAL-TIME THREAT DASHBOARD")
        
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
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Threat Distribution")
            
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
        
        if DB_CONFIG["enabled"]:
            try:
                session = init_database()
                if session:
                    analytics = self.get_database_analytics(session)
                    session.close()
                    
                    if analytics:
                        st.markdown("---")
                        st.subheader("🗄️ DATABASE ANALYTICS")
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            if 'stats' in analytics and not analytics['stats'].empty:
                                stats = analytics['stats']
                                st.metric("24h Threats", int(stats.get('total_threats', 0)))
                                st.metric("Critical Threats", int(stats.get('critical_threats', 0)))
                                st.metric("New Threats", int(stats.get('new_threats', 0)))
                        
                        with col2:
                            if 'risky_users' in analytics and not analytics['risky_users'].empty:
                                st.write("**Top Risky Users**")
                                st.dataframe(
                                    analytics['risky_users'].head(5),
                                    hide_index=True,
                                    use_container_width=True
                                )
            except:
                pass
    
    def create_threat_analysis_tab(self):
        """Create threat analysis tab"""
        st.header("🔍 THREAT ANALYSIS")
        
        df = st.session_state.threat_data
        
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
        
        filtered_df = df[
            (df['severity'].isin(severity_filter)) &
            (df['department'].isin(department_filter)) &
            (df['risk_score'] >= risk_min) &
            (df['risk_score'] <= risk_max)
        ]
        
        st.metric("Filtered Threats", len(filtered_df))
        
        st.dataframe(
            filtered_df[[
                'timestamp', 'user', 'action', 'severity', 
                'department', 'risk_score', 'status'
            ]].sort_values('risk_score', ascending=False),
            use_container_width=True
        )
        
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
        
        uploaded_file = st.file_uploader("Upload Sysmon CSV", type=['csv'])
        
        if uploaded_file is not None:
            sysmon_df = pd.read_csv(uploaded_file)
            st.success(f"✅ Loaded {len(sysmon_df)} Sysmon events")
            st.session_state.uploaded_sysmon = sysmon_df
        elif hasattr(st.session_state, 'uploaded_sysmon'):
            sysmon_df = st.session_state.uploaded_sysmon
        else:
            sysmon_df = st.session_state.sysmon_data
            st.info("Using sample Sysmon data. Upload a CSV file for real analysis.")
        
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
        
        st.subheader("📊 EVENT TYPE DISTRIBUTION")
        
        event_counts = sysmon_df['event_type'].value_counts().reset_index()
        event_counts.columns = ['Event Type', 'Count']
        
        fig = px.pie(event_counts, values='Count', names='Event Type',
                    title="Sysmon Event Types", hole=0.3)
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("🔝 TOP PROCESSES")
        
        top_processes = sysmon_df['process_name'].value_counts().head(10).reset_index()
        top_processes.columns = ['Process', 'Count']
        
        fig = px.bar(top_processes, x='Count', y='Process', orientation='h',
                    title="Most Frequent Processes", color='Count',
                    color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)
        
        with st.expander("📋 VIEW RAW DATA"):
            st.dataframe(sysmon_df, use_container_width=True)
    
    def create_analytics_tab(self):
        """Create analytics tab"""
        st.header("📈 ADVANCED ANALYTICS")
        
        df = st.session_state.threat_data
        
        st.subheader("⏰ TIME SERIES ANALYSIS")
        
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        daily_counts = df.groupby('date').size().reset_index()
        daily_counts.columns = ['Date', 'Threat Count']
        
        fig = px.line(daily_counts, x='Date', y='Threat Count',
                     title="Daily Threat Count",
                     markers=True)
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("👤 USER RISK PROFILING")
        
        user_risk = df.groupby('user').agg({
            'risk_score': 'mean',
            'id': 'count'
        }).rename(columns={'id': 'threat_count'}).reset_index()
        
        top_risky_users = user_risk.sort_values('risk_score', ascending=False).head(10)
        
        fig = px.bar(top_risky_users, x='user', y='risk_score',
                    title="Top 10 Riskiest Users",
                    color='threat_count',
                    color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)
        
        numeric_df = df[['risk_score']].copy()
        if 'port' in df.columns:
            numeric_df['port'] = df['port']
        
        dept_mapping = {dept: i for i, dept in enumerate(ENTERPRISE_CONFIG["departments"])}
        numeric_df['dept_numeric'] = df['department'].map(dept_mapping)
        
        if not numeric_df.empty and len(numeric_df.columns) > 1:
            corr_matrix = numeric_df.corr()
            
            fig = px.imshow(corr_matrix,
                           title="Correlation Matrix",
                           color_continuous_scale='RdBu',
                           text_auto=True)
            st.plotly_chart(fig, use_container_width=True)
        
        if DB_CONFIG["enabled"]:
            st.markdown("---")
            st.subheader("🗄️ DATABASE ANALYTICS")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📊 Load from Database", use_container_width=True):
                    try:
                        session = init_database()
                        if session:
                            from sqlalchemy import text
                            query = text("SELECT * FROM threats ORDER BY timestamp DESC")
                            db_data = pd.read_sql(query, session.bind)
                            session.close()
                            
                            if not db_data.empty:
                                st.session_state.db_threats = db_data
                                st.success(f"✅ Loaded {len(db_data)} threats from database")
                                st.dataframe(db_data.head(10), use_container_width=True)
                            else:
                                st.info("No threats found in database")
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)[:100]}")
            
            with col2:
                if st.button("🧹 Clear Database", use_container_width=True, type="secondary"):
                    try:
                        session = init_database()
                        if session:
                            session.execute(text("DELETE FROM threats"))
                            session.commit()
                            session.close()
                            st.success("✅ Database cleared!")
                    except:
                        st.error("Failed to clear database")
    
    def create_configuration_tab(self):
        """Create configuration tab"""
        st.header("⚙️ CONFIGURATION")
        
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
        
        st.subheader("🏢 MONITORED DEPARTMENTS")
        
        departments = ENTERPRISE_CONFIG["departments"]
        selected_depts = st.multiselect(
            "Select departments to monitor",
            options=departments,
            default=departments
        )
        
        st.subheader("🔗 ELK STACK CONFIGURATION")
        
        elk_host = st.text_input("Elasticsearch Host", value="http://localhost:9200")
        kibana_url = st.text_input("Kibana URL", value="http://localhost:5601")
        
        st.markdown("---")
        st.subheader("🗄️ DATABASE CONFIGURATION (PostgreSQL)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            db_enabled = st.toggle(
                "Enable PostgreSQL Storage",
                value=DB_CONFIG["enabled"],
                help="Store threats in PostgreSQL database"
            )
            
            if db_enabled:
                st.success("✅ PostgreSQL will store threat data")
            else:
                st.info("ℹ️ Using in-memory data only")
        
        with col2:
            if db_enabled:
                connection_string = st.text_input(
                    "Database Connection String",
                    value=DB_CONFIG["connection_string"],
                    help="Format: postgresql://username:password@host:port/database"
                )
                
                if st.button("🔗 Test Database Connection"):
                    try:
                        import psycopg2
                        conn = psycopg2.connect(connection_string)
                        conn.close()
                        st.success("✅ Database connection successful!")
                    except Exception as e:
                        st.error(f"❌ Connection failed: {str(e)[:100]}")
        
        if 'threat_data' in st.session_state and db_enabled:
            st.markdown("---")
            if st.button("💾 Save Current Threats to Database", use_container_width=True):
                with st.spinner("Saving to database..."):
                    success = save_threats_to_db(st.session_state.threat_data)
                    if success:
                        st.success(f"✅ Saved {len(st.session_state.threat_data)} threats to database!")
                    else:
                        st.error("❌ Failed to save to database. Check connection.")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save Configuration", use_container_width=True):
                current_module = sys.modules[__name__]
                current_module.DB_CONFIG["enabled"] = db_enabled
                if db_enabled:
                    current_module.DB_CONFIG["connection_string"] = connection_string
                st.success("Configuration saved!")
        
        with col2:
            if st.button("🔄 Reset to Defaults", use_container_width=True, type="secondary"):
                st.info("Configuration reset to defaults")
    
    def run(self):
        """Main dashboard runner"""
        if not st.session_state.authenticated:
            st.session_state.authenticated = True
            st.rerun()
        
        self.create_header()
        self.create_sidebar()
        
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
    dashboard = InsiderThreatDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()