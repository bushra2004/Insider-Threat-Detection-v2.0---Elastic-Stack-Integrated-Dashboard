import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import pandas as pd
import asyncio
import websockets
import json

class RealtimeMonitor:
    def __init__(self):
        self.ws_url = "ws://localhost:8000/ws/realtime"
        self.websocket = None
        
    async def connect(self):
        """Connect to WebSocket for real-time data"""
        try:
            self.websocket = await websockets.connect(self.ws_url)
            return True
        except Exception as e:
            st.error(f"Failed to connect to real-time feed: {e}")
            return False
    
    def display_dashboard(self):
        """Display professional dashboard"""
        st.set_page_config(
            page_title="Insider Threat Dashboard",
            page_icon="🛡️",
            layout="wide"
        )
        
        # Custom CSS
        st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            color: #1E3A8A;
            padding-bottom: 1rem;
            border-bottom: 2px solid #E5E7EB;
        }
        .metric-card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            border-left: 4px solid;
        }
        .critical { border-left-color: #DC2626; }
        .high { border-left-color: #EA580C; }
        .medium { border-left-color: #D97706; }
        .low { border-left-color: #059669; }
        </style>
        """, unsafe_allow_html=True)
        
        # Header
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.markdown('<h1 class="main-header">🔒 Insider Threat Detection Dashboard</h1>', 
                       unsafe_allow_html=True)
        with col2:
            st.metric("Active Threats", "12", "↑ 3")
        with col3:
            st.metric("Response Time", "2.3s", "↓ 0.4s")
        
        # Main columns
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Real-time threat map
            st.subheader("🌍 Real-time Threat Map")
            self.display_threat_map()
            
            # Timeline of events
            st.subheader("📈 Threat Timeline")
            self.display_threat_timeline()
            
        with col2:
            # Alert panel
            st.subheader("🚨 Recent Alerts")
            self.display_alerts_panel()
            
            # Severity distribution
            st.subheader("📊 Severity Distribution")
            self.display_severity_chart()
        
        # Bottom section
        col1, col2, col3 = st.columns(3)
        
        with col1:
            self.display_metric_card("Users Monitored", "142", "↗ 8", "low")
        with col2:
            self.display_metric_card("Total Events Today", "2,847", "↗ 124", "medium")
        with col3:
            self.display_metric_card("Avg. Threat Score", "0.42", "↓ 0.08", "high")
    
    def display_metric_card(self, title: str, value: str, delta: str, severity: str):
        """Display a metric card"""
        st.markdown(f"""
        <div class="metric-card {severity}">
            <h3 style="margin: 0; font-size: 1rem; color: #6B7280;">{title}</h3>
            <h1 style="margin: 0.5rem 0; font-size: 2rem; color: #111827;">{value}</h1>
            <p style="margin: 0; color: #6B7280;">{delta}</p>
        </div>
        """, unsafe_allow_html=True)
    
    def display_threat_map(self):
        """Display threat geographic map"""
        # Sample data - replace with real geo data
        threat_data = pd.DataFrame({
            'lat': [40.7128, 34.0522, 41.8781, 51.5074, 35.6762],
            'lon': [-74.0060, -118.2437, -87.6298, -0.1278, 139.6503],
            'severity': ['critical', 'high', 'medium', 'low', 'critical'],
            'size': [30, 25, 20, 15, 30],
            'location': ['New York', 'Los Angeles', 'Chicago', 'London', 'Tokyo']
        })
        
        fig = px.scatter_mapbox(
            threat_data,
            lat="lat",
            lon="lon",
            size="size",
            color="severity",
            color_discrete_map={
                'critical': '#DC2626',
                'high': '#EA580C',
                'medium': '#D97706',
                'low': '#059669'
            },
            hover_name="location",
            hover_data={"severity": True, "size": True},
            zoom=1,
            height=400
        )
        
        fig.update_layout(
            mapbox_style="carto-darkmatter",
            margin={"r":0,"t":0,"l":0,"b":0}
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def display_threat_timeline(self):
        """Display threat timeline"""
        # Sample timeline data
        timeline_data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=50, freq='H'),
            'threat_score': np.random.rand(50) * 100,
            'severity': np.random.choice(['low', 'medium', 'high', 'critical'], 50, p=[0.5, 0.3, 0.15, 0.05])
        })
        
        fig = go.Figure()
        
        for severity in ['low', 'medium', 'high', 'critical']:
            data = timeline_data[timeline_data['severity'] == severity]
            fig.add_trace(go.Scatter(
                x=data['timestamp'],
                y=data['threat_score'],
                mode='markers+lines',
                name=severity.title(),
                marker=dict(
                    size=8,
                    color={
                        'critical': '#DC2626',
                        'high': '#EA580C',
                        'medium': '#D97706',
                        'low': '#059669'
                    }[severity]
                )
            ))
        
        fig.update_layout(
            height=300,
            xaxis_title="Time",
            yaxis_title="Threat Score",
            hovermode="x unified",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def display_alerts_panel(self):
        """Display recent alerts panel"""
        alerts = [
            {"id": "ALT-001", "user": "john.doe", "severity": "critical", "time": "2 min ago", "type": "Data Exfiltration"},
            {"id": "ALT-002", "user": "jane.smith", "severity": "high", "time": "15 min ago", "type": "Unauthorized Access"},
            {"id": "ALT-003", "user": "bob.wilson", "severity": "medium", "time": "1 hr ago", "type": "Suspicious Download"},
            {"id": "ALT-004", "user": "alice.jones", "severity": "low", "time": "2 hrs ago", "type": "Unusual Login Time"},
        ]
        
        for alert in alerts:
            severity_color = {
                'critical': '#DC2626',
                'high': '#EA580C',
                'medium': '#D97706',
                'low': '#059669'
            }[alert['severity']]
            
            st.markdown(f"""
            <div style="
                background: white;
                border-radius: 8px;
                padding: 1rem;
                margin-bottom: 0.5rem;
                border-left: 4px solid {severity_color};
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            ">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong>{alert['id']}</strong>
                    <span style="
                        background: {severity_color};
                        color: white;
                        padding: 2px 8px;
                        border-radius: 12px;
                        font-size: 0.8rem;
                    ">{alert['severity'].upper()}</span>
                </div>
                <div style="margin-top: 0.5rem;">
                    <div>👤 {alert['user']}</div>
                    <div>📝 {alert['type']}</div>
                    <div style="color: #6B7280; font-size: 0.9rem;">🕐 {alert['time']}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        if st.button("View All Alerts", use_container_width=True):
            st.switch_page("pages/alerts.py")
    
    def display_severity_chart(self):
        """Display severity distribution chart"""
        severity_counts = {'Critical': 3, 'High': 5, 'Medium': 12, 'Low': 25}
        
        colors = ['#DC2626', '#EA580C', '#D97706', '#059669']
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            hole=.4,
            marker=dict(colors=colors),
            textinfo='label+percent',
            hoverinfo='label+value+percent'
        )])
        
        fig.update_layout(
            height=300,
            showlegend=False,
            margin=dict(t=0, b=0, l=0, r=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)