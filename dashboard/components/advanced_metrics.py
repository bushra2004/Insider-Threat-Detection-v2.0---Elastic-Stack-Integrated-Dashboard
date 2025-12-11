"""
Advanced metrics using your enhanced data integration
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def show_advanced_metrics(data_loader, data):
    """Show advanced security metrics"""
    st.subheader("🔍 Advanced Security Metrics")
    
    # Get system status from your data integration
    try:
        system_status = data_loader.get_system_metrics()
        tor_detection = data_loader.get_tor_detection()
    except:
        system_status = {"status": "Unknown"}
        tor_detection = []
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if 'anomaly_score' in data.columns:
            high_anomaly = (data['anomaly_score'] > 0.7).sum()
            st.metric("High Anomalies", high_anomaly)
        else:
            st.metric("High Anomalies", 0)
    
    with col2:
        if 'is_anomaly' in data.columns:
            anomalies = data['is_anomaly'].sum()
            st.metric("ML Detected Anomalies", anomalies)
        else:
            st.metric("ML Detected Anomalies", 0)
    
    with col3:
        # Sysmon-specific metrics
        if 'activity' in data.columns:
            sysmon_events = len(data[data['activity'].str.contains('Event', na=False)])
            st.metric("Sysmon Events", sysmon_events)
        else:
            st.metric("Total Events", len(data))
    
    with col4:
        st.metric("System Status", system_status.get('status', 'Unknown'))
    
    # Tor Detection Alerts
    if tor_detection:
        st.warning(f"🚨 Tor Usage Detected: {len(tor_detection)} indicators")
        with st.expander("Tor Detection Details"):
            for indicator in tor_detection:
                st.write(f"**{indicator['type']}**: {indicator['count']} occurrences")
                if 'ips' in indicator and indicator['ips']:
                    st.write(f"Suspicious IPs: {', '.join(indicator['ips'])}")

def show_event_breakdown(data):
    """Show breakdown of Sysmon events"""
    if 'activity' in data.columns:
        st.subheader("📊 Event Type Breakdown")
        
        event_counts = data['activity'].value_counts()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Event Distribution**")
            for event, count in event_counts.head(10).items():
                st.write(f"{event}: {count}")
        
        with col2:
            # Show anomaly distribution by event type
            if 'is_anomaly' in data.columns:
                anomaly_by_event = data.groupby('activity')['is_anomaly'].mean().sort_values(ascending=False)
                st.write("**Anomaly Rate by Event Type**")
                for event, rate in anomaly_by_event.head(5).items():
                    st.write(f"{event}: {rate:.1%}")
    else:
        st.info("Event breakdown data not available")

def create_anomaly_analysis(data):
    """Create advanced anomaly analysis visualization"""
    if 'anomaly_score' not in data.columns:
        st.info("Anomaly analysis data not available")
        return
    
    st.subheader("🤖 Machine Learning Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Anomaly score distribution
        fig = px.histogram(
            data, 
            x='anomaly_score',
            title='Anomaly Score Distribution',
            labels={'anomaly_score': 'Anomaly Score', 'count': 'Number of Events'},
            color_discrete_sequence=['#FF6B6B']
        )
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Risk vs Anomaly correlation
        if 'risk_score' in data.columns:
            fig = px.scatter(
                data,
                x='risk_score',
                y='anomaly_score',
                color='is_anomaly' if 'is_anomaly' in data.columns else None,
                title='Risk Score vs Anomaly Score',
                labels={'risk_score': 'Risk Score', 'anomaly_score': 'Anomaly Score'},
                color_discrete_map={True: '#FF6B6B', False: '#1f77b4'} if 'is_anomaly' in data.columns else None
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Risk score data not available for correlation analysis")

def show_raw_event_inspection(data):
    """Show raw event inspection for advanced analysis"""
    if 'raw_event' not in data.columns:
        st.info("Raw event inspection not available")
        return
    
    st.subheader("🔬 Raw Event Inspection")
    
    # Filter for high risk or anomalous events
    high_risk_data = data[(data['risk_score'] >= 70) | (data['is_anomaly'] == True)] if 'risk_score' in data.columns and 'is_anomaly' in data.columns else data.head(5)
    
    if not high_risk_data.empty:
        st.write(f"**Events to Investigate** ({len(high_risk_data)} events)")
        
        for idx, row in high_risk_data.head(3).iterrows():
            with st.expander(f"Event: {row.get('activity', 'Unknown')} - Risk: {row.get('risk_score', 0):.1f}"):
                st.json(row['raw_event'])
    else:
        st.info("No events found for detailed inspection")

def create_timeline_analysis(data):
    """Create advanced timeline analysis"""
    if 'timestamp' not in data.columns:
        st.info("Timeline analysis data not available")
        return
    
    st.subheader("⏰ Advanced Timeline Analysis")
    
    # Convert timestamp if needed
    data['timestamp'] = pd.to_datetime(data['timestamp'], errors='coerce')
    data = data.dropna(subset=['timestamp'])
    
    if data.empty:
        st.info("No valid timestamp data for timeline analysis")
        return
        
    hourly_activity = data.groupby(data['timestamp'].dt.hour).agg({
        'risk_score': 'mean' if 'risk_score' in data.columns else 'count'
    }).reset_index()
    
    fig = go.Figure()
    
    if 'risk_score' in data.columns:
        fig.add_trace(go.Scatter(
            x=hourly_activity['timestamp'],
            y=hourly_activity['risk_score'],
            name='Average Risk Score',
            line=dict(color='#FF6B6B', width=3)
        ))
    
    if 'anomaly_score' in data.columns:
        hourly_anomaly = data.groupby(data['timestamp'].dt.hour)['anomaly_score'].mean().reset_index()
        fig.add_trace(go.Scatter(
            x=hourly_anomaly['timestamp'],
            y=hourly_anomaly['anomaly_score'],
            name='Average Anomaly Score',
            line=dict(color='#1f77b4', width=3),
            yaxis='y2'
        ))
        
        fig.update_layout(
            yaxis2=dict(
                title='Anomaly Score',
                overlaying='y',
                side='right'
            )
        )
    
    fig.update_layout(
        title='Hourly Activity Patterns',
        xaxis_title='Hour of Day',
        yaxis_title='Risk Score' if 'risk_score' in data.columns else 'Event Count',
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)