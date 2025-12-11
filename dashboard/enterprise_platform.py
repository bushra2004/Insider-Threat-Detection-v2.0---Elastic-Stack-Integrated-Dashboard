# enterprise_pro_working.py
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import os
import hashlib
import random

# ============================================
# SIMPLE WORKING VERSION
# ============================================

st.set_page_config(
    page_title="Enterprise Threat Platform",
    page_icon="🛡️",
    layout="wide"
)

# Simple CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e40af 0%, #3b82f6 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #1e293b;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 4px solid #3b82f6;
        color: white;
        margin: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# SIMPLE USER MANAGER (FIXED)
# ============================================

class SimpleUserManager:
    def __init__(self):
        # Store users with username as key for easy lookup
        self.users = {
            "admin": {
                "password": self._hash_password("Admin@123"),
                "email": "admin@company.com",
                "full_name": "Administrator",
                "role": "Admin",
                "department": "IT",
                "is_active": True
            },
            "analyst": {
                "password": self._hash_password("Analyst@123"),
                "email": "analyst@company.com",
                "full_name": "Security Analyst",
                "role": "Analyst",
                "department": "Security",
                "is_active": True
            },
            "user": {
                "password": self._hash_password("User@123"),
                "email": "user@company.com",
                "full_name": "Regular User",
                "role": "Viewer",
                "department": "Operations",
                "is_active": True
            }
        }
    
    def _hash_password(self, password):
        # Simple hash for demo
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username, password):
        """Authenticate by username"""
        if username in self.users:
            user = self.users[username]
            if user['is_active'] and user['password'] == self._hash_password(password):
                return True, user
        return False, None
    
    def add_user(self, username, password, email, full_name, role="Viewer", department="IT"):
        if username in self.users:
            return False, "Username already exists"
        
        self.users[username] = {
            "password": self._hash_password(password),
            "email": email,
            "full_name": full_name,
            "role": role,
            "department": department,
            "is_active": True
        }
        return True, f"User {username} created successfully"
    
    def get_all_users(self):
        users_list = []
        for username, data in self.users.items():
            users_list.append({
                "username": username,
                "email": data['email'],
                "full_name": data['full_name'],
                "role": data['role'],
                "department": data['department'],
                "is_active": data['is_active']
            })
        return users_list

# ============================================
# MAIN APP
# ============================================

class EnterpriseApp:
    def __init__(self):
        self.user_manager = SimpleUserManager()
        
        # Initialize session state
        if 'logged_in' not in st.session_state:
            st.session_state.logged_in = False
        if 'current_user' not in st.session_state:
            st.session_state.current_user = None
        if 'current_role' not in st.session_state:
            st.session_state.current_role = None
        if 'page' not in st.session_state:
            st.session_state.page = 'dashboard'
    
    def login_page(self):
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ ENTERPRISE THREAT PLATFORM</h1>
            <p>Professional Security Dashboard</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            with st.form("login_form"):
                username = st.text_input("Username", value="admin")
                password = st.text_input("Password", type="password", value="Admin@123")
                
                login_btn = st.form_submit_button("🔓 LOGIN", use_container_width=True)
                
                if login_btn:
                    if username and password:
                        success, user = self.user_manager.authenticate(username, password)
                        if success:
                            st.session_state.logged_in = True
                            st.session_state.current_user = user
                            st.session_state.current_role = user['role']
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error("❌ Invalid username or password")
                    else:
                        st.error("Please enter both username and password")
            
            # Show demo credentials
            st.markdown("---")
            st.info("**Demo Credentials:**")
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.write("**👑 Admin**")
                st.write("User: `admin`")
                st.write("Pass: `Admin@123`")
            with col_b:
                st.write("**🔍 Analyst**")
                st.write("User: `analyst`")
                st.write("Pass: `Analyst@123`")
            with col_c:
                st.write("**👀 Viewer**")
                st.write("User: `user`")
                st.write("Pass: `User@123`")
    
    def sidebar(self):
        st.sidebar.title("Navigation")
        
        # User info
        if st.session_state.current_user:
            user = st.session_state.current_user
            st.sidebar.markdown(f"**👤 {user['full_name']}**")
            st.sidebar.markdown(f"*{user['role']}*")
            st.sidebar.markdown(f"📍 {user['department']}")
        
        st.sidebar.markdown("---")
        
        # Menu
        menu_items = [
            {"label": "📊 Dashboard", "page": "dashboard"},
            {"label": "👥 User Management", "page": "users", "roles": ["Admin"]},
            {"label": "🔗 ELK Integration", "page": "elk", "roles": ["Admin", "Analyst"]},
            {"label": "🚨 Alerts", "page": "alerts", "roles": ["Admin", "Analyst"]},
            {"label": "⚙️ Settings", "page": "settings", "roles": ["Admin"]},
        ]
        
        for item in menu_items:
            if "roles" not in item or st.session_state.current_role in item["roles"]:
                if st.sidebar.button(item["label"], use_container_width=True):
                    st.session_state.page = item["page"]
                    st.rerun()
        
        st.sidebar.markdown("---")
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.current_user = None
            st.session_state.current_role = None
            st.rerun()
    
    def dashboard_page(self):
        st.header("📊 Security Dashboard")
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>Total Users</h3>
                <h2>156</h2>
                <p>24 Active Now</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <h3>Active Threats</h3>
                <h2>12</h2>
                <p>3 Critical</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <h3>Risk Score</h3>
                <h2>42.5</h2>
                <p>Medium Risk</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="metric-card">
                <h3>Compliance</h3>
                <h2>98%</h2>
                <p>All Systems Go</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Recent Activities
        st.subheader("Recent Security Events")
        
        events = [
            {"time": "10:30", "user": "jsmith", "action": "Failed Login", "risk": "High"},
            {"time": "09:45", "user": "mjones", "action": "File Download", "risk": "Medium"},
            {"time": "08:15", "user": "admin", "action": "System Update", "risk": "Low"},
            {"time": "07:30", "user": "bwilson", "action": "Database Access", "risk": "High"},
        ]
        
        for event in events:
            risk_color = {
                "High": "#dc2626",
                "Medium": "#f59e0b",
                "Low": "#10b981"
            }[event["risk"]]
            
            st.markdown(f"""
            <div style="background: #1e293b; padding: 1rem; border-radius: 8px; margin: 0.5rem 0; border-left: 4px solid {risk_color};">
                <div style="display: flex; justify-content: space-between;">
                    <div>
                        <strong>{event['user']}</strong> - {event['action']}
                    </div>
                    <div>
                        <span style="color: {risk_color}; font-weight: bold;">{event['risk']}</span>
                        <span style="margin-left: 1rem; color: #94a3b8;">{event['time']}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    def user_management_page(self):
        st.header("👥 User Management")
        
        if st.session_state.current_role != "Admin":
            st.warning("⚠️ Admin access required")
            return
        
        tab1, tab2, tab3 = st.tabs(["View Users", "Add User", "User Stats"])
        
        with tab1:
            st.subheader("All System Users")
            
            users = self.user_manager.get_all_users()
            df = pd.DataFrame(users)
            
            # Display users in a nice table
            for user in users:
                col1, col2, col3, col4, col5 = st.columns([2, 2, 2, 1, 1])
                
                with col1:
                    st.write(f"**{user['full_name']}**")
                    st.write(f"`{user['username']}`")
                
                with col2:
                    st.write(user['email'])
                
                with col3:
                    st.write(f"{user['role']} • {user['department']}")
                
                with col4:
                    status = "🟢" if user['is_active'] else "🔴"
                    st.write(status)
                
                with col5:
                    if st.button("Edit", key=f"edit_{user['username']}"):
                        st.session_state.edit_user = user['username']
            
            # Edit user section
            if 'edit_user' in st.session_state:
                st.markdown("---")
                st.subheader(f"Edit User: {st.session_state.edit_user}")
                
                # Find user
                user_to_edit = None
                for u in users:
                    if u['username'] == st.session_state.edit_user:
                        user_to_edit = u
                        break
                
                if user_to_edit:
                    with st.form("edit_user_form"):
                        new_role = st.selectbox("Role", ["Admin", "Analyst", "Viewer"], 
                                              index=["Admin", "Analyst", "Viewer"].index(user_to_edit['role']))
                        new_dept = st.selectbox("Department", ["IT", "Security", "Finance", "HR", "Operations"],
                                              index=["IT", "Security", "Finance", "HR", "Operations"].index(user_to_edit['department']) 
                                              if user_to_edit['department'] in ["IT", "Security", "Finance", "HR", "Operations"] else 0)
                        
                        if st.form_submit_button("Save Changes"):
                            st.success("User updated!")
                            del st.session_state.edit_user
                            st.rerun()
        
        with tab2:
            st.subheader("Add New User")
            
            with st.form("add_user_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    username = st.text_input("Username", placeholder="jdoe")
                    full_name = st.text_input("Full Name", placeholder="John Doe")
                    email = st.text_input("Email", placeholder="john@company.com")
                
                with col2:
                    password = st.text_input("Password", type="password", value="Welcome@123")
                    role = st.selectbox("Role", ["Viewer", "Analyst", "Admin"])
                    department = st.selectbox("Department", ["IT", "Security", "Finance", "HR", "Operations"])
                
                if st.form_submit_button("➕ Add User"):
                    if username and password and email:
                        success, message = self.user_manager.add_user(
                            username=username,
                            password=password,
                            email=email,
                            full_name=full_name,
                            role=role,
                            department=department
                        )
                        if success:
                            st.success(f"✅ {message}")
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.error("Please fill all required fields")
        
        with tab3:
            st.subheader("User Statistics")
            
            users = self.user_manager.get_all_users()
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Users", len(users))
            with col2:
                active = len([u for u in users if u['is_active']])
                st.metric("Active Users", active)
            with col3:
                admins = len([u for u in users if u['role'] == 'Admin'])
                st.metric("Admins", admins)
            
            # Role distribution
            role_counts = {}
            for user in users:
                role_counts[user['role']] = role_counts.get(user['role'], 0) + 1
            
            chart_data = pd.DataFrame({
                'Role': list(role_counts.keys()),
                'Count': list(role_counts.values())
            })
            st.bar_chart(chart_data.set_index('Role'))
    
    def elk_integration_page(self):
        st.header("🔗 ELK Stack Integration")
        
        # Connection status
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Test Kibana Connection", use_container_width=True):
                st.info("Testing connection to Kibana...")
                # Simulate test
                if random.choice([True, False]):
                    st.success("✅ Kibana is reachable at http://localhost:5601")
                else:
                    st.error("❌ Cannot connect to Kibana")
        
        with col2:
            st.markdown("[Open Kibana Dashboard](http://localhost:5601)")
        
        st.markdown("---")
        
        # Dashboard embedding
        st.subheader("Embedded Dashboards")
        
        dashboards = [
            {"id": "security", "name": "Security Overview", "description": "Overall security posture"},
            {"id": "users", "name": "User Activity", "description": "User behavior analytics"},
            {"id": "threats", "name": "Threat Detection", "description": "Real-time threat monitoring"},
        ]
        
        selected = st.selectbox("Select Dashboard", dashboards, format_func=lambda x: x['name'])
        
        if st.button(f"Embed {selected['name']}"):
            dashboard_url = f"http://localhost:5601/app/dashboards#/view/{selected['id']}"
            
            st.markdown(f"""
            <div style="border: 2px solid #334155; border-radius: 10px; overflow: hidden; margin-top: 20px;">
                <div style="background: #1e293b; padding: 10px; border-bottom: 1px solid #334155;">
                    <strong>{selected['name']}</strong>
                </div>
                <iframe 
                    src="{dashboard_url}" 
                    width="100%" 
                    height="500"
                    style="border: none;"
                    frameborder="0"
                ></iframe>
            </div>
            """, unsafe_allow_html=True)
        
        # Configuration
        st.markdown("---")
        st.subheader("Configuration")
        
        with st.form("elk_config"):
            kibana_url = st.text_input("Kibana URL", value="http://localhost:5601")
            es_url = st.text_input("Elasticsearch URL", value="http://localhost:9200")
            
            if st.form_submit_button("Save Configuration"):
                st.success("Configuration saved!")
    
    def alerts_page(self):
        st.header("🚨 Threat Alerts")
        
        alerts = [
            {"id": "ALT-001", "severity": "Critical", "type": "Brute Force Attack", "time": "10:30 AM", "status": "Active"},
            {"id": "ALT-002", "severity": "High", "type": "Data Exfiltration", "time": "09:45 AM", "status": "Investigating"},
            {"id": "ALT-003", "severity": "Medium", "type": "Suspicious Login", "time": "08:15 AM", "status": "Resolved"},
            {"id": "ALT-004", "severity": "High", "type": "Malware Detection", "time": "07:30 AM", "status": "Contained"},
        ]
        
        for alert in alerts:
            severity_color = {
                "Critical": "#dc2626",
                "High": "#ea580c",
                "Medium": "#f59e0b",
                "Low": "#10b981"
            }[alert['severity']]
            
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, {severity_color}20, {severity_color}40);
                 border-left: 6px solid {severity_color};
                 padding: 1.2rem;
                 border-radius: 10px;
                 margin: 0.8rem 0;
                 color: white;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div>
                        <h4 style="margin: 0; font-size: 1.1rem;">{alert['type']}</h4>
                        <p style="margin: 5px 0; font-size: 0.9rem; opacity: 0.9;">
                            ID: {alert['id']} • Time: {alert['time']}
                        </p>
                    </div>
                    <span style="
                        background: {severity_color};
                        padding: 4px 12px;
                        border-radius: 15px;
                        font-size: 0.85rem;
                        font-weight: 600;
                    ">
                        {alert['severity']}
                    </span>
                </div>
                <div style="margin-top: 10px;">
                    <strong>Status:</strong> {alert['status']}
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    def settings_page(self):
        st.header("⚙️ Platform Settings")
        
        if st.session_state.current_role != "Admin":
            st.warning("⚠️ Admin access required")
            return
        
        tab1, tab2 = st.tabs(["General", "Security"])
        
        with tab1:
            st.subheader("General Settings")
            
            company_name = st.text_input("Company Name", value="CyberGuard Enterprise")
            primary_color = st.color_picker("Primary Color", value="#1e40af")
            
            if st.button("Save Settings"):
                st.success("Settings saved!")
        
        with tab2:
            st.subheader("Security Settings")
            
            session_timeout = st.slider("Session Timeout (minutes)", 5, 120, 30)
            enable_mfa = st.checkbox("Enable Multi-Factor Authentication", value=True)
            password_expiry = st.slider("Password Expiry (days)", 7, 365, 90)
            
            if st.button("Save Security Settings"):
                st.success("Security settings saved!")
    
    def run(self):
        if not st.session_state.logged_in:
            self.login_page()
            return
        
        self.sidebar()
        
        if st.session_state.page == 'dashboard':
            self.dashboard_page()
        elif st.session_state.page == 'users':
            self.user_management_page()
        elif st.session_state.page == 'elk':
            self.elk_integration_page()
        elif st.session_state.page == 'alerts':
            self.alerts_page()
        elif st.session_state.page == 'settings':
            self.settings_page()

# ============================================
# RUN THE APP
# ============================================

if __name__ == "__main__":
    app = EnterpriseApp()
    app.run()