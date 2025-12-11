import streamlit as st
from authlib.integrations.requests_client import OAuth2Session
import jwt
from datetime import datetime, timedelta
import hashlib

class EnterpriseAuth:
    def __init__(self):
        self.oauth = OAuth2Session(
            client_id=st.secrets.get("OAUTH_CLIENT_ID"),
            client_secret=st.secrets.get("OAUTH_CLIENT_SECRET"),
            scope='openid profile email'
        )
    
    def authenticate_user(self, username, password):
        """Enterprise authentication with multi-factor support"""
        # In production, integrate with Active Directory/LDAP
        if self._verify_credentials(username, password):
            if self._check_mfa(username):
                return self._generate_session_token(username)
        return None
    
    def _verify_credentials(self, username, password):
        """Verify against enterprise directory"""
        # Integration with Active Directory/LDAP
        return True  # Replace with actual auth
    
    def _check_mfa(self, username):
        """Multi-factor authentication"""
        return True  # Integrate with Duo, Google Authenticator, etc.
    
    def _generate_session_token(self, username):
        """Generate JWT session token"""
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=8),
            'iss': 'insider-threat-detection'
        }
        return jwt.encode(payload, st.secrets.get("JWT_SECRET"), algorithm='HS256')

class RoleBasedAccessControl:
    ROLES = {
        'security_analyst': ['view_alerts', 'investigate', 'export_data', 'run_queries'],
        'security_manager': ['view_reports', 'team_management', 'configure_rules'],
        'compliance_officer': ['view_compliance', 'generate_reports', 'audit_logs'],
        'system_admin': ['all_permissions', 'user_management', 'system_config']
    }
    
    def check_permission(self, user_role, permission):
        return permission in self.ROLES.get(user_role, [])