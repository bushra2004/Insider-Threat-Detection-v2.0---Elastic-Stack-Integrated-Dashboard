from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_
from datetime import datetime, timedelta
import pandas as pd
from src.models.user import User
from src.models.alert import Alert
from src.models.rule import ThreatRule

class DatabaseOperations:
    def __init__(self, session: Session):
        self.session = session
    
    # ===== USER OPERATIONS =====
    def create_user(self, username, email, department, role, **kwargs):
        """Create a new user"""
        user = User(
            username=username,
            email=email,
            department=department,
            role=role,
            **kwargs
        )
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user
    
    def get_user(self, user_id):
        """Get user by ID"""
        return self.session.query(User).filter(User.user_id == user_id).first()
    
    def get_user_by_username(self, username):
        """Get user by username"""
        return self.session.query(User).filter(User.username == username).first()
    
    def get_all_users(self, active_only=True):
        """Get all users"""
        query = self.session.query(User)
        if active_only:
            query = query.filter(User.employee_status == 'active')
        return query.order_by(User.username).all()
    
    def update_user_risk_score(self, user_id, risk_score):
        """Update user's risk score"""
        user = self.get_user(user_id)
        if user:
            user.risk_score = risk_score
            user.is_high_risk = risk_score > 70  # Threshold for high risk
            self.session.commit()
        return user
    
    # ===== ALERT OPERATIONS =====
    def create_alert(self, user_id, severity, alert_type, description, **kwargs):
        """Create a new alert"""
        alert = Alert(
            user_id=user_id,
            severity=severity,
            alert_type=alert_type,
            description=description,
            **kwargs
        )
        self.session.add(alert)
        self.session.commit()
        self.session.refresh(alert)
        return alert
    
    def get_alert(self, alert_id):
        """Get alert by ID"""
        return self.session.query(Alert).filter(Alert.alert_id == alert_id).first()
    
    def get_recent_alerts(self, hours=24, severity=None, status=None):
        """Get recent alerts"""
        query = self.session.query(Alert).filter(
            Alert.timestamp >= datetime.utcnow() - timedelta(hours=hours)
        )
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        if status:
            query = query.filter(Alert.status == status)
        
        return query.order_by(desc(Alert.timestamp)).all()
    
    def update_alert_status(self, alert_id, status, resolution_notes=None):
        """Update alert status"""
        alert = self.get_alert(alert_id)
        if alert:
            alert.status = status
            if status == 'resolved':
                alert.resolved_at = datetime.utcnow()
            if resolution_notes:
                alert.resolution_notes = resolution_notes
            self.session.commit()
        return alert
    
    # ===== ANALYTICS OPERATIONS =====
    def get_department_risk_stats(self):
        """Get risk statistics by department"""
        query = """
        SELECT 
            department,
            COUNT(*) as user_count,
            AVG(risk_score) as avg_risk_score,
            SUM(CASE WHEN is_high_risk THEN 1 ELSE 0 END) as high_risk_count
        FROM users
        WHERE employee_status = 'active'
        GROUP BY department
        ORDER BY avg_risk_score DESC
        """
        
        return pd.read_sql(query, self.session.bind)
    
    def get_alert_trends(self, days=7):
        """Get alert trends over time"""
        query = f"""
        SELECT 
            DATE(timestamp) as date,
            severity,
            COUNT(*) as alert_count
        FROM alerts
        WHERE timestamp >= CURRENT_DATE - INTERVAL '{days} days'
        GROUP BY DATE(timestamp), severity
        ORDER BY date DESC
        """
        
        return pd.read_sql(query, self.session.bind)
    
    def get_top_risky_users(self, limit=10):
        """Get top risky users"""
        query = """
        SELECT 
            username,
            department,
            risk_score,
            employee_status,
            (SELECT COUNT(*) FROM alerts WHERE alerts.user_id = users.user_id AND alerts.timestamp >= CURRENT_DATE - INTERVAL '7 days') as recent_alerts
        FROM users
        WHERE employee_status = 'active'
        ORDER BY risk_score DESC, recent_alerts DESC
        LIMIT %s
        """
        
        return pd.read_sql(query, self.session.bind, params=(limit,))
    
    # ===== RULE OPERATIONS =====
    def create_rule(self, rule_name, description, condition, action, threshold, severity):
        """Create a new threat rule"""
        rule = ThreatRule(
            rule_name=rule_name,
            description=description,
            condition=condition,
            action=action,
            threshold=threshold,
            severity=severity
        )
        self.session.add(rule)
        self.session.commit()
        self.session.refresh(rule)
        return rule
    
    def get_active_rules(self):
        """Get all active threat rules"""
        return self.session.query(ThreatRule).filter(ThreatRule.is_active == True).all()
