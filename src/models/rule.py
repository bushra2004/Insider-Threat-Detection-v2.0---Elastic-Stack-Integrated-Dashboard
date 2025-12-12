from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.sql import func
from src.config.database import Base

class ThreatRule(Base):
    __tablename__ = "threat_rules"
    
    rule_id = Column(Integer, primary_key=True, index=True)
    rule_name = Column(String(200), unique=True, nullable=False)
    description = Column(Text)
    condition = Column(JSON)  # Stores rule logic as JSON
    action = Column(String(100))
    threshold = Column(Integer)
    severity = Column(String(20))
    is_active = Column(Boolean, default=True)
    created_by = Column(Integer)  # user_id
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_triggered = Column(DateTime(timezone=True), nullable=True)
    trigger_count = Column(Integer, default=0)
    
    def __repr__(self):
        return f"<Rule(name='{self.rule_name}', active={self.is_active})>"
