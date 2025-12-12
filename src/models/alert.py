from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from src.config.database import Base

class Alert(Base):
    __tablename__ = "alerts"
    
    alert_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    severity = Column(String(20))  # low, medium, high, critical
    alert_type = Column(String(100))
    description = Column(Text)
    source_ip = Column(String(50))
    affected_resource = Column(String(255))
    status = Column(String(20), default='new')  # new, investigating, resolved, false_positive
    assigned_to = Column(Integer, ForeignKey('users.user_id'), nullable=True)
    resolution_notes = Column(Text)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="alerts", foreign_keys=[user_id])
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    
    def __repr__(self):
        return f"<Alert(type='{self.alert_type}', severity='{self.severity}')>"
