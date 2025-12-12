from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, Date, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.config.database import Base

class User(Base):
    __tablename__ = "users"
    
    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    department = Column(String(100))
    role = Column(String(50))
    access_level = Column(Integer, default=1)
    risk_score = Column(Float, default=0.0)
    employee_status = Column(String(20), default='active')
    hire_date = Column(Date)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))
    is_high_risk = Column(Boolean, default=False)
    
    # Relationships
    alerts = relationship("Alert", back_populates="user")
    
    def __repr__(self):
        return f"<User(username='{self.username}', department='{self.department}')>"
