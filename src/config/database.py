import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import psycopg2
from psycopg2.extras import RealDictCursor
import streamlit as st

def get_database_url():
    """Get database URL from secrets, env, or use default"""
    # Try Streamlit secrets first
    try:
        if hasattr(st, 'secrets') and 'DATABASE_URL' in st.secrets:
            return st.secrets['DATABASE_URL']
    except:
        pass
    
    # Try environment variable
    db_url = os.getenv('DATABASE_URL')
    if db_url:
        return db_url
    
    # Default local development (change as needed)
    return "postgresql://postgres:password@localhost:5432/threat_detection"

# SQLAlchemy setup
DATABASE_URL = get_database_url()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_raw_connection():
    """Get raw psycopg2 connection for complex queries"""
    conn = psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )
    return conn
