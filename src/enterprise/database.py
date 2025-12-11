import psycopg2
from contextlib import contextmanager
import pandas as pd

class EnterpriseDatabase:
    def __init__(self):
        self.connection_params = {
            'host': 'localhost',
            'database': 'threat_detection_enterprise',
            'user': 'threat_admin',
            'password': 'secure_password_123',
            'port': 5432
        }
    
    @contextmanager
    def get_connection(self):
        conn = psycopg2.connect(**self.connection_params)
        try:
            yield conn
        finally:
            conn.close()
    
    def initialize_database(self):
        """Initialize enterprise database schema"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # Companies table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS companies (
                        company_id VARCHAR(50) PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        config JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status VARCHAR(20) DEFAULT 'active'
                    )
                """)
                
                # Users table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        user_id SERIAL PRIMARY KEY,
                        company_id VARCHAR(50) REFERENCES companies(company_id),
                        username VARCHAR(100) UNIQUE NOT NULL,
                        email VARCHAR(255),
                        role VARCHAR(50),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Audit logs table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        log_id SERIAL PRIMARY KEY,
                        company_id VARCHAR(50),
                        user_id INTEGER,
                        action VARCHAR(100),
                        resource VARCHAR(100),
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ip_address INET,
                        details JSONB
                    )
                """)
                
                conn.commit()

class ComplianceManager:
    def __init__(self):
        self.db = EnterpriseDatabase()
    
    def generate_compliance_report(self, company_id, timeframe_days=30):
        """Generate compliance reports for SOX, GDPR, etc."""
        with self.db.get_connection() as conn:
            query = """
                SELECT 
                    COUNT(*) as total_events,
                    COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_events,
                    COUNT(DISTINCT user_id) as unique_users,
                    AVG(risk_score) as avg_risk_score
                FROM threat_events 
                WHERE company_id = %s AND timestamp >= NOW() - INTERVAL '%s days'
            """
            df = pd.read_sql_query(query, conn, params=(company_id, timeframe_days))
            return df