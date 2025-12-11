# simple_db.py
# Simple SQLite database for storing alerts
import sqlite3
import datetime

def init_database():
    conn = sqlite3.connect('threats.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            severity TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_alert(severity, message):
    conn = sqlite3.connect('threats.db')
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO alerts (timestamp, severity, message)
        VALUES (?, ?, ?)
    ''', (timestamp, severity, message))
    conn.commit()
    conn.close()

def get_alerts(limit=10):
    conn = sqlite3.connect('threats.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, severity, message 
        FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    alerts = cursor.fetchall()
    conn.close()
    return alerts