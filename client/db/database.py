import sqlite3
import json
from datetime import datetime
import os

class LogDB:
    def __init__(self, db_path="client_logs.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                attacker_ip TEXT,
                protocol TEXT,
                request_data TEXT,
                response_data TEXT,
                metadata TEXT,
                uploaded INTEGER DEFAULT 0
            )
        ''')
        
        # Migration for existing DB
        try:
            cursor.execute('ALTER TABLE logs ADD COLUMN uploaded INTEGER DEFAULT 0')
            # Mark existing logs as uploaded to avoid re-sending old history
            cursor.execute('UPDATE logs SET uploaded = 1')
        except sqlite3.OperationalError:
            pass
            
        conn.commit()
        conn.close()

    def log_interaction(self, attacker_ip, protocol, request_data, response_data, metadata=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        
        # Convert dicts/bytes to string for storage if necessary
        if isinstance(request_data, (dict, list)):
            request_data = json.dumps(request_data)
        elif isinstance(request_data, bytes):
            request_data = request_data.hex()
            
        if isinstance(response_data, (dict, list)):
            response_data = json.dumps(response_data)
        elif isinstance(response_data, bytes):
            response_data = response_data.hex()

        if isinstance(metadata, (dict, list)):
            metadata = json.dumps(metadata)

        cursor.execute('''
            INSERT INTO logs (timestamp, attacker_ip, protocol, request_data, response_data, metadata, uploaded)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        ''', (timestamp, attacker_ip, protocol, str(request_data), str(response_data), str(metadata)))
        
        conn.commit()
        conn.close()
        print(f"[{timestamp}] Logged {protocol} interaction from {attacker_ip}")

    def get_logs(self, limit=100):
        # Only get unsent logs
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM logs WHERE uploaded = 0 ORDER BY id ASC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
        
    def mark_uploaded(self, log_ids):
        if not log_ids: return
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        placeholders = ','.join('?' for _ in log_ids)
        cursor.execute(f'UPDATE logs SET uploaded = 1 WHERE id IN ({placeholders})', log_ids)
        conn.commit()
        conn.close()
