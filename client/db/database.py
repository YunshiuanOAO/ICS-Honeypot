import sqlite3
import json
import threading
from datetime import datetime
import os

class LogDB:
    def __init__(self, db_path="client_logs.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
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

                # Whitelist log table — same schema as logs, but kept
                # separate so it never bleeds into the attack pipeline.
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS whitelist_logs (
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
            except Exception as e:
                print(f"[LogDB] Error initializing database: {e}")
            finally:
                conn.close()

    def log_interaction(self, attacker_ip, protocol, request_data, response_data, metadata=None, timestamp=None):
        with self._lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                timestamp = timestamp or datetime.now().isoformat()
                
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
                    metadata = json.dumps(metadata, ensure_ascii=False)
                elif metadata is None:
                    metadata = "{}"

                if request_data is None:
                    request_data = ""
                if response_data is None:
                    response_data = ""

                cursor.execute('''
                    INSERT INTO logs (timestamp, attacker_ip, protocol, request_data, response_data, metadata, uploaded)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                ''', (timestamp, attacker_ip, protocol, str(request_data), str(response_data), metadata))
                
                conn.commit()
                print(f"[{timestamp}] Logged {protocol} interaction from {attacker_ip}")
            except sqlite3.Error as e:
                print(f"[LogDB] Error logging interaction: {e}")
            finally:
                if conn:
                    conn.close()

    def get_logs(self, limit=100):
        # Only get unsent logs
        with self._lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM logs WHERE uploaded = 0 ORDER BY id ASC LIMIT ?', (limit,))
                rows = cursor.fetchall()
                return rows
            except sqlite3.Error as e:
                print(f"[LogDB] Error getting logs: {e}")
                return []
            finally:
                if conn:
                    conn.close()
        
    def mark_uploaded(self, log_ids):
        if not log_ids:
            return
        with self._lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                placeholders = ','.join('?' for _ in log_ids)
                cursor.execute(f'UPDATE logs SET uploaded = 1 WHERE id IN ({placeholders})', log_ids)
                conn.commit()
            except sqlite3.Error as e:
                print(f"[LogDB] Error marking logs as uploaded: {e}")
            finally:
                if conn:
                    conn.close()

    # ---------- Whitelist log methods ----------

    def log_whitelist_interaction(self, attacker_ip, protocol, request_data, response_data, metadata=None, timestamp=None):
        """Insert a whitelist (friendly) interaction — kept separate from attack logs."""
        with self._lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                timestamp = timestamp or datetime.now().isoformat()

                if isinstance(request_data, (dict, list)):
                    request_data = json.dumps(request_data)
                elif isinstance(request_data, bytes):
                    request_data = request_data.hex()

                if isinstance(response_data, (dict, list)):
                    response_data = json.dumps(response_data)
                elif isinstance(response_data, bytes):
                    response_data = response_data.hex()

                if isinstance(metadata, (dict, list)):
                    metadata = json.dumps(metadata, ensure_ascii=False)
                elif metadata is None:
                    metadata = "{}"

                if request_data is None:
                    request_data = ""
                if response_data is None:
                    response_data = ""

                cursor.execute('''
                    INSERT INTO whitelist_logs (timestamp, attacker_ip, protocol, request_data, response_data, metadata, uploaded)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                ''', (timestamp, attacker_ip, protocol, str(request_data), str(response_data), metadata))

                conn.commit()
                print(f"[{timestamp}] Whitelist-logged {protocol} from {attacker_ip}")
            except sqlite3.Error as e:
                print(f"[LogDB] Error logging whitelist interaction: {e}")
            finally:
                if conn:
                    conn.close()

    def get_whitelist_logs(self, limit=100):
        with self._lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT * FROM whitelist_logs WHERE uploaded = 0 ORDER BY id ASC LIMIT ?',
                    (limit,),
                )
                return cursor.fetchall()
            except sqlite3.Error as e:
                print(f"[LogDB] Error getting whitelist logs: {e}")
                return []
            finally:
                if conn:
                    conn.close()

    def mark_whitelist_uploaded(self, log_ids):
        if not log_ids:
            return
        with self._lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                placeholders = ','.join('?' for _ in log_ids)
                cursor.execute(
                    f'UPDATE whitelist_logs SET uploaded = 1 WHERE id IN ({placeholders})',
                    log_ids,
                )
                conn.commit()
            except sqlite3.Error as e:
                print(f"[LogDB] Error marking whitelist logs as uploaded: {e}")
            finally:
                if conn:
                    conn.close()
