import sqlite3
import json
from datetime import datetime
import os

class ServerDB:
    def __init__(self, db_path="server.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # AGENTS Table: Stores registered agents and their configs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                node_id TEXT PRIMARY KEY,
                name TEXT,
                ip TEXT,
                last_heartbeat TEXT,
                status TEXT, -- Online, Offline
                config_json TEXT,
                is_active INTEGER DEFAULT 1 -- 1: Active, 0: Inactive
            )
        ''')
        
        # Migration: Add is_active if it doesn't exist (for existing DBs)
        try:
            cursor.execute('ALTER TABLE agents ADD COLUMN is_active INTEGER DEFAULT 1')
        except sqlite3.OperationalError:
            pass # Column likely already exists
        
        # LOGS Table: Stores logs uploaded by agents
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                node_id TEXT,
                protocol TEXT,
                attacker_ip TEXT,
                request_data TEXT,
                response_data TEXT,
                metadata TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    # --- Agent Management ---
    
    def register_agent(self, node_id, name="Unknown Agent", ip="0.0.0.0", config=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        if config is None:
            # Default config if new and no config provided
            config = {
                "node_id": node_id,
                "server_url": "http://localhost:8000",
                "plcs": []
            }
        
        config_str = json.dumps(config)
        
        # Check if agent exists to preserve is_active status if strictly updating?
        # But 'register_agent' usually implies new or overwrite.
        # User said "Add an agent on server".
        # If it's a re-registration (heartbeat), we might not want to reset is_active.
        # But this function is used by heartbeat AND manual add.
        # Let's use INSERT OR REPLACE but try to preserve is_active if possible?
        # Actually, heartbeat uses 'get_agent' then 'register_agent' if not found.
        # Manual Add calls 'register_agent'.
        
        # For INSERT OR REPLACE, we lose old data.
        # Let's check existence first.
        cursor.execute('SELECT is_active FROM agents WHERE node_id = ?', (node_id,))
        row = cursor.fetchone()
        # Default to 0 (Inactive) if new agent
        is_active = row[0] if row else 0
        
        cursor.execute('''
            INSERT OR REPLACE INTO agents (node_id, name, ip, last_heartbeat, status, config_json, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (node_id, name, ip, now, "Online", config_str, is_active))
        
        conn.commit()
        conn.close()
        return config

    def update_heartbeat(self, node_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('UPDATE agents SET last_heartbeat = ?, status = ? WHERE node_id = ?', 
                       (now, "Online", node_id))
        
        changes = cursor.rowcount
        conn.commit()
        conn.close()
        return changes > 0

    def get_agent(self, node_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM agents WHERE node_id = ?', (node_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    def get_all_agents(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM agents ORDER BY node_id')
        rows = cursor.fetchall()
        conn.close()
        
        agents = []
        for row in rows:
            agent = dict(row)
            # Check timeout (30 seconds)
            try:
                last_seen = datetime.fromisoformat(agent['last_heartbeat'])
                if (datetime.now() - last_seen).total_seconds() > 30:
                    agent['status'] = 'Offline'
            except Exception:
                pass # Parse error or None
            agents.append(agent)
            
        return agents
        
    def update_agent_config(self, node_id, config_dict, name=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        config_str = json.dumps(config_dict)
        
        if name:
            cursor.execute('UPDATE agents SET config_json = ?, name = ? WHERE node_id = ?', (config_str, name, node_id))
        else:
            cursor.execute('UPDATE agents SET config_json = ? WHERE node_id = ?', (config_str, node_id))
            
        conn.commit()
        conn.close()

    def rename_agent(self, old_node_id, new_node_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            # Check if new ID exists
            cursor.execute('SELECT 1 FROM agents WHERE node_id = ?', (new_node_id,))
            if cursor.fetchone():
                return False, "New Node ID already exists"

            # Update agents table
            cursor.execute('UPDATE agents SET node_id = ? WHERE node_id = ?', (new_node_id, old_node_id))
            
            # Update logs table
            cursor.execute('UPDATE logs SET node_id = ? WHERE node_id = ?', (new_node_id, old_node_id))
            
            conn.commit()
            return True, "Renamed successfully"
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    def delete_agent(self, node_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM agents WHERE node_id = ?', (node_id,))
        conn.commit()
        conn.close()

    def toggle_agent_active(self, node_id, is_active):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Ensure boolean/int mapping
        val = 1 if is_active else 0
        cursor.execute('UPDATE agents SET is_active = ? WHERE node_id = ?', (val, node_id))
        conn.commit()
        conn.close()

    # --- Log Management ---

    def _log_to_json_file(self, log_entry):
        try:
            # Ensure log directory exists
            log_dir = os.path.join(os.path.dirname(self.db_path), "logs")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # Filename by date
            date_str = datetime.now().strftime("%Y-%m-%d")
            log_file = os.path.join(log_dir, f"honeypot-{date_str}.json")
            
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"JSON Logging Error: {e}")

    def insert_logs(self, node_id, logs):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        for log in logs:
            # log dict structure from client: {timestamp, attacker_ip, protocol, request_data, response_data, metadata}
            # We map consistent fields
            timestamp = log.get('timestamp') or datetime.now().isoformat()
            attacker_ip = log.get('attacker_ip')
            protocol = log.get('protocol')
            req = log.get('request_data')
            resp = log.get('response_data')
            meta = log.get('metadata')
            
            # Prepare JSON Log Entry for ELK (Expanded Metadata)
            json_log = {
                "timestamp": timestamp,
                "node_id": node_id,
                "protocol": protocol,
                "attacker_ip": attacker_ip,
                "request_data": req,
                "response_data": resp,
                "metadata": meta
            }
            # Try to parse metadata if it's a string, for better ELK indexing
            if isinstance(meta, str):
                try:
                    json_log["metadata"] = json.loads(meta)
                except:
                    pass
            
            self._log_to_json_file(json_log)

            # Ensure strings for SQLite
            if isinstance(meta, (dict, list)): meta = json.dumps(meta)
            if isinstance(req, (dict, list)): req = json.dumps(req)
            if isinstance(resp, (dict, list)): resp = json.dumps(resp)

            cursor.execute('''
                INSERT INTO logs (timestamp, node_id, protocol, attacker_ip, request_data, response_data, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, node_id, protocol, attacker_ip, req, resp, meta))
            count += 1
            
        conn.commit()
        conn.close()
        return count

    def get_recent_logs(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
