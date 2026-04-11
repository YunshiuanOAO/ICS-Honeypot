import sqlite3
import aiosqlite
import aiofiles
import json
from datetime import datetime
import os
import asyncio

class ServerDB:
    def __init__(self, db_path="server.db"):
        self.db_path = db_path
        # Keep initial table creation synchronous to ensure DB exists at startup
        self._init_db_sync()

    def _init_db_sync(self):
        """Synchronous initialization for application startup"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # AGENTS Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                node_id TEXT PRIMARY KEY,
                name TEXT,
                ip TEXT,
                last_heartbeat TEXT,
                status TEXT, -- Online, Offline
                config_json TEXT,
                is_active INTEGER DEFAULT 1, -- 1: Active, 0: Inactive
                runtime_status_json TEXT
            )
        ''')
        
        # Migration: Add is_active if it doesn't exist
        try:
            cursor.execute('ALTER TABLE agents ADD COLUMN is_active INTEGER DEFAULT 1')
        except sqlite3.OperationalError:
            pass 

        try:
            cursor.execute('ALTER TABLE agents ADD COLUMN runtime_status_json TEXT')
        except sqlite3.OperationalError:
            pass

        # Migration: Add whitelist_json if it doesn't exist
        try:
            cursor.execute('ALTER TABLE agents ADD COLUMN whitelist_json TEXT')
        except sqlite3.OperationalError:
            pass
        
        # LOGS Table
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

        # WHITELIST_LOGS Table — traffic from whitelisted IPs. Kept separate
        # so it never enters the attack-log pipeline (attack map, recent
        # logs, ELK JSON dump), but is still queryable for audit.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist_logs (
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
    
    def _decode_agent_row(self, row):
        agent = dict(row)
        if agent.get('runtime_status_json'):
            try:
                agent['runtime_status'] = json.loads(agent['runtime_status_json'])
            except Exception:
                agent['runtime_status'] = {}
        else:
            agent['runtime_status'] = {}
        return agent

    async def register_agent(self, node_id, name="Unknown Agent", ip="0.0.0.0", config=None, runtime_status=None):
        now = datetime.now().isoformat()
        
        if config is None:
            # Default config when none provided; server_url will be updated
            # by main.py's get_server_public_url() upon first heartbeat.
            config = {
                "node_id": node_id,
                "server_url": os.environ.get("SERVER_PUBLIC_URL", "").strip() or "http://localhost:8000",
                "deployments": []
            }
        
        config_str = json.dumps(config)
        runtime_status_str = json.dumps(runtime_status or {})
        
        async with aiosqlite.connect(self.db_path) as db:
            # Check if agent exists to preserve is_active/runtime status
            async with db.execute('SELECT is_active, runtime_status_json FROM agents WHERE node_id = ?', (node_id,)) as cursor:
                row = await cursor.fetchone()
                is_active = row[0] if row else 0 # Default to 0 (Inactive) if new agent
                if row and row[1] and not runtime_status:
                    runtime_status_str = row[1]

            await db.execute('''
                INSERT OR REPLACE INTO agents (node_id, name, ip, last_heartbeat, status, config_json, is_active, runtime_status_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (node_id, name, ip, now, "Online", config_str, is_active, runtime_status_str))
            
            await db.commit()
        return config

    async def update_heartbeat(self, node_id, ip=None, name=None, runtime_status=None):
        now = datetime.now().isoformat()
        runtime_status_str = json.dumps(runtime_status or {})
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                'UPDATE agents SET last_heartbeat = ?, status = ?, ip = COALESCE(?, ip), name = COALESCE(?, name), runtime_status_json = ? WHERE node_id = ?', 
                (now, "Online", ip, name, runtime_status_str, node_id)
            )
            changes = cursor.rowcount
            await db.commit()
        return changes > 0

    async def get_agent(self, node_id):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM agents WHERE node_id = ?', (node_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return self._decode_agent_row(row)
        return None

    async def get_all_agents(self):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM agents ORDER BY node_id') as cursor:
                rows = await cursor.fetchall()
        
        agents = []
        for row in rows:
            agent = self._decode_agent_row(row)
            # Check timeout (30 seconds)
            try:
                last_seen = datetime.fromisoformat(agent['last_heartbeat'])
                if (datetime.now() - last_seen).total_seconds() > 30:
                    agent['status'] = 'Offline'
            except Exception:
                pass 
            agents.append(agent)
            
        return agents
        
    async def update_agent_config(self, node_id, config_dict, name=None):
        config_str = json.dumps(config_dict)
        async with aiosqlite.connect(self.db_path) as db:
            if name:
                await db.execute('UPDATE agents SET config_json = ?, name = ? WHERE node_id = ?', (config_str, name, node_id))
            else:
                await db.execute('UPDATE agents SET config_json = ? WHERE node_id = ?', (config_str, node_id))
            await db.commit()

    async def rename_agent(self, old_node_id, new_node_id):
        async with aiosqlite.connect(self.db_path) as db:
            try:
                # Check if new ID exists
                async with db.execute('SELECT 1 FROM agents WHERE node_id = ?', (new_node_id,)) as cursor:
                    if await cursor.fetchone():
                        return False, "New Node ID already exists"

                # Update agents table (whitelist_json stays with the row)
                await db.execute('UPDATE agents SET node_id = ? WHERE node_id = ?', (new_node_id, old_node_id))
                
                # Update logs table
                await db.execute('UPDATE logs SET node_id = ? WHERE node_id = ?', (new_node_id, old_node_id))

                # Update whitelist_logs table
                await db.execute('UPDATE whitelist_logs SET node_id = ? WHERE node_id = ?', (new_node_id, old_node_id))
                
                await db.commit()
                return True, "Renamed successfully"
            except Exception as e:
                await db.rollback()
                return False, str(e)

    async def delete_agent(self, node_id):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('DELETE FROM logs WHERE node_id = ?', (node_id,))
            await db.execute('DELETE FROM whitelist_logs WHERE node_id = ?', (node_id,))
            await db.execute('DELETE FROM agents WHERE node_id = ?', (node_id,))
            await db.commit()

    async def toggle_agent_active(self, node_id, is_active):
        val = 1 if is_active else 0
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('UPDATE agents SET is_active = ? WHERE node_id = ?', (val, node_id))
            await db.commit()

    # --- Per-Agent Whitelist ---

    async def get_agent_whitelist(self, node_id):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute('SELECT whitelist_json FROM agents WHERE node_id = ?', (node_id,)) as cursor:
                row = await cursor.fetchone()
                if row and row[0]:
                    try:
                        return json.loads(row[0])
                    except (json.JSONDecodeError, TypeError):
                        pass
        return None

    async def update_agent_whitelist(self, node_id, whitelist_dict):
        whitelist_str = json.dumps(whitelist_dict, ensure_ascii=False)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('UPDATE agents SET whitelist_json = ? WHERE node_id = ?', (whitelist_str, node_id))
            await db.commit()

    # --- Log Management ---

    async def _log_to_json_file(self, log_entry):
        try:
            # Ensure log directory exists
            log_dir = os.path.join(os.path.dirname(self.db_path), "logs")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            # Filename by date
            date_str = datetime.now().strftime("%Y-%m-%d")
            log_file = os.path.join(log_dir, f"honeypot-{date_str}.json")

            async with aiofiles.open(log_file, "a") as f:
                await f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"JSON Logging Error: {e}")

    @staticmethod
    def _parse_metadata(meta):
        """Parse metadata string to dict, handling edge cases"""
        if isinstance(meta, dict):
            return meta
        if isinstance(meta, str):
            if meta in ("None", "null", ""):
                return {}
            try:
                parsed = json.loads(meta)
                return parsed if isinstance(parsed, dict) else {"raw": meta}
            except (json.JSONDecodeError, ValueError):
                return {"raw": meta}
        return {}

    @staticmethod
    def _build_elk_entry(node_id, timestamp, attacker_ip, protocol, req, resp, meta_dict):
        """
        Build a flat, ELK-friendly JSON entry.
        Dots in key names are replaced with underscores to avoid
        Elasticsearch nested object mapping conflicts.
        """
        elk = {
            "@timestamp": timestamp,
            "node_id": node_id,
            "protocol": protocol,
            "attacker_ip": attacker_ip,
            "request_data": req,
            "response_data": resp,
        }

        # Extract well-known fields from metadata
        elk["deployment_id"] = meta_dict.get("deployment.id", "")
        elk["deployment_name"] = meta_dict.get("deployment.name", "")
        elk["event_id"] = meta_dict.get("event_id", "")
        elk["session_id"] = meta_dict.get("session.id", "")
        elk["log_message"] = meta_dict.get("log.message", "")
        elk["log_source"] = meta_dict.get("source", "")

        # Extract network info from unified entry if available
        unified = meta_dict.get("_unified_entry", {})
        network = unified.get("network", {})
        if network:
            elk["src_ip"] = network.get("src_ip", attacker_ip)
            elk["src_port"] = network.get("src_port", 0)
            elk["dst_ip"] = network.get("dst_ip", "")
            elk["dst_port"] = network.get("dst_port", 0)

        session = unified.get("session", {})
        if session:
            elk["session_request_count"] = session.get("request_count", 0)
            elk["session_duration_ms"] = session.get("duration_ms", 0)

        req_size = unified.get("request", {}).get("size_bytes", 0)
        resp_size = unified.get("response", {}).get("size_bytes", 0)
        if req_size:
            elk["request_size_bytes"] = req_size
        if resp_size:
            elk["response_size_bytes"] = resp_size

        # Flatten protocol-specific parsed fields (replace dots with underscores)
        skip_keys = {
            "deployment.id", "deployment.name", "event_id", "session.id",
            "log.message", "source", "_unified_entry", "valid", "raw_length",
            "log.file",
        }
        for key, value in meta_dict.items():
            if key in skip_keys:
                continue
            # Replace dots with underscores for ELK compatibility
            elk_key = key.replace(".", "_")
            if elk_key not in elk:
                elk[elk_key] = value

        return elk

    async def insert_logs(self, node_id, logs):
        count = 0
        async with aiosqlite.connect(self.db_path) as db:
            for log in logs:
                # log dict structure from client: {timestamp, attacker_ip, protocol, request_data, response_data, metadata}
                timestamp = log.get('timestamp') or datetime.now().isoformat()
                attacker_ip = log.get('attacker_ip')
                protocol = log.get('protocol')
                req = log.get('request_data')
                resp = log.get('response_data')
                meta = log.get('metadata')

                # Parse metadata
                meta_dict = self._parse_metadata(meta)

                # Build flat ELK-friendly JSON entry
                elk_entry = self._build_elk_entry(
                    node_id, timestamp, attacker_ip, protocol, req, resp, meta_dict
                )
                await self._log_to_json_file(elk_entry)

                # Store in SQLite (keep metadata as JSON string for frontend)
                meta_str = json.dumps(meta_dict, ensure_ascii=False) if isinstance(meta_dict, dict) else str(meta_dict)
                if isinstance(req, (dict, list)): req = json.dumps(req)
                if isinstance(resp, (dict, list)): resp = json.dumps(resp)

                await db.execute('''
                    INSERT INTO logs (timestamp, node_id, protocol, attacker_ip, request_data, response_data, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (timestamp, node_id, protocol, attacker_ip, req, resp, meta_str))
                count += 1

            await db.commit()
        return count

    async def get_recent_logs(self, limit=100):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,)) as cursor:
                rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def delete_agent_logs(self, node_id):
        """Delete all logs for a specific agent"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('DELETE FROM logs WHERE node_id = ?', (node_id,))
            await db.commit()

    # ---------- Whitelist log methods ----------

    async def insert_whitelist_logs(self, node_id, logs):
        """Insert friendly traffic into whitelist_logs.

        Mirrors insert_logs() but writes to whitelist_logs instead and
        intentionally does NOT call _log_to_json_file() — whitelist entries
        must not appear in the ELK ingest stream.
        """
        count = 0
        async with aiosqlite.connect(self.db_path) as db:
            for log in logs:
                timestamp = log.get('timestamp') or datetime.now().isoformat()
                attacker_ip = log.get('attacker_ip')
                protocol = log.get('protocol')
                req = log.get('request_data')
                resp = log.get('response_data')
                meta = log.get('metadata')

                meta_dict = self._parse_metadata(meta)
                meta_str = json.dumps(meta_dict, ensure_ascii=False) if isinstance(meta_dict, dict) else str(meta_dict)
                if isinstance(req, (dict, list)): req = json.dumps(req)
                if isinstance(resp, (dict, list)): resp = json.dumps(resp)

                await db.execute('''
                    INSERT INTO whitelist_logs (timestamp, node_id, protocol, attacker_ip, request_data, response_data, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (timestamp, node_id, protocol, attacker_ip, req, resp, meta_str))
                count += 1

            await db.commit()
        return count

    async def get_recent_whitelist_logs(self, limit=100, node_id=None):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if node_id:
                query = 'SELECT * FROM whitelist_logs WHERE node_id = ? ORDER BY id DESC LIMIT ?'
                params = (node_id, limit)
            else:
                query = 'SELECT * FROM whitelist_logs ORDER BY id DESC LIMIT ?'
                params = (limit,)
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def delete_agent_whitelist_logs(self, node_id):
        """Delete all whitelist logs for a specific agent"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('DELETE FROM whitelist_logs WHERE node_id = ?', (node_id,))
            await db.commit()
