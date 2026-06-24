import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import aiofiles


def _is_unique_violation(exc):
    return exc.__class__.__name__ == "UniqueViolationError"


class PostgresServerDB:
    def __init__(self, database_url: str):
        self.database_url = database_url
        self._pool = None
        self._init_lock = asyncio.Lock()
        try:
            self.agent_offline_after_seconds = int(os.environ.get("AGENT_OFFLINE_AFTER_SECONDS", "300"))
        except ValueError:
            self.agent_offline_after_seconds = 300

    async def _ensure_pool(self):
        if self._pool is not None:
            return self._pool

        async with self._init_lock:
            if self._pool is not None:
                return self._pool
            try:
                import asyncpg
            except ImportError as exc:
                raise RuntimeError(
                    "DATABASE_URL is PostgreSQL, but asyncpg is not installed. "
                    "Run: uv pip install -r requirements.txt"
                ) from exc

            max_size = int(os.environ.get("POSTGRES_POOL_MAX_SIZE", "10"))
            self._pool = await asyncpg.create_pool(
                self.database_url,
                min_size=1,
                max_size=max(max_size, 2),
                command_timeout=float(os.environ.get("POSTGRES_COMMAND_TIMEOUT_SECONDS", "30")),
            )
            await self._init_schema()
            return self._pool

    async def _init_schema(self):
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    node_id TEXT PRIMARY KEY,
                    name TEXT,
                    ip TEXT,
                    last_heartbeat TEXT,
                    status TEXT,
                    config_json TEXT,
                    is_active INTEGER DEFAULT 1,
                    runtime_status_json TEXT,
                    whitelist_json TEXT
                );

                CREATE TABLE IF NOT EXISTS logs (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT,
                    node_id TEXT,
                    protocol TEXT,
                    attacker_ip TEXT,
                    request_data TEXT,
                    response_data TEXT,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS whitelist_logs (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT,
                    node_id TEXT,
                    protocol TEXT,
                    attacker_ip TEXT,
                    request_data TEXT,
                    response_data TEXT,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT,
                    attacker_ip TEXT,
                    node_id TEXT,
                    protocol TEXT,
                    signature TEXT,
                    signature_id INTEGER,
                    category TEXT,
                    severity INTEGER,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    log_id BIGINT,
                    source TEXT DEFAULT 'internal',
                    metadata TEXT,
                    UNIQUE(log_id, signature_id, source)
                );

                CREATE TABLE IF NOT EXISTS ip_summaries (
                    ip TEXT PRIMARY KEY,
                    total_packets BIGINT NOT NULL DEFAULT 0,
                    protocols TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
                    node_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
                    first_seen TEXT,
                    last_seen TEXT,
                    alert_count BIGINT NOT NULL DEFAULT 0,
                    max_severity INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_logs_ip_id ON logs(attacker_ip, id DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_id_desc ON logs(id DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_ts_ip ON logs(timestamp, attacker_ip);
                CREATE INDEX IF NOT EXISTS idx_logs_ts_id_desc ON logs(timestamp DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_ip_ts_desc ON logs(attacker_ip, timestamp DESC) WHERE attacker_ip IS NOT NULL AND attacker_ip != '';
                CREATE INDEX IF NOT EXISTS idx_alerts_ip_id ON alerts(attacker_ip, id DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_id_desc ON alerts(id DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_ts_ip ON alerts(timestamp, attacker_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_ip_ts_desc ON alerts(attacker_ip, timestamp DESC) WHERE attacker_ip IS NOT NULL AND attacker_ip != '';
                CREATE INDEX IF NOT EXISTS idx_ip_summaries_last_seen ON ip_summaries(last_seen DESC, ip);
                """
            )
            for table in ("logs", "whitelist_logs", "alerts"):
                await conn.execute(
                    f"""
                    WITH seq_state AS (
                        SELECT COALESCE(MAX(id), 1) AS max_id, MAX(id) IS NOT NULL AS has_rows
                        FROM {table}
                    )
                    SELECT setval(pg_get_serial_sequence('{table}', 'id'), max_id, has_rows)
                    FROM seq_state
                    """
                )

    def _decode_agent_row(self, row):
        agent = dict(row)
        if agent.get("runtime_status_json"):
            try:
                agent["runtime_status"] = json.loads(agent["runtime_status_json"])
            except Exception:
                agent["runtime_status"] = {}
        else:
            agent["runtime_status"] = {}
        return agent

    async def register_agent(self, node_id, name="Unknown Agent", ip="0.0.0.0", config=None, runtime_status=None):
        pool = await self._ensure_pool()
        now = datetime.now().isoformat()
        if config is None:
            config = {
                "node_id": node_id,
                "server_url": os.environ.get("SERVER_PUBLIC_URL", "").strip() or "http://localhost:8000",
                "deployments": [],
            }
        config_str = json.dumps(config)
        runtime_status_str = json.dumps(runtime_status or {})

        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT is_active, runtime_status_json, whitelist_json FROM agents WHERE node_id = $1",
                    node_id,
                )
                is_active = row["is_active"] if row else 0
                if row and row["runtime_status_json"] and not runtime_status:
                    runtime_status_str = row["runtime_status_json"]
                whitelist_json = row["whitelist_json"] if row else None
                await conn.execute(
                    """
                    INSERT INTO agents
                        (node_id, name, ip, last_heartbeat, status, config_json, is_active, runtime_status_json, whitelist_json)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                    ON CONFLICT (node_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        ip = EXCLUDED.ip,
                        last_heartbeat = EXCLUDED.last_heartbeat,
                        status = EXCLUDED.status,
                        config_json = EXCLUDED.config_json,
                        is_active = EXCLUDED.is_active,
                        runtime_status_json = EXCLUDED.runtime_status_json,
                        whitelist_json = EXCLUDED.whitelist_json
                    """,
                    node_id,
                    name,
                    ip,
                    now,
                    "Online",
                    config_str,
                    is_active,
                    runtime_status_str,
                    whitelist_json,
                )
        return config

    async def update_heartbeat(self, node_id, ip=None, name=None, runtime_status=None):
        pool = await self._ensure_pool()
        now = datetime.now().isoformat()
        runtime_status_str = json.dumps(runtime_status or {})
        result = await pool.execute(
            """
            UPDATE agents
            SET last_heartbeat = $1,
                status = $2,
                ip = COALESCE($3, ip),
                name = COALESCE($4, name),
                runtime_status_json = $5
            WHERE node_id = $6
            """,
            now,
            "Online",
            ip,
            name,
            runtime_status_str,
            node_id,
        )
        return not result.endswith(" 0")

    async def get_agent(self, node_id):
        pool = await self._ensure_pool()
        row = await pool.fetchrow("SELECT * FROM agents WHERE node_id = $1", node_id)
        return self._decode_agent_row(row) if row else None

    async def get_all_agents(self):
        pool = await self._ensure_pool()
        rows = await pool.fetch("SELECT * FROM agents ORDER BY node_id")
        agents = []
        for row in rows:
            agent = self._decode_agent_row(row)
            try:
                last_seen = datetime.fromisoformat(agent["last_heartbeat"])
                heartbeat_age = (datetime.now() - last_seen).total_seconds()
                agent["heartbeat_age_seconds"] = int(heartbeat_age)
                if heartbeat_age > self.agent_offline_after_seconds:
                    agent["status"] = "Offline"
            except Exception:
                pass
            agents.append(agent)
        return agents

    async def update_agent_config(self, node_id, config_dict, name=None):
        pool = await self._ensure_pool()
        config_str = json.dumps(config_dict)
        if name:
            await pool.execute(
                "UPDATE agents SET config_json = $1, name = $2 WHERE node_id = $3",
                config_str,
                name,
                node_id,
            )
        else:
            await pool.execute("UPDATE agents SET config_json = $1 WHERE node_id = $2", config_str, node_id)

    async def rename_agent(self, old_node_id, new_node_id):
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                exists = await conn.fetchval("SELECT 1 FROM agents WHERE node_id = $1", new_node_id)
                if exists:
                    return False, "New Node ID already exists"
                await conn.execute("UPDATE agents SET node_id = $1 WHERE node_id = $2", new_node_id, old_node_id)
                await conn.execute("UPDATE logs SET node_id = $1 WHERE node_id = $2", new_node_id, old_node_id)
                await conn.execute("UPDATE whitelist_logs SET node_id = $1 WHERE node_id = $2", new_node_id, old_node_id)
        return True, "Renamed successfully"

    async def delete_agent(self, node_id):
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM logs WHERE node_id = $1", node_id)
                await conn.execute("DELETE FROM whitelist_logs WHERE node_id = $1", node_id)
                await conn.execute("DELETE FROM agents WHERE node_id = $1", node_id)

    async def toggle_agent_active(self, node_id, is_active):
        pool = await self._ensure_pool()
        await pool.execute("UPDATE agents SET is_active = $1 WHERE node_id = $2", 1 if is_active else 0, node_id)

    async def get_agent_whitelist(self, node_id):
        pool = await self._ensure_pool()
        whitelist_json = await pool.fetchval("SELECT whitelist_json FROM agents WHERE node_id = $1", node_id)
        if whitelist_json:
            try:
                return json.loads(whitelist_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    async def update_agent_whitelist(self, node_id, whitelist_dict):
        pool = await self._ensure_pool()
        await pool.execute(
            "UPDATE agents SET whitelist_json = $1 WHERE node_id = $2",
            json.dumps(whitelist_dict, ensure_ascii=False),
            node_id,
        )

    async def _log_to_json_file(self, log_entry):
        try:
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            os.makedirs(log_dir, exist_ok=True)
            date_str = datetime.now().strftime("%Y-%m-%d")
            log_file = os.path.join(log_dir, f"honeypot-{date_str}.json")
            async with aiofiles.open(log_file, "a") as f:
                await f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"JSON Logging Error: {e}")

    @staticmethod
    def _parse_metadata(meta):
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
        elk = {
            "@timestamp": timestamp,
            "node_id": node_id,
            "protocol": protocol,
            "attacker_ip": attacker_ip,
            "request_data": req,
            "response_data": resp,
        }
        elk["deployment_id"] = meta_dict.get("deployment.id", "")
        elk["deployment_name"] = meta_dict.get("deployment.name", "")
        elk["event_id"] = meta_dict.get("event_id", "")
        elk["session_id"] = meta_dict.get("session.id", "")
        elk["log_message"] = meta_dict.get("log.message", "")
        elk["log_source"] = meta_dict.get("source", "")

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

        skip_keys = {
            "deployment.id", "deployment.name", "event_id", "session.id",
            "log.message", "source", "_unified_entry", "valid", "raw_length",
            "log.file",
        }
        for key, value in meta_dict.items():
            if key in skip_keys:
                continue
            elk_key = key.replace(".", "_")
            if elk_key not in elk:
                elk[elk_key] = value
        return elk

    @staticmethod
    def _merge_ip_log_rows(rows):
        summaries = {}
        for timestamp, node_id, protocol, attacker_ip, *_ in rows:
            if not attacker_ip:
                continue
            summary = summaries.setdefault(
                attacker_ip,
                {
                    "count": 0,
                    "protocols": set(),
                    "node_ids": set(),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                },
            )
            summary["count"] += 1
            if protocol:
                summary["protocols"].add(protocol)
            if node_id:
                summary["node_ids"].add(node_id)
            if timestamp and (summary["first_seen"] is None or timestamp < summary["first_seen"]):
                summary["first_seen"] = timestamp
            if timestamp and (summary["last_seen"] is None or timestamp > summary["last_seen"]):
                summary["last_seen"] = timestamp
        return [
            (
                ip,
                data["count"],
                sorted(data["protocols"]),
                sorted(data["node_ids"]),
                data["first_seen"],
                data["last_seen"],
            )
            for ip, data in summaries.items()
        ]

    async def _upsert_ip_log_summaries(self, executor, rows):
        summaries = self._merge_ip_log_rows(rows)
        if not summaries:
            return
        await executor.executemany(
            """
            INSERT INTO ip_summaries
                (ip, total_packets, protocols, node_ids, first_seen, last_seen)
            VALUES ($1,$2,$3::text[],$4::text[],$5,$6)
            ON CONFLICT (ip) DO UPDATE SET
                total_packets = ip_summaries.total_packets + EXCLUDED.total_packets,
                protocols = (
                    SELECT ARRAY(
                        SELECT DISTINCT value
                        FROM unnest(ip_summaries.protocols || EXCLUDED.protocols) AS value
                        WHERE value IS NOT NULL AND value != ''
                        ORDER BY value
                    )
                ),
                node_ids = (
                    SELECT ARRAY(
                        SELECT DISTINCT value
                        FROM unnest(ip_summaries.node_ids || EXCLUDED.node_ids) AS value
                        WHERE value IS NOT NULL AND value != ''
                        ORDER BY value
                    )
                ),
                first_seen = CASE
                    WHEN ip_summaries.first_seen IS NULL THEN EXCLUDED.first_seen
                    WHEN EXCLUDED.first_seen IS NULL THEN ip_summaries.first_seen
                    WHEN EXCLUDED.first_seen < ip_summaries.first_seen THEN EXCLUDED.first_seen
                    ELSE ip_summaries.first_seen
                END,
                last_seen = CASE
                    WHEN ip_summaries.last_seen IS NULL THEN EXCLUDED.last_seen
                    WHEN EXCLUDED.last_seen IS NULL THEN ip_summaries.last_seen
                    WHEN EXCLUDED.last_seen > ip_summaries.last_seen THEN EXCLUDED.last_seen
                    ELSE ip_summaries.last_seen
                END
            """,
            summaries,
        )

    async def _upsert_ip_alert_summary(self, executor, alert):
        attacker_ip = alert.get("attacker_ip")
        if not attacker_ip:
            return
        severity = alert.get("severity") or 3
        await executor.execute(
            """
            INSERT INTO ip_summaries
                (ip, protocols, node_ids, alert_count, max_severity)
            VALUES ($1,$2::text[],$3::text[],1,$4)
            ON CONFLICT (ip) DO UPDATE SET
                protocols = (
                    SELECT ARRAY(
                        SELECT DISTINCT value
                        FROM unnest(ip_summaries.protocols || EXCLUDED.protocols) AS value
                        WHERE value IS NOT NULL AND value != ''
                        ORDER BY value
                    )
                ),
                node_ids = (
                    SELECT ARRAY(
                        SELECT DISTINCT value
                        FROM unnest(ip_summaries.node_ids || EXCLUDED.node_ids) AS value
                        WHERE value IS NOT NULL AND value != ''
                        ORDER BY value
                    )
                ),
                alert_count = ip_summaries.alert_count + 1,
                max_severity = CASE
                    WHEN ip_summaries.max_severity = 0 THEN EXCLUDED.max_severity
                    WHEN EXCLUDED.max_severity = 0 THEN ip_summaries.max_severity
                    WHEN EXCLUDED.max_severity < ip_summaries.max_severity THEN EXCLUDED.max_severity
                    ELSE ip_summaries.max_severity
                END
            """,
            attacker_ip,
            [alert.get("protocol")] if alert.get("protocol") else [],
            [alert.get("node_id")] if alert.get("node_id") else [],
            severity,
        )

    async def insert_logs(self, node_id, logs):
        pool = await self._ensure_pool()
        rows = []
        for log in logs:
            timestamp = log.get("timestamp") or datetime.now().isoformat()
            attacker_ip = log.get("attacker_ip")
            protocol = log.get("protocol")
            req = log.get("request_data")
            resp = log.get("response_data")
            meta_dict = self._parse_metadata(log.get("metadata"))
            await self._log_to_json_file(self._build_elk_entry(node_id, timestamp, attacker_ip, protocol, req, resp, meta_dict))
            if isinstance(req, (dict, list)):
                req = json.dumps(req)
            if isinstance(resp, (dict, list)):
                resp = json.dumps(resp)
            rows.append((timestamp, node_id, protocol, attacker_ip, req, resp, json.dumps(meta_dict, ensure_ascii=False)))
        if not rows:
            return 0
        sql = """
        INSERT INTO logs (timestamp, node_id, protocol, attacker_ip, request_data, response_data, metadata)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        """
        try:
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.executemany(sql, rows)
                    await self._upsert_ip_log_summaries(conn, rows)
        except Exception as exc:
            if not _is_unique_violation(exc):
                raise
            await pool.execute("SELECT setval('logs_id_seq', COALESCE((SELECT MAX(id) FROM logs), 1) + 1000000, true)")
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.executemany(sql, rows)
                    await self._upsert_ip_log_summaries(conn, rows)
        return len(rows)

    async def get_recent_logs(self, limit=100):
        pool = await self._ensure_pool()
        if limit is None:
            limit = 500
        rows = await pool.fetch("SELECT * FROM logs ORDER BY id DESC LIMIT $1", limit)
        return [dict(row) for row in rows]

    async def get_dashboard_stats(self):
        pool = await self._ensure_pool()
        row = await pool.fetchrow(
            """
            SELECT
                COALESCE(SUM(total_packets), 0)::bigint AS total_logs,
                COALESCE(SUM(alert_count), 0)::bigint AS total_alerts
            FROM ip_summaries
            """
        )
        if row:
            return {"total_logs": row["total_logs"], "total_alerts": row["total_alerts"]}
        else:
            return {"total_logs": 0, "total_alerts": 0}

    async def delete_agent_logs(self, node_id):
        pool = await self._ensure_pool()
        await pool.execute("DELETE FROM logs WHERE node_id = $1", node_id)

    async def insert_whitelist_logs(self, node_id, logs):
        pool = await self._ensure_pool()
        rows = []
        for log in logs:
            timestamp = log.get("timestamp") or datetime.now().isoformat()
            req = log.get("request_data")
            resp = log.get("response_data")
            meta_dict = self._parse_metadata(log.get("metadata"))
            if isinstance(req, (dict, list)):
                req = json.dumps(req)
            if isinstance(resp, (dict, list)):
                resp = json.dumps(resp)
            rows.append((
                timestamp,
                node_id,
                log.get("protocol"),
                log.get("attacker_ip"),
                req,
                resp,
                json.dumps(meta_dict, ensure_ascii=False),
            ))
        if not rows:
            return 0
        await pool.executemany(
            """
            INSERT INTO whitelist_logs (timestamp, node_id, protocol, attacker_ip, request_data, response_data, metadata)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            """,
            rows,
        )
        return len(rows)

    async def get_recent_whitelist_logs(self, limit=100, node_id=None):
        pool = await self._ensure_pool()
        if node_id:
            rows = await pool.fetch(
                "SELECT * FROM whitelist_logs WHERE node_id = $1 ORDER BY id DESC LIMIT $2",
                node_id,
                limit,
            )
        else:
            rows = await pool.fetch("SELECT * FROM whitelist_logs ORDER BY id DESC LIMIT $1", limit)
        return [dict(row) for row in rows]

    async def delete_agent_whitelist_logs(self, node_id):
        pool = await self._ensure_pool()
        await pool.execute("DELETE FROM whitelist_logs WHERE node_id = $1", node_id)

    async def get_agent_ips(self):
        pool = await self._ensure_pool()
        rows = await pool.fetch("SELECT DISTINCT ip FROM agents WHERE ip IS NOT NULL AND ip != ''")
        return [row["ip"] for row in rows]

    async def get_ip_summary(self, limit=200, since=None, until=None, offset=0, ip_search=None, exclude_ips=None, hide_private_ips=False):
        pool = await self._ensure_pool()
        params = []
        exclude_ips = [ip for ip in (exclude_ips or []) if ip]

        def add(value):
            params.append(value)
            return f"${len(params)}"

        def not_private_ip_sql(column: str) -> str:
            return (
                "NOT ("
                f"{column} LIKE '10.%' OR "
                f"{column} LIKE '127.%' OR "
                f"{column} LIKE '169.254.%' OR "
                f"{column} LIKE '192.168.%' OR "
                f"{column} LIKE '0.%' OR "
                f"{column} = '::1' OR "
                f"{column} ILIKE 'fc%' OR "
                f"{column} ILIKE 'fd%' OR "
                f"{column} ~ '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'"
                ")"
            )

        def is_long_rolling_window(value: str) -> bool:
            if not value or until:
                return False
            try:
                dt = datetime.fromisoformat(str(value))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt <= datetime.now(timezone.utc) - timedelta(hours=24)
            except Exception:
                return False

        if not since and not until:
            summary_where = ["s.total_packets > 0"]
            if ip_search:
                summary_where.append(f"s.ip ILIKE {add('%' + ip_search + '%')}")
            if exclude_ips:
                summary_where.append(f"s.ip <> ALL({add(exclude_ips)}::text[])")
            if hide_private_ips:
                summary_where.append(not_private_ip_sql("s.ip"))
            summary_where_sql = " AND ".join(summary_where)
            count_params = list(params)
            total = await pool.fetchval(
                f"SELECT COUNT(*) FROM ip_summaries s WHERE {summary_where_sql}",
                *count_params,
            )
            limit_placeholder = add(limit)
            offset_placeholder = add(offset)
            rows = await pool.fetch(
                f"""
                SELECT
                    s.ip,
                    s.total_packets,
                    array_to_string(s.protocols, ',') AS protocols,
                    array_to_string(s.node_ids, ',') AS node_ids,
                    s.first_seen,
                    s.last_seen,
                    s.alert_count,
                    s.max_severity
                FROM ip_summaries s
                WHERE {summary_where_sql}
                ORDER BY s.last_seen DESC NULLS LAST, s.ip
                LIMIT {limit_placeholder}
                OFFSET {offset_placeholder}
                """,
                *params,
            )
            result = [dict(row) for row in rows]
            return {"rows": result, "total": total}

        # Long rolling windows such as "Last 7 days" can touch millions of
        # raw log rows. Use the maintained rollup table for these dashboard
        # views so the panel remains responsive under load. Packet counts are
        # lifetime totals for IPs active in the selected window.
        if is_long_rolling_window(since):
            summary_where = ["s.total_packets > 0", f"s.last_seen >= {add(since)}"]
            if ip_search:
                summary_where.append(f"s.ip ILIKE {add('%' + ip_search + '%')}")
            if exclude_ips:
                summary_where.append(f"s.ip <> ALL({add(exclude_ips)}::text[])")
            if hide_private_ips:
                summary_where.append(not_private_ip_sql("s.ip"))
            summary_where_sql = " AND ".join(summary_where)
            count_params = list(params)
            total = await pool.fetchval(
                f"SELECT COUNT(*) FROM ip_summaries s WHERE {summary_where_sql}",
                *count_params,
            )
            limit_placeholder = add(limit)
            offset_placeholder = add(offset)
            rows = await pool.fetch(
                f"""
                SELECT
                    s.ip,
                    s.total_packets,
                    array_to_string(s.protocols, ',') AS protocols,
                    array_to_string(s.node_ids, ',') AS node_ids,
                    s.first_seen,
                    s.last_seen,
                    s.alert_count,
                    s.max_severity
                FROM ip_summaries s
                WHERE {summary_where_sql}
                ORDER BY s.last_seen DESC NULLS LAST, s.ip
                LIMIT {limit_placeholder}
                OFFSET {offset_placeholder}
                """,
                *params,
            )
            return {"rows": [dict(row) for row in rows], "total": total}

        log_where = []
        alert_where = []
        if ip_search:
            log_where.append(f"l.attacker_ip ILIKE {add('%' + ip_search + '%')}")
            alert_where.append(f"a.attacker_ip ILIKE {add('%' + ip_search + '%')}")
        if exclude_ips:
            exclude_placeholder = add(exclude_ips)
            log_where.append(f"l.attacker_ip <> ALL({exclude_placeholder}::text[])")
            alert_where.append(f"a.attacker_ip <> ALL({exclude_placeholder}::text[])")
        if hide_private_ips:
            log_where.append(not_private_ip_sql("l.attacker_ip"))
            alert_where.append(not_private_ip_sql("a.attacker_ip"))
        if since:
            log_where.append(f"l.timestamp >= {add(since)}")
            alert_where.append(f"a.timestamp >= {add(since)}")
        if until:
            log_where.append(f"l.timestamp <= {add(until)}")
            alert_where.append(f"a.timestamp <= {add(until)}")
        log_where.extend(["l.attacker_ip IS NOT NULL", "l.attacker_ip != ''"])
        alert_where.extend(["a.attacker_ip IS NOT NULL", "a.attacker_ip != ''"])
        limit_placeholder = add(limit)
        offset_placeholder = add(offset)
        log_where_sql = " AND ".join(log_where)
        alert_where_sql = " AND ".join(alert_where)

        sql = f"""
            WITH latest_logs AS (
                SELECT DISTINCT ON (l.attacker_ip)
                    l.attacker_ip AS ip,
                    l.timestamp AS last_seen
                FROM logs l
                WHERE {log_where_sql}
                ORDER BY l.attacker_ip, l.timestamp DESC NULLS LAST, l.id DESC
            ),
            page_ips AS (
                SELECT ip, last_seen
                FROM latest_logs
                ORDER BY last_seen DESC NULLS LAST, ip
                LIMIT {limit_placeholder}
                OFFSET {offset_placeholder}
            ),
            log_summary AS (
                SELECT
                    l.attacker_ip AS ip,
                    COUNT(*) AS total_packets,
                    STRING_AGG(DISTINCT l.protocol, ',') AS protocols,
                    STRING_AGG(DISTINCT l.node_id, ',') AS node_ids,
                    MIN(l.timestamp) AS first_seen,
                    MAX(l.timestamp) AS last_seen
                FROM logs l
                JOIN page_ips p ON p.ip = l.attacker_ip
                WHERE {log_where_sql}
                GROUP BY l.attacker_ip
            ),
            alert_summary AS (
                SELECT
                    a.attacker_ip AS ip,
                    COUNT(*) AS alert_count,
                    MIN(a.severity) AS max_severity
                FROM alerts a
                JOIN page_ips p ON p.ip = a.attacker_ip
                WHERE {alert_where_sql}
                GROUP BY a.attacker_ip
            )
            SELECT
                ls.ip,
                ls.total_packets,
                ls.protocols,
                ls.node_ids,
                ls.first_seen,
                ls.last_seen,
                COALESCE(a.alert_count, 0) AS alert_count,
                COALESCE(a.max_severity, 0) AS max_severity
            FROM page_ips p
            JOIN log_summary ls ON ls.ip = p.ip
            LEFT JOIN alert_summary a ON a.ip = ls.ip
            ORDER BY p.last_seen DESC NULLS LAST, p.ip
        """
        rows = await pool.fetch(sql, *params)
        result = [dict(row) for row in rows]
        total = offset + len(result) + (1 if len(result) == limit else 0)
        return {"rows": result, "total": total}

    async def get_logs_by_ip(self, ip, limit=200):
        pool = await self._ensure_pool()
        rows = await pool.fetch("SELECT * FROM logs WHERE attacker_ip = $1 ORDER BY id DESC LIMIT $2", ip, limit)
        return [dict(row) for row in rows]

    async def insert_alert(self, alert: dict) -> bool:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO alerts
                        (timestamp, attacker_ip, node_id, protocol, signature, signature_id,
                         category, severity, src_ip, src_port, dst_ip, dst_port, log_id, source, metadata)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                    ON CONFLICT (log_id, signature_id, source) DO NOTHING
                    RETURNING id
                    """,
                    alert.get("timestamp") or datetime.now().isoformat(),
                    alert.get("attacker_ip"),
                    alert.get("node_id"),
                    alert.get("protocol"),
                    alert.get("signature"),
                    alert.get("signature_id"),
                    alert.get("category"),
                    alert.get("severity") or 3,
                    alert.get("src_ip"),
                    alert.get("src_port") or 0,
                    alert.get("dst_ip"),
                    alert.get("dst_port") or 0,
                    alert.get("log_id"),
                    alert.get("source") or "internal",
                    json.dumps(alert.get("metadata") or {}, ensure_ascii=False),
                )
                if row is not None:
                    await self._upsert_ip_alert_summary(conn, alert)
        return row is not None

    async def get_alerts(self, limit=200, ip=None):
        pool = await self._ensure_pool()
        if ip:
            rows = await pool.fetch("SELECT * FROM alerts WHERE attacker_ip = $1 ORDER BY id DESC LIMIT $2", ip, limit)
        else:
            rows = await pool.fetch("SELECT * FROM alerts ORDER BY id DESC LIMIT $1", limit)
        return [dict(row) for row in rows]
