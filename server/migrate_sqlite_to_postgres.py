#!/usr/bin/env python3
import argparse
import asyncio
import os
import sqlite3
from pathlib import Path


TABLES = {
    "agents": [
        "node_id", "name", "ip", "last_heartbeat", "status", "config_json",
        "is_active", "runtime_status_json", "whitelist_json",
    ],
    "logs": [
        "id", "timestamp", "node_id", "protocol", "attacker_ip",
        "request_data", "response_data", "metadata",
    ],
    "whitelist_logs": [
        "id", "timestamp", "node_id", "protocol", "attacker_ip",
        "request_data", "response_data", "metadata",
    ],
    "alerts": [
        "id", "timestamp", "attacker_ip", "node_id", "protocol", "signature",
        "signature_id", "category", "severity", "src_ip", "src_port", "dst_ip",
        "dst_port", "log_id", "source", "metadata",
    ],
}


def read_batches(conn, table, columns, batch_size, start_id=0):
    conn.row_factory = sqlite3.Row
    last_id = start_id

    if table == "agents":
        rows = conn.execute(f"SELECT {', '.join(columns)} FROM agents ORDER BY node_id").fetchall()
        yield [tuple(row[col] for col in columns) for row in rows]
        return

    while True:
        rows = conn.execute(
            f"SELECT {', '.join(columns)} FROM {table} WHERE id > ? ORDER BY id LIMIT ?",
            (last_id, batch_size),
        ).fetchall()
        if not rows:
            break
        last_id = rows[-1]["id"]
        yield [tuple(row[col] for col in columns) for row in rows]


async def insert_batch(pg, sql, batch):
    try:
        await pg.executemany(sql, batch)
    except asyncio.TimeoutError:
        if len(batch) == 1:
            raise
        mid = len(batch) // 2
        print(f"batch timed out; retrying as {mid:,} + {len(batch) - mid:,}", flush=True)
        await insert_batch(pg, sql, batch[:mid])
        await insert_batch(pg, sql, batch[mid:])


async def migrate_table(pg, sqlite_conn, table, columns, batch_size, truncate, start_id=0):
    placeholders = ", ".join(f"${i}" for i in range(1, len(columns) + 1))
    column_sql = ", ".join(columns)
    if table == "agents":
        conflict_sql = "ON CONFLICT (node_id) DO NOTHING"
    elif table == "alerts":
        conflict_sql = "ON CONFLICT (id) DO NOTHING"
    else:
        conflict_sql = "ON CONFLICT (id) DO NOTHING"

    if truncate:
        await pg.execute(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE")
        start_id = 0

    total = 0
    insert_sql = f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders}) {conflict_sql}"
    for batch in read_batches(sqlite_conn, table, columns, batch_size, start_id=start_id):
        if not batch:
            continue
        await insert_batch(pg, insert_sql, batch)
        total += len(batch)
        if table == "agents":
            print(f"{table}: migrated {total:,}", flush=True)
        else:
            print(f"{table}: migrated through id {batch[-1][0]:,} (+{total:,})", flush=True)

    if table in ("logs", "whitelist_logs", "alerts"):
        seq_name = f"{table}_id_seq"
        await pg.execute(
            f"SELECT setval('{seq_name}', COALESCE((SELECT MAX(id) FROM {table}), 1), true)"
        )
    return total


async def main():
    parser = argparse.ArgumentParser(description="Migrate honeypot SQLite data to PostgreSQL.")
    parser.add_argument("--sqlite", default=str(Path(__file__).with_name("server.db")))
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--start-id", type=int, default=0, help="Resume id for id-based tables; rows with id <= start-id are skipped.")
    parser.add_argument("--only", choices=TABLES.keys(), help="Migrate only one table.")
    parser.add_argument("--timeout", type=int, default=300, help="PostgreSQL command timeout in seconds.")
    parser.add_argument("--truncate", action="store_true", help="Clear destination tables before migration.")
    args = parser.parse_args()

    if not args.database_url.startswith(("postgres://", "postgresql://")):
        raise SystemExit("DATABASE_URL must be a PostgreSQL URL.")
    if not os.path.exists(args.sqlite):
        raise SystemExit(f"SQLite DB not found: {args.sqlite}")

    from postgres_database import PostgresServerDB

    os.environ["POSTGRES_COMMAND_TIMEOUT_SECONDS"] = str(args.timeout)
    db = PostgresServerDB(args.database_url)
    await db._ensure_pool()
    sqlite_conn = sqlite3.connect(args.sqlite, timeout=30)

    try:
        async with db._pool.acquire() as pg:
            tables = {args.only: TABLES[args.only]} if args.only else TABLES
            for table, columns in tables.items():
                start_id = args.start_id if table != "agents" else 0
                await migrate_table(pg, sqlite_conn, table, columns, args.batch_size, args.truncate, start_id=start_id)
    finally:
        sqlite_conn.close()
        await db._pool.close()


if __name__ == "__main__":
    asyncio.run(main())
