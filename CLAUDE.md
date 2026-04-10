# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ICS (Industrial Control Systems) honeypot platform. A central **server** manages distributed **client agents** that deploy Docker-based honeypot packages and forward captured logs back to the server. Optional ELK stack for log analysis.

## Commands

### Start the server (includes ELK stack)
```bash
./server/start_services.sh
```
Server UI at http://127.0.0.1:8000, Kibana at http://localhost:5601.

### Start the client agent
```bash
source venv/bin/activate
python3 client/main.py
```

### Install dependencies
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Run server directly (without ELK)
```bash
cd server && python3 main.py
```

## Architecture

### Two-process model
- **Server** (`server/main.py`): FastAPI app serving a web dashboard and REST API. Stores agent configs and logs in `server/server.db` (SQLite via aiosqlite). Also writes JSON logs under `server/logs/` for Filebeat/ELK ingestion.
- **Client** (`client/main.py` → `client/agent.py`): `NodeAgent` runs a sync loop — registers with the server, pulls deployment config, delegates to `DockerDeploymentManager` to write package files and run `docker compose`, then uses `ContainerLogCollector` to tail log files and upload them.

### Key data flow
1. Server stores honeypot package configs (files, Dockerfiles, compose files) per agent in the `agents` table `config_json` column.
2. Client fetches config, writes files to `client/runtime/<node>/<deployment>/package/<source_dir>/`.
3. Client runs `docker compose up` in the package directory. Each deployment gets isolated `data/` and `logs/` directories.
4. `ContainerLogCollector` tails configured `log_paths`, stores in local `client/client_logs.db`, and agent uploads to server.
5. After initial deployment, client-local package files are authoritative (server updates don't overwrite local edits).

### Proxy layer
`client/proxy/` contains protocol-aware proxy modules (`modbus_proxy.py`, `http_proxy.py`, `mqtt_proxy.py`, `tcp_proxy.py`) managed by `ProxyManager`. These sit between attackers and honeypot containers to capture and log traffic with protocol-level detail.

### Authentication
- Server requires `.env` file with `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `API_KEY`, and optional `SESSION_SECRET` (see `server/auth_config.py`).
- Client requires `.env` file with `API_KEY` matching the server's.
- Dashboard uses session-based auth; agent API uses `X-Api-Key` header. Some endpoints accept either.

### Deployment templates
`server/deployment_templates/` has JSON templates for `modbus`, `http`, and `mqtt` honeypot types. The UI uses these as starting points when creating new packages.

### Databases
- `server/server.db`: agents table (config, status, heartbeat) + logs table. Async via aiosqlite.
- `client/client_logs.db`: local log buffer before upload. Sync SQLite.
- Both are gitignored.

## Language and Framework Notes

- Python 3.8+, no type checker or linter configured.
- Server: FastAPI + Jinja2 templates + vanilla JS/CSS frontend (`server/static/`, `server/templates/`).
- Client: plain Python with `requests`, `subprocess` for Docker CLI, threaded sync loop.
- No test suite currently exists.
