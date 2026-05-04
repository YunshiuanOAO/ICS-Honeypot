# ICS Honeypot Platform

A distributed honeypot platform for **Industrial Control Systems**. A central server manages remote agents that deploy Docker-based honeypot packages, capture attacker traffic through protocol-aware proxies, and forward logs back for analysis — optionally indexed by an ELK stack.

![architecture](./assets/arch.png)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Honeypot Package Spec](#honeypot-package-spec)
- [Deployment Lifecycle](#deployment-lifecycle)
- [Proxy Layer](#proxy-layer)
- [Logging Pipeline](#logging-pipeline)
- [Project Structure](#project-structure)
- [Operational Notes](#operational-notes)
- [License](#license)

## Overview

The platform has three cooperating components:

| Component | Role |
|-----------|------|
| **Server** | FastAPI control plane. Hosts the dashboard, stores agent configs and logs, exposes an agent API, and serves the package library. |
| **Client Agent** | Runs on each honeypot node. Pulls config, materializes package files, drives `docker compose`, runs protocol proxies, and uploads logs. |
| **ELK Stack** *(optional)* | Filebeat → Elasticsearch → Kibana pipeline that consumes the JSON logs the server writes to disk. |

A **honeypot package** is just a folder of files (`Dockerfile`, `docker-compose.yml`, source code, configs). Operators author packages in the dashboard or upload zip archives; agents materialize them onto disk and run them with Docker.

## Architecture

```
┌───────────────┐  HTTPS / X-Api-Key   ┌────────────────┐
│  Server (UI)  │◀────────────────────▶│  Client Agent  │
│  FastAPI      │   config + logs      │  NodeAgent     │
│  SQLite       │                      │  Docker / proxy│
└──────┬────────┘                      └────────┬───────┘
       │ JSON logs                              │ docker compose
       ▼                                        ▼
   Filebeat  →  Elasticsearch  →  Kibana    Honeypot containers
```

- **Server persistence**: `server/server.db` (aiosqlite) holds agents, package configs, and uploaded logs. JSON copies land in `server/logs/` for Filebeat ingestion.
- **Client persistence**: `client/client_logs.db` is a local buffer for log lines awaiting upload.
- **Auth**: dashboard uses session cookies; the agent API uses an `X-Api-Key` header. Credentials live in each side's `.env`.

## Quick Start

### Prerequisites

- Python 3.8+
- Docker with the `docker compose` plugin

### 1. Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure secrets

Create `server/.env`:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me
API_KEY=shared-agent-key
SESSION_SECRET=optional-but-recommended
```

Create `client/.env`:

```env
API_KEY=shared-agent-key
```

### 3. Start the server (with ELK)

```bash
./server/start_services.sh
```

- Dashboard: <http://127.0.0.1:8000>
- Kibana: <http://localhost:5601>

To run the server alone (no ELK):

```bash
cd server && python3 main.py
```

### 4. Start a client agent

```bash
source venv/bin/activate
python3 client/main.py
```

Edit `client/client_config.json` to set `node_id` and `server_url`. Deployments arrive from the server — leave the array empty initially.

### 5. Build a package

In the dashboard, edit an agent and add a deployment. You can:

- Start from a built-in template (`modbus`, `http`, `mqtt`).
- Hand-author files (`Dockerfile`, `docker-compose.yml`, source code, configs).
- Upload a `.zip` archive — the server extracts it, populates the file editor tree, and saves it to the **package library** for reuse by other agents.

## Honeypot Package Spec

Each agent config has a `deployments` array. A deployment is a self-contained package.

```json
{
  "node_id": "node_01",
  "server_url": "http://localhost:8000",
  "deployments": [
    {
      "id": "http-gateway",
      "name": "HTTP Gateway Honeypot",
      "type": "http",
      "template": "http",
      "enabled": true,
      "source_dir": "http-gateway",
      "log_paths": ["logs/access.jsonl"],
      "files": [
        {
          "path": "Dockerfile",
          "content": "FROM nginx:1.27-alpine\nCOPY nginx.conf /etc/nginx/nginx.conf\nCOPY site /usr/share/nginx/html\n"
        },
        {
          "path": "docker-compose.yml",
          "content": "services:\n  honeypot:\n    build: .\n    restart: unless-stopped\n"
        }
      ]
    }
  ]
}
```

Key fields:

| Field | Meaning |
|-------|---------|
| `id` | Unique deployment identifier on this node. |
| `type` / `template` | Protocol hint used by the proxy layer and template UI. |
| `source_dir` | Subfolder name created under the runtime tree. |
| `log_paths` | Files (relative to the package folder) that the agent should tail. |
| `files[]` | Each entry has `path` (relative) and `content` (raw text). |

Paths starting with `logs/` and `data/` are resolved into the deployment's isolated log and data folders (see [Logging Pipeline](#logging-pipeline)).

## Deployment Lifecycle

1. Operator edits a package in the dashboard. The server persists it in the agent's `config_json`.
2. On its next sync, the client downloads the config and seeds files at:
   ```
   client/runtime/<node-id>/<deployment-id>/package/<source_dir>/
   ```
3. The client also creates dedicated runtime folders:
   ```
   client/runtime/<node-id>/<deployment-id>/data/
   client/runtime/<node-id>/<deployment-id>/logs/
   ```
4. The client launches the package:
   - If `docker-compose.yml` exists → `docker compose up -d --build` (preferred).
   - Else if only `Dockerfile` exists → fallback to `docker build` + `docker run`.
   - A compose override is generated to ensure unique container names so reused packages do not collide.
5. The client tails each `log_paths` file and uploads new lines to the server.
6. **After the first deploy, the client-local package is authoritative** — local edits under `client/runtime/.../package/` are preserved, and subsequent server changes do **not** overwrite local files. Edit on the client if you want client-side persistence.
7. On `SIGINT`, `SIGTERM`, or normal exit, the agent stops every honeypot container it started.

The agent only re-uploads the full package config when it actually changes; routine heartbeats stay tiny so large packages don't make the agent appear offline.

## Proxy Layer

`client/proxy/` implements protocol-aware TCP proxies that sit between attackers and honeypot containers. `ProxyManager` selects a proxy class by protocol or port:

| Proxy | Default ports |
|-------|---------------|
| `ModbusProxy` | 502, 5020 |
| `HTTPProxy` | 80, 8080, 443 |
| `MQTTProxy` | 1883, 8883 |
| `TCPProxy` | generic fallback |

Proxies parse protocol frames, log structured events through `UnifiedLogger`, and forward traffic to the real container — giving you protocol-level visibility on top of raw connection logs.

## Logging Pipeline

```
honeypot container
        │ writes
        ▼
client/runtime/<node>/<deployment>/logs|data/...
        │ tail
        ▼
client/client_logs.db  ──upload──▶  server.db
                                       │
                                       ▼
                                  server/logs/*.jsonl
                                       │
                                       ▼
                                Filebeat → Elasticsearch → Kibana
```

- Relative `log_paths` beginning with `logs/` resolve into the deployment's log folder; those beginning with `data/` resolve into its data folder.
- `docker-compose.yml` can mount `${HONEYPOT_DATA_DIR}` and `${HONEYPOT_LOGS_DIR}` into containers to keep each honeypot's state isolated.
- The server writes JSON copies of every uploaded log under `server/logs/` so Filebeat can pick them up without touching the database.

## Project Structure

```
ICS-Honeypot/
├── client/
│   ├── main.py               # entry point
│   ├── agent.py              # NodeAgent: server sync, orchestration, log upload
│   ├── docker_manager.py     # writes package files, drives docker compose
│   ├── log_collector.py      # tails log files into the local SQLite buffer
│   ├── proxy/                # protocol-aware proxies (modbus / http / mqtt / tcp)
│   ├── client_config.json    # local node config (node_id, server_url)
│   └── runtime/              # per-deployment package, data, and logs (gitignored)
├── server/
│   ├── main.py               # FastAPI app + dashboard
│   ├── database.py           # async SQLite layer (agents, logs)
│   ├── auth_config.py        # admin credentials, API key, session secret
│   ├── package_generators.py # built-in package templates (modbus / http / mqtt)
│   ├── static/, templates/   # dashboard frontend
│   ├── uploads/              # zip-uploaded package library
│   ├── elk/                  # Filebeat / Elasticsearch / Kibana compose files
│   └── logs/                 # JSON logs for Filebeat
├── assets/                   # diagrams
├── requirements.txt
└── README.md
```

Both `server/server.db` and `client/client_logs.db` are gitignored.

## Operational Notes

- The dashboard edits **raw package files**, not fixed protocol-specific forms — every package is just a folder of files you control.
- The client never auto-creates a `docker-compose.yml`. Include one in the package if you want compose mode.
- If a package has both `docker-compose.yml` and `Dockerfile`, compose wins.
- Uploaded zip archives are stored in the server-side **package library** so other agents can browse and reuse them.
- There is no test suite, type checker, or linter wired up. Changes are validated by running the agent + server end-to-end.

## License

[MIT](LICENSE)
