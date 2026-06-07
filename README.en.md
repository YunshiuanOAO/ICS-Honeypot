<p align="right">
  <a href="./README.md">繁體中文</a> | <strong>English</strong>
</p>

# ICS Honeypot Streetlight Simulation System

<p align="center">
  <img src="./assets/distributed-honeypot-logo-white.png" alt="Distributed ICS Honeypot Logo" width="260">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-Server-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Honeypot-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/PostgreSQL-Database-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/SQLite-Agent_Buffer-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/MQTT-Protocol-660066?style=for-the-badge&logo=eclipsemosquitto&logoColor=white" alt="MQTT">
  <img src="https://img.shields.io/badge/Elasticsearch-Logs-005571?style=for-the-badge&logo=elasticsearch&logoColor=white" alt="Elasticsearch">
  <img src="https://img.shields.io/badge/Kibana-Dashboard-E8478B?style=for-the-badge&logo=kibana&logoColor=white" alt="Kibana">
  <img src="https://img.shields.io/badge/Filebeat-Collector-005571?style=for-the-badge&logo=elastic&logoColor=white" alt="Filebeat">
  <img src="https://img.shields.io/badge/ElastAlert-Alerting-FF6F00?style=for-the-badge" alt="ElastAlert">
</p>

## Overview

This project is a distributed ICS Honeypot streetlight simulation system built with Python. It is designed to emulate industrial control devices, attract attack traffic, and centralize security analysis. The system uses a separated Server and Honeypot Agent architecture. The Server manages honeypot nodes, deployment configuration, attack log ingestion, and the web dashboard. Agents can run on different hosts or network environments and use Docker to deploy MQTT, HTTP, TCP Socket, simulated PLC, custom HMI, or other honeypot services.

Traffic to honeypot services is intercepted, forwarded, and recorded through a Proxy layer. Each Agent first buffers logs locally in SQLite, then periodically uploads service status and attack logs to the Server. The Server stores attack logs in PostgreSQL and can integrate Filebeat, Elasticsearch, Kibana, and ElastAlert for log collection, visualization, analysis, and alerting. Multiple honeypot nodes can also interact with one another to form a honeynet that better resembles a real ICS environment.

## Architecture

![architecture](./assets/arch.png)

```text
Attacker
   |
   v
Honeypot Agent Node
   |-- Proxy Layer: MQTT / HTTP / TCP / Modbus
   |-- Docker Honeypot Services: HMI / PLC / Streetlight Simulator
   |-- Local Buffer: SQLite
   |
   |  heartbeat + logs + status
   v
Central Server
   |-- FastAPI Dashboard
   |-- Agent Management
   |-- Deployment Config
   |-- PostgreSQL
   |
   v
Filebeat -> Elasticsearch -> Kibana -> ElastAlert
```

### Components

| Component | Description |
| --- | --- |
| Server | FastAPI control server that provides the dashboard, Agent management, deployment configuration, log ingestion, and query features. |
| Honeypot Agent | Runs on each honeypot node, receives Server configuration, starts Docker services, and uploads status and attack logs. |
| Proxy Layer | Intercepts and forwards MQTT, HTTP, TCP, Modbus, and other protocol traffic while producing structured attack events. |
| Docker Services | Runs honeypot services such as simulated PLC, HMI, streetlight controller, or custom services. |
| PostgreSQL / SQLite | The Server stores logs in PostgreSQL; each Agent uses SQLite as a local buffer. |
| ELK / ElastAlert | Filebeat, Elasticsearch, Kibana, and ElastAlert provide log collection, visualization, analysis, and alerting. |

## Features

- Distributed architecture: Server and Honeypot Agents can run on different machines.
- Supports multiple interacting honeypot nodes to form a honeynet.
- Uses Docker to deploy custom HMI, simulated PLC, MQTT, HTTP, TCP Socket, and other services.
- Captures, forwards, and records attack traffic through a Proxy layer.
- Supports PostgreSQL, SQLite, and JSON log output.
- Integrates Filebeat, Elasticsearch, Kibana, and ElastAlert for analysis and alerting.
- Provides a web dashboard for Agent management, honeypot deployment, and attack data review.

## Installation

### Requirements

- Python 3.8+
- Docker
- Docker Compose plugin
- Linux / Ubuntu is recommended

### 1. Clone the Repository

```bash
git clone <repo-url>
cd ICS-Honeypot
```

### 2. Create a Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Server Environment Variables

Create `server/.env`:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me
API_KEY=shared-agent-key
SESSION_SECRET=change-this-session-secret

POSTGRES_DB=honeypot
POSTGRES_USER=honeypot
POSTGRES_PASSWORD=honeypot_change_me
POSTGRES_PORT=5432
DATABASE_URL=postgresql://honeypot:honeypot_change_me@127.0.0.1:5432/honeypot
```

`API_KEY` must match the Client Agent configuration so Agents can fetch deployment settings and upload logs.

### 4. Configure Client Agent Environment Variables

Create `client/.env`:

```env
API_KEY=shared-agent-key
```

Check `client/client_config.json` for `node_id` and `server_url`:

```json
{
  "node_id": "node_01",
  "server_url": "http://127.0.0.1:8000",
  "deployments": []
}
```

If the Agent and Server are on different machines, change `server_url` to the Server's actual IP address or domain.

### 5. Start the Server and Analysis Services

```bash
./server/start_services.sh
```

After startup, open:

- Dashboard: <http://127.0.0.1:8000>
- Kibana: <http://127.0.0.1:5601>

To start only the FastAPI Server without ELK:

```bash
cd server
python3 main.py
```

### 6. Start a Honeypot Agent

Open another terminal:

```bash
source .venv/bin/activate
python3 client/main.py
```

After startup, the Agent registers with the Server and waits for deployment configuration. You can add or modify honeypot services for the Agent from the dashboard.

### 7. Deploy Honeypot Services

From the dashboard, add deployments for an Agent:

- Generate Modbus or MQTT simulation services from built-in templates.
- Upload a custom Docker package.
- Edit `Dockerfile`, `docker-compose.yml`, source code, and configuration files.
- Configure Proxy listen ports and backend service ports.

After deployment, the Agent creates Docker containers and starts capturing attack traffic.

## Project Structure

```text
ICS-Honeypot/
├── assets/                  # Logo and architecture diagram
├── client/                  # Honeypot Agent
│   ├── main.py              # Agent entry point
│   ├── agent.py             # Server sync, deployment, and log upload
│   ├── docker_manager.py    # Docker / Docker Compose deployment management
│   ├── log_collector.py     # Log collection
│   └── proxy/               # MQTT / HTTP / TCP / Modbus Proxy
├── server/                  # Central Server
│   ├── main.py              # FastAPI app and dashboard
│   ├── database.py          # SQLite fallback
│   ├── postgres_database.py # PostgreSQL database operations
│   ├── package_generators.py
│   ├── static/
│   ├── templates/
│   └── elk/                 # PostgreSQL / ELK / ElastAlert docker-compose
├── tools/                   # Testing tools
├── requirements.txt
└── README.md
```

## License

[MIT](LICENSE)
