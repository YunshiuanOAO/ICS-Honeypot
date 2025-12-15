# ICS Honeypot Project

A comprehensive Industrial Control Systems (ICS) honeypot designed to emulate various PLC devices (Modbus and S7) and capture attacker activities. The system consists of distributed client agents (sensors) and a typical central management server with an ELK stack for log analysis.

## Architecture

The project follows a localized Client-Server architecture:

- **Client (Agent)**: Runs on the "victim" machine(s). It hosts the PLC emulators (Modbus/S7), manages connections, and keeps a local buffer of logs (`db/logs.db`). It periodically pushes logs to the central server.
- **Server**: Central management hub. It receives logs from agents, stores them in CSV format for Filebeat to pick up, and provides a dashboard for viewing agent status.
- **ELK Stack**:
  - **Filebeat**: Tails the server's log files.
  - **Elasticsearch**: Indexes the logs.
  - **Kibana**: Visualizes the data (attack type, source IP, protocols used).

[](./assets/arch.png)

## Features

### Protocols

#### Modbus TCP

- **Registers Supported**: Holding Registers, Coils.
- **Data Types**: `int16`, `float32` (IEEE 754), `string`.
- **Simulation Patterns**:
  - `static`: Constant value.
  - `sine`: Sine wave generation (configurable min/max/period).
  - `random_walk`: Randomly drifting value.
  - `step`: Step function.
- **Persistence**: Supports standard Modbus write functions (FC 5, 6, 15, 16). Written values are stored in memory and reflected in subsequent reads.

#### Siemens S7comm

- **Models Emulated**: S7-300, S7-400, S7-1200, S7-1500.
- **Memory Areas**:
  - **DB (Data Blocks)**: Fully configurable user data blocks.
  - **M (Flags)**: Memory flags support.
- **Identity Simulation**: Responds to SZL (System Status List) requests with realistic ID info (Module Name, Serial Number, Copyright) matching the configured model.

### Centralized Logging & Dashboard

- **Real-time Visualization**: Kibana dashboard showing attack sources and trends.
- **Agent Management**: Web interface to view active agents and their status.

## Project Structure

- **client/**: Contains the honeypot agent code and PLC emulators.
  - `agent.py`: Main agent logic (communicates with server, manages PLCs).
  - `plc/`: Protocol implementations (Modbus, S7) and simulation logic.
  - `scenarios/`: JSON profiles for different industrial setups (HVAC, Manufacturing, etc.).
  - `client_config.json`: Main configuration file for the agent.
- **server/**: Central server and logging infrastructure.
  - `main.py`: FastAPI application.
  - `elk/`: Docker composition for ELK stack.
  - `logs/`: Central repository for collected logs.

## Configuration

The agent is configured via `client/client_config.json`.

### Example Configuration

```json
{
    "node_id": "node_01",
    "server_url": "http://localhost:8000",
    "plcs": [
        {
            "type": "modbus",
            "enabled": true,
            "port": 502,
            "simulation": {
                "scenario": "schneider_pm5300"
            }
        },
        {
            "type": "s7",
            "enabled": true,
            "port": 102,
            "model": "S7-300",
            "simulation": {
                "scenario": "water_treatment"
            }
        }
    ]
}
```

### Scenarios

Scenario files (in `client/scenarios/`) define the registers and simulation behavior.

- `schneider_pm5300`: Emulates a Schneider Electric power meter.
- `water_treatment`: Emulates a water treatment facility PLC.

## Prerequisites

- **Python**: 3.8+
- **Docker & Docker Compose**: Required for running the ELK stack.

## Installation & Usage

### 1. Start Support Services (Server + ELK)

```bash
./server/start_services.sh
```

- **Kibana**: <http://localhost:5601>
- **Server API**: <http://localhost:8000>

### 2. Start the Honeypot Agent

```bash
cd client
python main.py
```

## Logging

- Logs are stored in `server/logs/`.
- View logs in Kibana under the `honeypot-*` index pattern.

## License

[MIT License](LICENSE)
