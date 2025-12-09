# ICS Honeypot Project

A comprehensive Industrial Control Systems (ICS) honeypot designed to emulate various PLC devices (Modbus and S7) and capture attacker activities. The system consists of distributed client agents (sensors) and a typical central management server with an ELK stack for log analysis.

## Project Structure

- **client/**: Contains the honeypot agent code, PLC emulators (Modbus, S7), and local database.
    - `agent.py`: Main agent logic (communicates with server, manages PLCs).
    - `plc/`: Implementation of PLC protocols.
    - `db/`: Local database handling.
- **server/**: Central server and logging infrastructure.
    - `main.py`: FastAPI application serving the management API.
    - `elk/`: Elasticsearch, Logstash, and Kibana configuration for log ingestion and visualization.
    - `logs/`: Directory where server and honeypot logs are stored.
    - `database.py`: Server-side database interactions.
- **tests/**: Unit and integration tests.
- **requirements.txt**: Python dependencies.

## Prerequisites

- **Python**: 3.8+
- **Docker & Docker Compose**: Required for running the ELK stack.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone <repository-url>
    cd <project-directory>
    ```

2.  **Make the startup script executable**:
    ```bash
    chmod +x server/start_services.sh
    ```

## Usage

### 1. Automated Setup & Run (Recommended)

The `start_services.sh` script automates the entire process:
- Checks prerequisites.
- Creates and activates the virtual environment.
- Installs dependencies.
- Starts the ELK stack (Elasticsearch, Kibana, Filebeat).
- Starts the FastAPI server.

```bash
./server/start_services.sh
```
- **Kibana**: http://localhost:5601
- **Server API**: http://localhost:8000

To stop the services, simply press `Ctrl+C`. The script will attempt to stop the ELK containers automatically.

### 2. Manual Setup (Alternative)

If you prefer to run components individually:

**Step A: Environment Setup**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Step B: Start ELK Stack**
```bash
cd server/elk
docker-compose up -d
```

**Step C: Start Server**
```bash
cd server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Running the Client (Honeypot Agent)

Start the honeypot agent to emulate PLCs.

```bash
cd client
python agent.py
# OR
python main.py
```

## Logging

- Logs are stored in `server/logs/`.
- Filebeat (in the ELK stack) watches this directory and sends logs to Elasticsearch.
- View logs in Kibana under the `honeypot-*` index pattern.

## License

[MIT License](LICENSE)
