#!/bin/bash

# ==========================================
# Universal Honeypot Startup Script
# ==========================================

# 1. Path Definitions
# Get the absolute directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Assuming the repo root is one level up (since this is in /server)
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# 2. Cleanup Function
cleanup() {
    echo ""
    echo "Stopping ELK services..."
    # Check where ELK is (support both relative locations)
    if [ -d "$SCRIPT_DIR/elk" ]; then
        cd "$SCRIPT_DIR/elk" || exit
        docker-compose stop
    elif [ -d "$REPO_ROOT/elk" ]; then
        cd "$REPO_ROOT/elk" || exit
        docker-compose stop
    fi
    echo "Services stopped."
}

# Trap SIGINT (Ctrl+C) and EXIT
trap cleanup EXIT

# 3. Prerequisites Check
echo "Checking prerequisites..."
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH."
    exit 1
fi
if ! command -v python3 &> /dev/null; then

    echo "Error: Python 3 is not installed."
    exit 1
fi

# 3.5 Check Port 8000
PORT=8000
PID=$(lsof -ti :$PORT)
if [ -n "$PID" ]; then
    echo "Port $PORT is occupied by PID $PID. Killing it..."
    kill -9 $PID
    sleep 1
    echo "Port $PORT cleared."
fi

# 4. Environment Setup (Universal)
# Look for venv in Repo Root (standard) or Script Dir
VENV_DIR="$REPO_ROOT/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found. Creating one at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create virtual environment."
        exit 1
    fi
    echo "Virtual environment created."
fi

# Activate Environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install Dependencies
check_install_deps() {
    REQ_FILE="$REPO_ROOT/requirements.txt"
    if [ -f "$REQ_FILE" ]; then
        echo "Checking/Installing dependencies from requirements.txt..."
        pip install -r "$REQ_FILE"
    else
        echo "Warning: requirements.txt not found at $REQ_FILE."
    fi
}
check_install_deps

# 5. Start ELK Stack
echo "Starting ELK Stack (Docker)..."
# Locate ELK directory
if [ -d "$SCRIPT_DIR/elk" ]; then
    ELK_DIR="$SCRIPT_DIR/elk"
elif [ -d "$REPO_ROOT/elk" ]; then
    ELK_DIR="$REPO_ROOT/elk"
else
    echo "Error: 'elk' directory not found in $SCRIPT_DIR or $REPO_ROOT."
    exit 1
fi

cd "$ELK_DIR" || exit
docker-compose up -d --force-recreate

if [ $? -ne 0 ]; then
    echo "Error: Failed to start ELK stack. Ensure Docker is running."
    exit 1
fi

echo "ELK Stack started."
echo " -> Kibana: http://localhost:5601"

# 6. Start Python Server
echo "Starting Honeypot Server..."
cd "$SCRIPT_DIR" || exit

# Run the server
echo "Server running at http://localhost:8000 (Ctrl+C to stop)"
python3 main.py
