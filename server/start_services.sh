#!/bin/bash

# ==========================================
# APS Honeypot — Startup Script
# Supports: Ubuntu 22.04 / 24.04, Amazon Linux 2023
# ==========================================

set -e  # Exit on any error

# ─────────────────────────────────────────
# 1. Path Definitions
# ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PID_FILE="$SCRIPT_DIR/.server.pid"
LOG_FILE="$SCRIPT_DIR/server.log"
DAEMON_MODE=false
SERVER_PORT=8000

# ─────────────────────────────────────────
# 2. Color Helpers
# ─────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

_validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

_load_server_env_config() {
    local configured_port=""
    if [ -f "$SCRIPT_DIR/.env" ]; then
        configured_port=$(grep -E "^SERVER_PORT=" "$SCRIPT_DIR/.env" | tail -1 | cut -d'=' -f2- | xargs)
    fi
    configured_port="${configured_port:-8000}"
    if ! _validate_port "$configured_port"; then
        fail "Invalid SERVER_PORT=$configured_port in server/.env. Use a number from 1 to 65535."
    fi
    SERVER_PORT="$configured_port"
}

_load_server_env_config

# ─────────────────────────────────────────
# 3. Command Handling (stop / status / logs)
# ─────────────────────────────────────────
_server_running() {
    [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

# Find any server PID, even if the PID file is missing/stale.
# Combines: (a) listeners on the configured server port (via lsof / fuser / ss) and
# (b) python processes whose cmdline mentions main.py *and* whose cwd is
# this server directory. Works for daemon, foreground, and manual launches.
_discover_server_pids() {
    local pids=""

    # (a) Configured server port listeners
    if command -v lsof &> /dev/null; then
        pids="$pids $(lsof -ti :$SERVER_PORT 2>/dev/null || true)"
    fi
    if command -v fuser &> /dev/null; then
        pids="$pids $(fuser "$SERVER_PORT/tcp" 2>/dev/null || true)"
    fi
    if command -v ss &> /dev/null; then
        # ss "users:((\"python3\",pid=720027,fd=3))" -> extract pid=NNN
        pids="$pids $(ss -ltnp 2>/dev/null | awk -v port="$SERVER_PORT" '$4 ~ ":" port "$"' | grep -oE 'pid=[0-9]+' | cut -d= -f2 || true)"
    fi

    # (b) python processes running main.py. We try to filter by cwd =
    # SCRIPT_DIR, but if /proc/<pid>/cwd is unreadable (e.g. root-owned
    # server, current user is not root) we accept the match anyway —
    # the alternative is missing the very server we're trying to stop.
    local cand
    cand="$(pgrep -f 'python3? .*main\.py' 2>/dev/null || true)"
    for p in $cand; do
        local cwd
        cwd="$(readlink -f /proc/$p/cwd 2>/dev/null || echo unreadable)"
        if [ "$cwd" = "$SCRIPT_DIR" ] || [ "$cwd" = "unreadable" ]; then
            pids="$pids $p"
        fi
    done

    # Dedupe + strip whitespace; only keep numeric PIDs
    echo "$pids" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u | tr '\n' ' '
}

_kill_pids() {
    local pids="$1"
    [ -z "$pids" ] && return 0
    info "Stopping server PIDs:$pids"

    # Try without sudo first; if any PID still alive afterwards and we lack
    # permission, retry with sudo. Servers started via 'sudo ./start_services.sh'
    # cannot be killed by an unprivileged user.
    kill $pids 2>/dev/null || true
    sleep 1

    local need_sudo=""
    for p in $pids; do
        if kill -0 "$p" 2>/dev/null; then
            need_sudo="$need_sudo $p"
        fi
    done

    if [ -n "$need_sudo" ] && command -v sudo &> /dev/null; then
        warn "Some processes need elevated privileges:$need_sudo"
        sudo kill $need_sudo 2>/dev/null || true
    fi

    for i in $(seq 1 10); do
        local alive=""
        for p in $pids; do
            kill -0 "$p" 2>/dev/null && alive="$alive $p"
        done
        [ -z "$alive" ] && return 0
        sleep 1
    done

    # SIGKILL fallback
    kill -9 $pids 2>/dev/null || true
    if command -v sudo &> /dev/null; then
        sudo kill -9 $pids 2>/dev/null || true
    fi
}

_stop_elk() {
    local elk_dir=""
    if [ -d "$SCRIPT_DIR/elk" ]; then
        elk_dir="$SCRIPT_DIR/elk"
    elif [ -d "$REPO_ROOT/elk" ]; then
        elk_dir="$REPO_ROOT/elk"
    fi
    [ -z "$elk_dir" ] && return 0
    info "Stopping ELK services in $elk_dir..."
    (cd "$elk_dir" && (docker compose stop 2>/dev/null || docker-compose stop 2>/dev/null)) || true
}

case "${1:-}" in
    stop)
        STOPPED_ANY=false
        # 1. Try PID file first
        if _server_running; then
            PID=$(cat "$PID_FILE")
            _kill_pids "$PID"
            STOPPED_ANY=true
        fi
        rm -f "$PID_FILE"

        # 2. Fall back to scanning the configured port and main.py processes —
        #    catches foreground / non-script launches the PID file missed.
        DISCOVERED="$(_discover_server_pids)"
        DISCOVERED="$(echo "$DISCOVERED" | xargs)"
        if [ -n "$DISCOVERED" ]; then
            warn "Found additional server processes outside PID file: $DISCOVERED"
            _kill_pids "$DISCOVERED"
            STOPPED_ANY=true
        fi

        # 3. Always tear down ELK if we stopped anything (or asked nicely)
        _stop_elk

        if $STOPPED_ANY; then
            ok "Server stopped."
        else
            warn "Server is not running."
        fi
        exit 0
        ;;
    status)
        if _server_running; then
            PID=$(cat "$PID_FILE")
            ok "Server is running (PID $PID)"
        else
            DISCOVERED="$(_discover_server_pids | xargs)"
            if [ -n "$DISCOVERED" ]; then
                warn "Server is running but PID file is stale: $DISCOVERED"
                warn "Run '$0 stop' to clean up."
            else
                warn "Server is not running."
                rm -f "$PID_FILE"
            fi
        fi
        exit 0
        ;;
    logs)
        if [ -f "$LOG_FILE" ]; then
            tail -f "$LOG_FILE"
        else
            warn "No log file found at $LOG_FILE"
        fi
        exit 0
        ;;
    -d|--daemon)
        DAEMON_MODE=true
        ;;
    -h|--help)
        echo "Usage: $0 [-d|--daemon] | stop | status | logs"
        echo ""
        echo "  (no args)    Start in foreground"
        echo "  -d, --daemon Start in background"
        echo "  stop         Stop background server"
        echo "  status       Check if server is running"
        echo "  logs         Tail server log file"
        exit 0
        ;;
    "")
        ;; # foreground mode, default
    *)
        fail "Unknown command: $1. Use -h for help."
        ;;
esac

if _server_running; then
    fail "Server is already running (PID $(cat "$PID_FILE")). Run '$0 stop' first."
fi

# ─────────────────────────────────────────
# 3b. Cleanup Function (foreground mode only)
# ─────────────────────────────────────────
cleanup() {
    echo ""
    info "Stopping ELK services..."
    if [ -d "$SCRIPT_DIR/elk" ]; then
        cd "$SCRIPT_DIR/elk" || true
        docker compose stop 2>/dev/null || docker-compose stop 2>/dev/null || true
    elif [ -d "$REPO_ROOT/elk" ]; then
        cd "$REPO_ROOT/elk" || true
        docker compose stop 2>/dev/null || docker-compose stop 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    ok "Services stopped."
}

if [ "$DAEMON_MODE" = false ]; then
    trap cleanup EXIT
fi

# ─────────────────────────────────────────
# 4. Detect OS
# ─────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
    elif [ "$(uname)" == "Darwin" ]; then
        OS_ID="macos"
        OS_VERSION="$(sw_vers -productVersion)"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
    fi
    info "Detected OS: $OS_ID $OS_VERSION"
}

detect_os

# ─────────────────────────────────────────
# 5. Install System Dependencies
# ─────────────────────────────────────────
install_system_deps() {
    info "Checking system dependencies..."

    if [ "$OS_ID" == "macos" ]; then
        # macOS — assume Homebrew installed
        if ! command -v docker &> /dev/null; then
            warn "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
            fail "Docker is required. Please install it and re-run this script."
        fi
        if ! command -v python3 &> /dev/null; then
            info "Installing Python 3 via Homebrew..."
            brew install python3
        fi
        # Install uv on macOS
        if ! command -v uv &> /dev/null; then
            info "Installing uv..."
            curl -LsSf https://astral.sh/uv/install.sh | sh
            export PATH="$HOME/.local/bin:$PATH"
        fi
        ok "macOS dependencies OK."
        return
    fi

    # Linux — install packages
    if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
        warn "Some packages may need sudo. You may be prompted for your password."
    fi

    local SUDO=""
    if [ "$EUID" -ne 0 ]; then
        SUDO="sudo"
    fi

    if [ "$OS_ID" == "ubuntu" ] || [ "$OS_ID" == "debian" ]; then
        info "Installing system packages (apt)..."
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq \
            python3 \
            python3-venv \
            curl \
            lsof \
            git \
            ca-certificates \
            gnupg

        # Install Docker — try docker.io first, fallback to official Docker repo
        if ! command -v docker &> /dev/null; then
            info "Installing Docker..."
            if apt-cache show docker.io &> /dev/null; then
                $SUDO apt-get install -y -qq docker.io
            else
                # Use Docker's official install script (works on all Debian/Ubuntu)
                info "docker.io not in repos, using Docker official installer..."
                curl -fsSL https://get.docker.com | $SUDO sh
            fi
        fi

        # Install docker compose plugin
        if ! docker compose version &> /dev/null; then
            if apt-cache show docker-compose-plugin &> /dev/null; then
                $SUDO apt-get install -y -qq docker-compose-plugin
            else
                info "Installing Docker Compose plugin manually..."
                DOCKER_CONFIG=${DOCKER_CONFIG:-/usr/local/lib/docker}
                $SUDO mkdir -p "$DOCKER_CONFIG/cli-plugins"
                $SUDO curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
                    -o "$DOCKER_CONFIG/cli-plugins/docker-compose"
                $SUDO chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
            fi
        fi

        # Install uv
        if ! command -v uv &> /dev/null; then
            info "Installing uv..."
            curl -LsSf https://astral.sh/uv/install.sh | sh
            export PATH="$HOME/.local/bin:$PATH"
        fi
        ok "APT packages installed."

    elif [ "$OS_ID" == "amzn" ]; then
        info "Installing system packages (yum/dnf)..."
        $SUDO dnf install -y \
            python3 \
            docker \
            curl \
            lsof \
            git \
            > /dev/null 2>&1
        # Install uv
        if ! command -v uv &> /dev/null; then
            info "Installing uv..."
            curl -LsSf https://astral.sh/uv/install.sh | sh
            export PATH="$HOME/.local/bin:$PATH"
        fi
        # docker-compose as plugin
        if ! docker compose version &> /dev/null; then
            info "Installing Docker Compose plugin..."
            DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
            mkdir -p "$DOCKER_CONFIG/cli-plugins"
            curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
                -o "$DOCKER_CONFIG/cli-plugins/docker-compose" 2>/dev/null
            chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
        fi
        ok "DNF packages installed."

    elif [ "$OS_ID" == "centos" ] || [ "$OS_ID" == "rhel" ]; then
        info "Installing system packages (yum)..."
        $SUDO yum install -y \
            python3 \
            docker \
            curl \
            lsof \
            git \
            > /dev/null 2>&1
        # Install uv
        if ! command -v uv &> /dev/null; then
            info "Installing uv..."
            curl -LsSf https://astral.sh/uv/install.sh | sh
            export PATH="$HOME/.local/bin:$PATH"
        fi
        ok "YUM packages installed."
    else
        warn "Unknown Linux distro: $OS_ID. Skipping system package install."
        warn "Please manually install: python3, docker, docker-compose, lsof, curl, uv"
    fi

    # Ensure Docker service is running
    if command -v systemctl &> /dev/null; then
        if ! systemctl is-active --quiet docker 2>/dev/null; then
            info "Starting Docker service..."
            $SUDO systemctl start docker
            $SUDO systemctl enable docker
        fi
        # Add current user to docker group (avoid needing sudo for docker)
        if ! groups | grep -q docker; then
            $SUDO usermod -aG docker "$USER" 2>/dev/null || true
            warn "Added $USER to docker group. You may need to log out and back in."
        fi
    fi

    ok "System dependencies OK."
}

install_system_deps

# ─────────────────────────────────────────
# 6. Verify Core Tools
# ─────────────────────────────────────────
info "Verifying core tools..."
command -v docker &> /dev/null || fail "Docker is not installed."
command -v python3 &> /dev/null || fail "Python 3 is not installed."
command -v uv &> /dev/null || fail "uv is not installed. Run: curl -LsSf https://astral.sh/uv/install.sh | sh"
(docker compose version &> /dev/null || docker-compose --version &> /dev/null) || fail "Docker Compose is not installed."
ok "docker: $(docker --version | head -1)"
ok "uv:     $(uv --version)"
ok "python3: $(python3 --version)"

# ─────────────────────────────────────────
# 7. Check Server Port
# ─────────────────────────────────────────
PORT="$SERVER_PORT"
PID=$(lsof -ti :$PORT 2>/dev/null || true)
if [ -n "$PID" ]; then
    warn "Port $PORT is occupied by PID $PID. Killing it..."
    kill -9 $PID 2>/dev/null || true
    sleep 1
    ok "Port $PORT cleared."
fi

# ─────────────────────────────────────────
# 8. Initialize .env Files
# ─────────────────────────────────────────
init_env_files() {
    # Server .env
    if [ ! -f "$SCRIPT_DIR/.env" ]; then
        info "Creating server/.env with defaults..."
        API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        SESSION_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        cat > "$SCRIPT_DIR/.env" <<EOF
# Honeypot Server Authentication
# ⚠️ IMPORTANT: Change ADMIN_PASSWORD before deploying to production!
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
API_KEY=${API_KEY}
SESSION_SECRET=${SESSION_SECRET}

# FastAPI listen port
SERVER_PORT=8000

# Server Public URL (set to EC2 public IP for remote deployment)
# Leave empty for auto-detect from request headers.
# Example: SERVER_PUBLIC_URL=http://3.25.100.200:8000
SERVER_PUBLIC_URL=

# Kibana URL (leave empty to auto-detect)
KIBANA_URL=

# PostgreSQL database used by the FastAPI server.
# The docker compose stack binds PostgreSQL to 127.0.0.1 only.
POSTGRES_DB=honeypot
POSTGRES_USER=honeypot
POSTGRES_PASSWORD=honeypot_change_me
POSTGRES_PORT=5432
DATABASE_URL=postgresql://honeypot:honeypot_change_me@127.0.0.1:5432/honeypot
EOF
        ok "Created server/.env (API_KEY auto-generated)"
        warn "⚠️  Change ADMIN_PASSWORD before deploying to production!"
    else
        ok "server/.env already exists."
        if ! grep -qE "^SERVER_PORT=" "$SCRIPT_DIR/.env"; then
            cat >> "$SCRIPT_DIR/.env" <<'EOF'

# FastAPI listen port
SERVER_PORT=8000
EOF
            ok "Added SERVER_PORT default to server/.env."
        fi
        if ! grep -qE "^DATABASE_URL=" "$SCRIPT_DIR/.env"; then
            cat >> "$SCRIPT_DIR/.env" <<'EOF'

# PostgreSQL database used by the FastAPI server.
# The docker compose stack binds PostgreSQL to 127.0.0.1 only.
POSTGRES_DB=honeypot
POSTGRES_USER=honeypot
POSTGRES_PASSWORD=honeypot_change_me
POSTGRES_PORT=5432
DATABASE_URL=postgresql://honeypot:honeypot_change_me@127.0.0.1:5432/honeypot
EOF
            ok "Added PostgreSQL defaults to server/.env."
            warn "Change POSTGRES_PASSWORD before production deployment."
        fi
    fi

    # Client .env
    if [ ! -f "$REPO_ROOT/client/.env" ]; then
        info "Creating client/.env..."
        # Try to read API_KEY from server .env
        SERVER_API_KEY=$(grep -E "^API_KEY=" "$SCRIPT_DIR/.env" 2>/dev/null | cut -d'=' -f2- | xargs)
        cat > "$REPO_ROOT/client/.env" <<EOF
# Honeypot Client Agent Configuration
# API_KEY must match the server's API_KEY
API_KEY=${SERVER_API_KEY:-change_me}
EOF
        ok "Created client/.env (API_KEY synced from server)"
    else
        ok "client/.env already exists."
    fi

    # Client config.json
    if [ ! -f "$REPO_ROOT/client/client_config.json" ]; then
        info "Creating client/client_config.json from example..."
        if [ -f "$REPO_ROOT/client/client_config.example.json" ]; then
            cp "$REPO_ROOT/client/client_config.example.json" "$REPO_ROOT/client/client_config.json"
        else
            cat > "$REPO_ROOT/client/client_config.json" <<EOF
{
    "node_id": "node_01",
    "server_url": "http://localhost:${SERVER_PORT}",
    "deployments": []
}
EOF
        fi
        ok "Created client/client_config.json"
    fi
}

init_env_files
_load_server_env_config

# ─────────────────────────────────────────
# 9. Python Virtual Environment & Dependencies (uv)
# ─────────────────────────────────────────
VENV_DIR="$REPO_ROOT/.venv"

if [ ! -d "$VENV_DIR" ]; then
    info "Creating Python virtual environment with uv..."
    uv venv "$VENV_DIR" || fail "Failed to create virtual environment."
    ok "Virtual environment created at $VENV_DIR"
fi

info "Activating virtual environment..."
source "$VENV_DIR/bin/activate"
PYTHON_BIN="$VENV_DIR/bin/python"

REQ_FILE="$REPO_ROOT/requirements.txt"
if [ -f "$REQ_FILE" ]; then
    info "Installing Python dependencies with uv..."
    uv pip install -r "$REQ_FILE"
    ok "Python dependencies installed."
else
    warn "requirements.txt not found at $REQ_FILE."
fi

# ─────────────────────────────────────────
# 10. Create Log Directories
# ─────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$REPO_ROOT/client/runtime"

# Filebeat runs in Docker and older log files may have been created as root.
# The FastAPI server must be able to append JSON logs, otherwise Filebeat and
# ElastAlert stop seeing new events even though PostgreSQL keeps receiving them.
if [ -d "$SCRIPT_DIR/logs" ]; then
    if find "$SCRIPT_DIR/logs" -maxdepth 1 -type f ! -writable | grep -q .; then
        if command -v sudo &> /dev/null; then
            sudo chown -R "$(id -u):$(id -g)" "$SCRIPT_DIR/logs" || true
        fi
    fi
    chmod -R u+rwX,g+rX "$SCRIPT_DIR/logs" 2>/dev/null || true
fi

# Keep the daemon log from growing forever. Uvicorn access logs are disabled
# in main.py, but existing deployments may already have large files.
if [ -f "$LOG_FILE" ]; then
    LOG_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$LOG_SIZE" -gt $((100 * 1024 * 1024)) ]; then
        mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d%H%M%S)"
        ok "Rotated oversized server.log."
    fi
fi

# ─────────────────────────────────────────
# 11. Start ELK Stack
# ─────────────────────────────────────────
info "Starting ELK Stack (Docker)..."

if [ -d "$SCRIPT_DIR/elk" ]; then
    ELK_DIR="$SCRIPT_DIR/elk"
elif [ -d "$REPO_ROOT/elk" ]; then
    ELK_DIR="$REPO_ROOT/elk"
else
    fail "'elk' directory not found in $SCRIPT_DIR or $REPO_ROOT."
fi

cd "$ELK_DIR" || exit

# Use 'docker compose' (v2) or fallback to 'docker-compose' (v1)
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Compose variable substitution reads exported shell variables. Load
# server/.env here so the same values feed PostgreSQL and ElastAlert even on
# older Compose builds that do not support --env-file.
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$SCRIPT_DIR/.env"
    set +a
    SERVER_PORT="${SERVER_PORT:-8000}"
    if ! _validate_port "$SERVER_PORT"; then
        fail "Invalid SERVER_PORT=$SERVER_PORT in server/.env. Use a number from 1 to 65535."
    fi
    if [ -z "${SERVER_INGEST_URL:-}" ]; then
        export SERVER_INGEST_URL="http://host.docker.internal:${SERVER_PORT}/api/alerts/ingest"
    fi
else
    warn "$SCRIPT_DIR/.env not found — ElastAlert webhook may post without an API key."
fi

$COMPOSE_CMD up -d --force-recreate

if [ $? -ne 0 ]; then
    fail "Failed to start ELK stack. Ensure Docker is running."
fi

ok "ELK Stack started (Elasticsearch, Kibana, Filebeat, ElastAlert)."

# ─────────────────────────────────────────
# 12. Start Python Server
# ─────────────────────────────────────────
cd "$SCRIPT_DIR" || exit

# Detect public URL for display
SERVER_URL="http://localhost:${SERVER_PORT}"
KIBANA_URL="http://localhost:5601"
if [ -f "$SCRIPT_DIR/.env" ]; then
    PUBLIC_URL=$(grep -E "^SERVER_PUBLIC_URL=" "$SCRIPT_DIR/.env" | cut -d'=' -f2- | xargs)
    if [ -n "$PUBLIC_URL" ]; then
        SERVER_URL="$PUBLIC_URL"
    fi
    CUSTOM_KIBANA=$(grep -E "^KIBANA_URL=" "$SCRIPT_DIR/.env" | cut -d'=' -f2- | xargs)
    if [ -n "$CUSTOM_KIBANA" ]; then
        KIBANA_URL="$CUSTOM_KIBANA"
    fi
fi

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}  APS Honeypot Server                    ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "  Dashboard: ${CYAN}${SERVER_URL}${NC}"
echo -e "  Kibana:    ${CYAN}${KIBANA_URL}${NC}"

if [ "$DAEMON_MODE" = true ]; then
    echo -e "  Mode:      ${CYAN}Background (daemon)${NC}"
    echo -e "  Log:       ${CYAN}${LOG_FILE}${NC}"
    echo -e "  Stop:      ${CYAN}$0 stop${NC}"
    echo -e "${GREEN}==========================================${NC}"
    echo ""
    setsid -f "$PYTHON_BIN" main.py >> "$LOG_FILE" 2>&1 < /dev/null
    sleep 1
    NEW_PID=$(pgrep -f "$PYTHON_BIN main.py" | tail -1)
    echo "$NEW_PID" > "$PID_FILE"
    ok "Server started in background (PID $NEW_PID)"
    ok "View logs: $0 logs"
else
    echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop"
    echo -e "${GREEN}==========================================${NC}"
    echo ""
    echo $$ > "$PID_FILE"
    "$PYTHON_BIN" main.py
fi
