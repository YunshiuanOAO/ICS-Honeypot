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

# ─────────────────────────────────────────
# 3. Cleanup Function
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
    ok "Services stopped."
}

trap cleanup EXIT

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
            docker.io \
            docker-compose-plugin \
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
# 7. Check Port 8000
# ─────────────────────────────────────────
PORT=8000
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

# Server Public URL (set to EC2 public IP for remote deployment)
# Leave empty for auto-detect from request headers.
# Example: SERVER_PUBLIC_URL=http://3.25.100.200:8000
SERVER_PUBLIC_URL=

# Kibana URL (leave empty to auto-detect)
KIBANA_URL=
EOF
        ok "Created server/.env (API_KEY auto-generated)"
        warn "⚠️  Change ADMIN_PASSWORD before deploying to production!"
    else
        ok "server/.env already exists."
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
    "server_url": "http://localhost:8000",
    "deployments": []
}
EOF
        fi
        ok "Created client/client_config.json"
    fi
}

init_env_files

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

$COMPOSE_CMD up -d --force-recreate

if [ $? -ne 0 ]; then
    fail "Failed to start ELK stack. Ensure Docker is running."
fi

ok "ELK Stack started."

# ─────────────────────────────────────────
# 12. Start Python Server
# ─────────────────────────────────────────
cd "$SCRIPT_DIR" || exit

# Detect public URL for display
SERVER_URL="http://localhost:8000"
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
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop"
echo -e "${GREEN}==========================================${NC}"
echo ""

python3 main.py
