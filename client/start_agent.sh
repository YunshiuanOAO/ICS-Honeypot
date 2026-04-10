#!/bin/bash

# ==========================================
# APS Honeypot — Client Agent Startup Script
# Supports: Ubuntu 22.04 / 24.04, Amazon Linux 2023
# ==========================================

set -e

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
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ─────────────────────────────────────────
# 3. Detect OS
# ─────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
    elif [ "$(uname)" == "Darwin" ]; then
        OS_ID="macos"
    else
        OS_ID="unknown"
    fi
    info "Detected OS: $OS_ID"
}

detect_os

# ─────────────────────────────────────────
# 4. Install System Dependencies
# ─────────────────────────────────────────
install_deps() {
    info "Checking system dependencies..."

    local SUDO=""
    if [ "$EUID" -ne 0 ] 2>/dev/null; then
        SUDO="sudo"
    fi

    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        if [ "$OS_ID" == "macos" ]; then
            fail "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
        elif [ "$OS_ID" == "ubuntu" ] || [ "$OS_ID" == "debian" ]; then
            info "Installing Docker..."
            $SUDO apt-get update -qq
            $SUDO apt-get install -y -qq ca-certificates curl gnupg > /dev/null 2>&1
            
            if apt-cache show docker.io &> /dev/null; then
                $SUDO apt-get install -y -qq docker.io docker-compose-plugin > /dev/null 2>&1
            else
                info "docker.io not in repos, using Docker official installer..."
                curl -fsSL https://get.docker.com | $SUDO sh
                
                # Install compose plugin manually if needed
                if ! docker compose version &> /dev/null; then
                    info "Installing Docker Compose plugin manually..."
                    DOCKER_CONFIG=${DOCKER_CONFIG:-/usr/local/lib/docker}
                    $SUDO mkdir -p "$DOCKER_CONFIG/cli-plugins"
                    $SUDO curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
                        -o "$DOCKER_CONFIG/cli-plugins/docker-compose"
                    $SUDO chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
                fi
            fi
        elif [ "$OS_ID" == "amzn" ]; then
            info "Installing Docker..."
            $SUDO dnf install -y docker > /dev/null 2>&1
        fi
    fi

    # Install Python if not present
    if ! command -v python3 &> /dev/null; then
        if [ "$OS_ID" == "ubuntu" ] || [ "$OS_ID" == "debian" ]; then
            $SUDO apt-get install -y -qq python3 > /dev/null 2>&1
        elif [ "$OS_ID" == "amzn" ]; then
            $SUDO dnf install -y python3 > /dev/null 2>&1
        elif [ "$OS_ID" == "macos" ]; then
            brew install python3
        fi
    fi

    # Install uv if not present
    if ! command -v uv &> /dev/null; then
        info "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
    fi

    # Install other tools
    if [ "$OS_ID" != "macos" ]; then
        if ! command -v lsof &> /dev/null || ! command -v curl &> /dev/null; then
            if [ "$OS_ID" == "ubuntu" ] || [ "$OS_ID" == "debian" ]; then
                $SUDO apt-get install -y -qq curl lsof git > /dev/null 2>&1
            elif [ "$OS_ID" == "amzn" ]; then
                $SUDO dnf install -y curl lsof git > /dev/null 2>&1
            fi
        fi
    fi

    # Ensure Docker service is running (Linux only)
    if [ "$OS_ID" != "macos" ] && command -v systemctl &> /dev/null; then
        if ! systemctl is-active --quiet docker 2>/dev/null; then
            info "Starting Docker service..."
            $SUDO systemctl start docker
            $SUDO systemctl enable docker
        fi
        if ! groups | grep -q docker 2>/dev/null; then
            $SUDO usermod -aG docker "$USER" 2>/dev/null || true
            warn "Added $USER to docker group. You may need to log out and back in."
        fi
    fi

    ok "System dependencies OK."
}

install_deps

# ─────────────────────────────────────────
# 5. Verify Core Tools
# ─────────────────────────────────────────
info "Verifying core tools..."
command -v docker &> /dev/null || fail "Docker is not installed."
command -v python3 &> /dev/null || fail "Python 3 is not installed."
command -v uv &> /dev/null || fail "uv is not installed. Run: curl -LsSf https://astral.sh/uv/install.sh | sh"
ok "docker:  $(docker --version | head -1)"
ok "uv:      $(uv --version)"
ok "python3: $(python3 --version)"

# ─────────────────────────────────────────
# 6. Initialize Config Files
# ─────────────────────────────────────────
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    info "Creating client/.env..."
    cat > "$SCRIPT_DIR/.env" <<EOF
# Honeypot Client Agent Configuration
# API_KEY must match the server's API_KEY
API_KEY=change_me
EOF
    warn "⚠️  Edit client/.env and set API_KEY to match the server!"
fi

if [ ! -f "$SCRIPT_DIR/client_config.json" ]; then
    if [ -f "$SCRIPT_DIR/client_config.example.json" ]; then
        cp "$SCRIPT_DIR/client_config.example.json" "$SCRIPT_DIR/client_config.json"
        info "Created client_config.json from example."
    else
        cat > "$SCRIPT_DIR/client_config.json" <<EOF
{
    "node_id": "node_01",
    "server_url": "http://localhost:8000",
    "deployments": []
}
EOF
        info "Created default client_config.json."
    fi
    warn "⚠️  Edit client_config.json: set node_id and server_url!"
fi

# ─────────────────────────────────────────
# 7. Python Virtual Environment (uv)
# ─────────────────────────────────────────
VENV_DIR="$REPO_ROOT/.venv"

if [ ! -d "$VENV_DIR" ]; then
    info "Creating Python virtual environment with uv..."
    uv venv "$VENV_DIR" || fail "Failed to create virtual environment."
    ok "Virtual environment created."
fi

info "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

REQ_FILE="$REPO_ROOT/requirements.txt"
if [ -f "$REQ_FILE" ]; then
    info "Installing Python dependencies with uv..."
    uv pip install -r "$REQ_FILE"
    ok "Python dependencies installed."
else
    warn "requirements.txt not found. Skipping dependency install."
fi

# ─────────────────────────────────────────
# 8. Create Runtime Directories
# ─────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/runtime"

# ─────────────────────────────────────────
# 9. Validate Config Before Starting
# ─────────────────────────────────────────
info "Validating configuration..."

# Check API_KEY
API_KEY=$(grep -E "^API_KEY=" "$SCRIPT_DIR/.env" 2>/dev/null | cut -d'=' -f2- | xargs)
if [ -z "$API_KEY" ] || [ "$API_KEY" == "change_me" ]; then
    fail "API_KEY is not set! Edit client/.env and set the API_KEY from your server."
fi

# Check server_url
SERVER_URL=$(python3 -c "
import json
with open('$SCRIPT_DIR/client_config.json') as f:
    print(json.load(f).get('server_url', ''))
" 2>/dev/null)

if [ -z "$SERVER_URL" ] || [ "$SERVER_URL" == "http://localhost:8000" ]; then
    warn "server_url is set to localhost. Make sure this is correct for your deployment."
fi

NODE_ID=$(python3 -c "
import json
with open('$SCRIPT_DIR/client_config.json') as f:
    print(json.load(f).get('node_id', ''))
" 2>/dev/null)

ok "Config validated."

# ─────────────────────────────────────────
# 10. Start Client Agent
# ─────────────────────────────────────────
cd "$SCRIPT_DIR" || fail "Cannot enter client directory."

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}  APS Honeypot Client Agent              ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "  Node ID:    ${CYAN}${NODE_ID}${NC}"
echo -e "  Server:     ${CYAN}${SERVER_URL}${NC}"
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop"
echo -e "${GREEN}==========================================${NC}"
echo ""

python3 main.py
