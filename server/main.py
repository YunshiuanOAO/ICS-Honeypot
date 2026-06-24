from fastapi import FastAPI, Request, HTTPException, Form, UploadFile, File, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import asyncio
import base64
import binascii
import uvicorn
import os
import shutil
import sqlite3
import uuid
import zipfile
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from database import ServerDB
from postgres_database import PostgresServerDB
from auth_config import load_secrets, verify_password, verify_api_key
from package_generators import (
    SUPPORTED_PROTOCOLS,
    PackageGenerationError,
    generate_package,
)

# Resolve paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "server.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
if DATABASE_URL.startswith(("postgres://", "postgresql://")):
    db = PostgresServerDB(DATABASE_URL)
else:
    db = ServerDB(DB_PATH)


# --- Per-agent whitelist ---------------------------------------------------
# Each agent has its own whitelist stored in the agents table (whitelist_json
# column). The dashboard edits each agent's whitelist via
# GET/PUT /api/whitelist?node_id=...  The whitelist is injected into the
# agent's /api/config response so clients always receive their own list.
_WHITELIST_DEFAULT: Dict[str, Any] = {"enabled": True, "ips": [], "cidrs": [], "description": ""}


def _validate_whitelist_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize + validate an incoming whitelist. Raises HTTPException on bad input."""
    import ipaddress

    ips_in = payload.get("ips") or []
    cidrs_in = payload.get("cidrs") or []
    if isinstance(ips_in, str):
        ips_in = [line.strip() for line in ips_in.splitlines()]
    if isinstance(cidrs_in, str):
        cidrs_in = [line.strip() for line in cidrs_in.splitlines()]

    ips: List[str] = []
    cidrs: List[str] = []
    invalid: List[str] = []

    for raw in ips_in:
        s = str(raw).strip()
        if not s:
            continue
        try:
            ipaddress.ip_address(s)
            ips.append(s)
        except ValueError:
            invalid.append(f"IP:{s}")

    for raw in cidrs_in:
        s = str(raw).strip()
        if not s:
            continue
        try:
            ipaddress.ip_network(s, strict=False)
            cidrs.append(s)
        except ValueError:
            invalid.append(f"CIDR:{s}")

    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid entries: {', '.join(invalid)}")

    return {
        "enabled": bool(payload.get("enabled", True)),
        "ips": ips,
        "cidrs": cidrs,
        "description": str(payload.get("description") or ""),
    }

# Load auth secrets from .env
auth_secrets = load_secrets()

# Server public URL for client-agent communication (set in .env for EC2 deployment)
SERVER_PUBLIC_URL = os.environ.get("SERVER_PUBLIC_URL", "").strip()
KIBANA_URL = os.environ.get("KIBANA_URL", "").strip()


def get_server_public_url(request: Request = None) -> str:
    """Return the public server URL for client agents.
    Priority: SERVER_PUBLIC_URL env var > auto-detect from request host header > localhost fallback.
    """
    if SERVER_PUBLIC_URL:
        return SERVER_PUBLIC_URL.rstrip("/")
    if request:
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
        if host:
            return f"{scheme}://{host}"
    return "http://localhost:8000"


app = FastAPI(title="Honeypot Central Server")


# Add CORS middleware for cross-origin requests (needed when frontend is served from a different domain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=auth_secrets["session_secret"])

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)


# --- Auth Dependencies ---

async def require_api_key(x_api_key: str = Header(None)):
    """Dependency: require valid API key for client agent endpoints."""
    if not x_api_key or not verify_api_key(x_api_key, auth_secrets["api_key"]):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


async def require_session(request: Request):
    """Dependency: require authenticated session for dashboard endpoints."""
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Not authenticated")


async def require_api_key_or_session(request: Request, x_api_key: str = Header(None)):
    """Dependency: accept either API key or authenticated session."""
    if x_api_key and verify_api_key(x_api_key, auth_secrets["api_key"]):
        return
    if request.session.get("authenticated"):
        return
    raise HTTPException(status_code=401, detail="Not authenticated")


# --- Login / Logout Endpoints ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if (username == auth_secrets["admin_username"]
            and verify_password(password, auth_secrets["admin_password_hash"], auth_secrets["admin_salt"])):
        request.session["authenticated"] = True
        request.session["username"] = username
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request=request, name="login.html", context={"request": request, "error": "Invalid username or password"})


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)



# --- Pydantic Models for API ---
class LogBatch(BaseModel):
    node_id: str
    logs: List[Dict[str, Any]]

class Heartbeat(BaseModel):
    node_id: str
    ip: str
    name: Optional[str] = "Unknown"
    config: Optional[Dict[str, Any]] = None
    deployment_status: Optional[Dict[str, Any]] = None


_PRIVATE_IP_PREFIXES = (
    "10.", "127.", "169.254.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    return ip.startswith(_PRIVATE_IP_PREFIXES) or ip == "::1" or ip.startswith("fc") or ip.startswith("fd")


def _get_client_ip(request: Request) -> Optional[str]:
    """Extract the real client IP from the request.

    Honors standard reverse-proxy headers (X-Forwarded-For, X-Real-IP) so
    agents behind NAT / behind a reverse proxy report their public IP rather
    than an internal VM address (e.g. GCP 10.x.x.x).
    """
    # X-Forwarded-For: "client, proxy1, proxy2" — the first non-private entry
    # is the original client.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        for candidate in (part.strip() for part in xff.split(",")):
            if candidate and not _is_private_ip(candidate):
                return candidate
        # All entries were private — fall through to other sources, but keep
        # the first as a last-resort value.
        first = xff.split(",")[0].strip()
        if first:
            return first

    # X-Real-IP: single value set by nginx/traefik/caddy reverse proxies.
    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()

    # Direct socket peer (no reverse proxy in front).
    if request.client and request.client.host:
        return request.client.host

    return None


def _merge_deployments(server_deployments: List[Dict[str, Any]], client_deployments: List[Dict[str, Any]]):
    merged = []
    client_by_id = {}

    for deployment in client_deployments or []:
        deployment_id = deployment.get("id")
        if deployment_id:
            client_by_id[deployment_id] = deployment

    seen = set()
    for deployment in server_deployments or []:
        deployment_id = deployment.get("id")
        if deployment_id and deployment_id in client_by_id:
            server_updated = deployment.get("files_updated_at")
            client_updated = client_by_id[deployment_id].get("files_updated_at")
            if server_updated and (not client_updated or server_updated > client_updated):
                merged.append(deployment)
            else:
                merged.append(client_by_id[deployment_id])
            seen.add(deployment_id)
        else:
            merged.append(deployment)
            if deployment_id:
                seen.add(deployment_id)

    for deployment in client_deployments or []:
        deployment_id = deployment.get("id")
        if deployment_id and deployment_id in seen:
            continue
        merged.append(deployment)

    return merged

# --- API Endpoints ---

@app.post("/api/heartbeat", dependencies=[Depends(require_api_key)])
async def heartbeat(hb: Heartbeat, request: Request):
    # Prefer the real client IP detected from the HTTP connection. Agents in
    # cloud VMs (GCP, AWS, etc.) often self-report their internal VPC address
    # because their OS-level interface has no public IP bound. Detecting the
    # IP server-side gives us the actual public IP attackers would reach,
    # which is what the attack map should display.
    detected_ip = _get_client_ip(request)
    if detected_ip and not _is_private_ip(detected_ip):
        hb.ip = detected_ip
    elif detected_ip and _is_private_ip(hb.ip):
        # Both detected and client-reported are private — at least keep the
        # one closest to the real edge (detected from the connection).
        hb.ip = detected_ip

    # Register or update status
    existing = await db.get_agent(hb.node_id)

    command = "start" # Default command
    response_extras = {}

    if not existing:
        # 1. Adoption Check: Check if this node_id was renamed to something else
        # Scan all agents to see if 'original_id' matches hb.node_id
        # (Optimization: In a large system this should be a DB query, but fine for prototype)
        all_agents = await db.get_all_agents()
        adopted_agent = None
        for agent in all_agents:
            try:
                conf = json.loads(agent['config_json'])
                if conf.get('original_id') == hb.node_id:
                    adopted_agent = agent
                    break
            except:
                pass
        
        if adopted_agent:
            # Found! This agent was renamed. Tell client to update.
            print(f"Adoption match: {hb.node_id} -> {adopted_agent['node_id']}")
            # Update heartbeat for the adopted agent so it stays online
            await db.update_heartbeat(adopted_agent['node_id'], ip=hb.ip, name=None, runtime_status=hb.deployment_status or {})
            return {
                "status": "adopted", 
                "command": "stop", # Stop temporarily to reload
                "new_node_id": adopted_agent['node_id']
            }

        # 2. Auto-Registration for Unknown Agents
        print(f"Auto-registering new agent: {hb.node_id} ({hb.ip})")
        # Use client-side config as the initial source of truth when available
        server_url = get_server_public_url(request)
        pending_config = hb.config or {
            "node_id": hb.node_id,
            "server_url": server_url,
            "deployments": [],
        }
        pending_config["node_id"] = hb.node_id
        pending_config.setdefault("server_url", server_url)
        pending_config.setdefault("deployments", [])
        pending_config.setdefault("original_id", hb.node_id)
        await db.register_agent(
            hb.node_id,
            name=hb.name or f"Pending ({hb.node_id})",
            ip=hb.ip,
            config=pending_config,
            runtime_status=hb.deployment_status or {},
        )
        # Mark as standby initially? Or let it run (with 0 PLCs it does nothing)
        # We'll just return OK.
        return {"status": "registered", "command": "start"}

    else:
        # Existing Agent
        await db.update_heartbeat(hb.node_id, ip=hb.ip, name=hb.name, runtime_status=hb.deployment_status or {})

        if hb.config:
            server_config = {}
            try:
                server_config = json.loads(existing.get("config_json") or "{}")
            except Exception:
                server_config = {}

            client_config = dict(hb.config)
            client_config["node_id"] = hb.node_id
            client_config.setdefault("server_url", server_config.get("server_url") or get_server_public_url(request))
            client_config.setdefault("original_id", server_config.get("original_id") or hb.node_id)

            server_deployments = server_config.get("deployments") or []
            client_deployments = client_config.get("deployments") or []

            merged_config = dict(server_config)
            merged_config.update(client_config)
            merged_config["deployments"] = _merge_deployments(server_deployments, client_deployments)
            await db.update_agent_config(hb.node_id, merged_config, name=hb.name)
        
        # Check active status
        if existing['is_active'] == 0:
            command = "stop"
    
    return {"status": "ok", "command": command}

@app.get("/api/config/{node_id}", dependencies=[Depends(require_api_key_or_session)])
async def get_config(node_id: str, request: Request):
    agent = await db.get_agent(node_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found. please wait for auto-registration.")

    try:
        if agent['config_json']:
            response_data = json.loads(agent['config_json'])
        else:
            response_data = {}
    except json.JSONDecodeError:
        print(f"Error decoding config for {node_id}: Invalid JSON")
        # Fallback to empty or minimal config
        response_data = {
            "node_id": node_id,
            "server_url": get_server_public_url(request), 
            "deployments": []
        }
        
    response_data['name'] = agent['name'] # Ensure we return the authoritative name
    # Inject the per-agent whitelist so clients apply their own list without
    # needing a local whitelist.json file.
    wl = await db.get_agent_whitelist(node_id)
    response_data['whitelist'] = wl if wl else dict(_WHITELIST_DEFAULT)
    return JSONResponse(content=response_data)

@app.post("/api/logs", dependencies=[Depends(require_api_key)])
async def upload_logs(batch: LogBatch):
    count = await db.insert_logs(batch.node_id, batch.logs)
    return {"status": "received", "count": count}


@app.post("/api/whitelist_logs", dependencies=[Depends(require_api_key)])
async def upload_whitelist_logs(batch: LogBatch):
    """Receive whitelist (friendly) traffic from agents.

    Stored in the whitelist_logs table — never enters the attack-log
    pipeline (attack map, recent_logs, ELK ingest).
    """
    count = await db.insert_whitelist_logs(batch.node_id, batch.logs)
    return {"status": "received", "count": count}


@app.get("/api/whitelist", dependencies=[Depends(require_session)])
async def get_whitelist(node_id: str = ""):
    """Return the whitelist for a specific agent."""
    if not node_id:
        raise HTTPException(status_code=400, detail="node_id query parameter is required")
    agent = await db.get_agent(node_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    wl = await db.get_agent_whitelist(node_id)
    return wl if wl else dict(_WHITELIST_DEFAULT)


@app.put("/api/whitelist", dependencies=[Depends(require_session)])
async def update_whitelist(payload: Dict[str, Any]):
    """Update the whitelist for a specific agent. Pushed on the agent's next config fetch."""
    node_id = payload.pop("node_id", None)
    if not node_id:
        raise HTTPException(status_code=400, detail="node_id is required in the payload")
    agent = await db.get_agent(node_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    data = _validate_whitelist_payload(payload)
    await db.update_agent_whitelist(node_id, data)
    return {"status": "saved", "whitelist": data}


@app.get("/api/server_info")
async def server_info(request: Request):
    """Return server configuration info for the frontend (e.g., Kibana URL)."""
    kibana_url = KIBANA_URL
    if not kibana_url:
        # Auto-detect from current request host
        host = request.headers.get("host", "localhost")
        hostname = host.split(":")[0]  # Strip port
        kibana_url = f"http://{hostname}:5601"
    return {
        "kibana_url": kibana_url,
        "server_url": get_server_public_url(request),
    }


# --- GeoIP Proxy ---
# Frontend used to call https://ip-api.com/json/... directly, but that endpoint
# only supports HTTP on the free tier. When the dashboard is loaded over HTTPS
# the browser blocks the mixed-content fetch and the map silently falls back to
# lat=0, lon=0. Proxy through the server instead and cache responses.
_GEOIP_CACHE: Dict[str, Dict[str, Any]] = {}
_GEOIP_TTL_SECONDS = 24 * 60 * 60  # 24h


@app.get("/api/geoip/{ip}")
async def geoip_lookup(ip: str):
    """Server-side GeoIP proxy with TTL cache.

    Avoids mixed-content / CORS problems when the frontend is served over HTTPS.
    Returns { ip, lat, lon, country, city, status }.
    """
    ip = (ip or "").strip()
    if not ip or _is_private_ip(ip):
        return {
            "ip": ip,
            "lat": 0,
            "lon": 0,
            "country": "Private Network",
            "city": "Local",
            "status": "private",
        }

    now = time.time()
    cached = _GEOIP_CACHE.get(ip)
    if cached and (now - cached.get("_ts", 0)) < _GEOIP_TTL_SECONDS:
        return {k: v for k, v in cached.items() if k != "_ts"}

    # Try ipwho.is first (free, HTTPS, no key, CORS-friendly).
    providers = [
        ("ipwho", f"https://ipwho.is/{ip}?fields=success,country,city,latitude,longitude"),
        ("ip-api", f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon"),
    ]
    result: Optional[Dict[str, Any]] = None
    for name, url in providers:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "honeypot-server/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError):
            continue

        if name == "ipwho" and data.get("success"):
            result = {
                "ip": ip,
                "lat": data.get("latitude") or 0,
                "lon": data.get("longitude") or 0,
                "country": data.get("country") or "",
                "city": data.get("city") or "",
                "status": "success",
            }
            break
        if name == "ip-api" and data.get("status") == "success":
            result = {
                "ip": ip,
                "lat": data.get("lat") or 0,
                "lon": data.get("lon") or 0,
                "country": data.get("country") or "",
                "city": data.get("city") or "",
                "status": "success",
            }
            break

    if result is None:
        result = {
            "ip": ip,
            "lat": 0,
            "lon": 0,
            "country": "Unknown",
            "city": "",
            "status": "fail",
        }

    _GEOIP_CACHE[ip] = {**result, "_ts": now}
    return result

# --- Profile Endpoints ---
 
# Point to client/profiles directory
# Assuming structure: /root/server/main.py and /root/client/profiles
PROFILES_DIR = os.path.join(os.path.dirname(BASE_DIR), "client", "profiles")

import aiofiles

@app.get("/api/profiles", dependencies=[Depends(require_session)])
async def list_profiles():
    """List available profile files"""
    if not os.path.exists(PROFILES_DIR):
        print(f"Warning: Profiles dir not found: {PROFILES_DIR}")
        return []
    
    profiles = []
    # os.listdir is fast enough for small directories, but reading content should be async
    try:
        for f in os.listdir(PROFILES_DIR):
            if f.endswith(".json"):
                name = f.replace(".json", "")
                # Read minimal metadata
                try:
                    async with aiofiles.open(os.path.join(PROFILES_DIR, f), 'r') as file:
                        content = await file.read()
                        data = json.loads(content)
                        desc = data.get("description", "No description")
                        profiles.append({
                            "name": name,
                            "description": desc,
                            # Check protocols
                            "type": "modbus"
                        })
                except:
                    continue
    except Exception as e:
        print(f"Error listing profiles: {e}")
        return []
        
    return profiles

@app.get("/api/profiles/{name}", dependencies=[Depends(require_session)])
async def get_profile(name: str):
    """Get full content of a profile"""
    # Security: Sanitize path to prevent directory traversal
    safe_name = os.path.basename(name)
    if not safe_name or safe_name != name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid profile name")
    
    file_path = os.path.join(PROFILES_DIR, f"{safe_name}.json")
    
    # Additional security check: ensure resolved path is within PROFILES_DIR
    resolved_path = os.path.realpath(file_path)
    if not resolved_path.startswith(os.path.realpath(PROFILES_DIR)):
        raise HTTPException(status_code=400, detail="Invalid profile name")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Profile not found")
    
    try:
        async with aiofiles.open(file_path, 'r') as f:
            content = await f.read()
            return json.loads(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
PACKAGE_LIBRARY_DIR = os.path.join(UPLOADS_DIR, "library")
SERVICE_TEMPLATES_DIR = os.path.join(BASE_DIR, "service_templates")


def _safe_extract_zip(archive_path: str, extract_dir: str):
    extracted_files = []
    base_path = Path(extract_dir).resolve()

    with zipfile.ZipFile(archive_path, "r") as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue

            member_path = Path(member.filename)
            clean_parts = [part for part in member_path.parts if part not in ("", ".", "..")]
            if not clean_parts:
                continue

            if clean_parts[0] == "__MACOSX":
                continue

            target_path = (base_path / Path(*clean_parts)).resolve()
            if base_path not in target_path.parents and target_path != base_path:
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted_files.append(target_path)

    return extracted_files


def _deployment_file_entry(relative_path: str, raw: bytes) -> Dict[str, Any]:
    if b"\x00" not in raw:
        try:
            return {
                "path": relative_path,
                "content": raw.decode("utf-8"),
                "encoding": "text",
                "size_bytes": len(raw),
            }
        except UnicodeDecodeError:
            pass

    return {
        "path": relative_path,
        "content": base64.b64encode(raw).decode("ascii"),
        "encoding": "base64",
        "size_bytes": len(raw),
    }


def _deployment_file_bytes(item: Dict[str, Any]) -> bytes:
    content = item.get("content") or ""
    if item.get("encoding") == "base64":
        try:
            return base64.b64decode(str(content), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid base64 content for {item.get('path') or 'file'}: {exc}") from exc
    return str(content).encode("utf-8")


def _read_extracted_files(extracted_files, extract_dir: str):
    extract_root = Path(extract_dir).resolve()
    relative_paths = []
    for file_path in extracted_files:
        try:
            rp = Path(file_path).resolve().relative_to(extract_root)
            if rp.parts and rp.parts[0] == "__MACOSX":
                continue
            relative_paths.append(rp)
        except ValueError:
            continue

    top_levels = {path.parts[0] for path in relative_paths if path.parts}
    strip_leading = len(top_levels) == 1 and all(len(path.parts) > 1 for path in relative_paths)
    source_dir = next(iter(top_levels), "imported-package") if top_levels else "imported-package"

    files = []
    for relative_path in sorted(relative_paths):
        display_path = Path(*relative_path.parts[1:]) if strip_leading else relative_path
        if not display_path.parts:
            continue

        absolute_path = extract_root / relative_path
        files.append(_deployment_file_entry(display_path.as_posix(), absolute_path.read_bytes()))

    return {
        "source_dir": source_dir,
        "files": files,
    }


def _slugify(text: str, fallback: str = "package"):
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(text or ""))
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned or fallback


def _save_package_to_library(name: str, source_dir: str, files: List[Dict[str, Any]], archive_name: str):
    package_id = uuid.uuid4().hex
    package_root = os.path.join(PACKAGE_LIBRARY_DIR, package_id)
    package_source_dir = _slugify(source_dir or Path(archive_name).stem, "imported-package")
    package_files_root = os.path.join(package_root, "package", package_source_dir)
    os.makedirs(package_files_root, exist_ok=True)

    normalized_files = []
    for item in files:
        relative_path = str(item.get("path") or "").replace("\\", "/").strip("/")
        if not relative_path:
            continue
        safe_parts = [part for part in relative_path.split("/") if part not in ("", ".", "..")]
        if not safe_parts:
            continue
        target_path = os.path.join(package_files_root, *safe_parts)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        raw = _deployment_file_bytes(item)
        with open(target_path, "wb") as handle:
            handle.write(raw)
        normalized_item = {
            "path": "/".join(safe_parts),
            "content": item.get("content") or "",
            "encoding": item.get("encoding") or "text",
            "size_bytes": len(raw),
        }
        normalized_files.append(normalized_item)

    metadata = {
        "id": package_id,
        "name": name,
        "source_dir": package_source_dir,
        "archive_name": archive_name,
        "file_count": len(normalized_files),
        "created_at": datetime.now().isoformat(),
    }
    with open(os.path.join(package_root, "metadata.json"), "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2, ensure_ascii=False)

    return {
        **metadata,
        "files": normalized_files,
    }


def _list_package_library():
    if not os.path.exists(PACKAGE_LIBRARY_DIR):
        return []

    packages = []
    for package_id in sorted(os.listdir(PACKAGE_LIBRARY_DIR)):
        metadata_path = os.path.join(PACKAGE_LIBRARY_DIR, package_id, "metadata.json")
        if not os.path.exists(metadata_path):
            continue
        try:
            with open(metadata_path, "r", encoding="utf-8") as handle:
                packages.append(json.load(handle))
        except Exception:
            continue
    return packages


def _load_package_from_library(package_id: str):
    # Security: Sanitize package_id to prevent directory traversal
    safe_package_id = os.path.basename(package_id)
    if not safe_package_id or safe_package_id != package_id or ".." in package_id:
        raise HTTPException(status_code=400, detail="Invalid package ID")
    
    package_root = os.path.join(PACKAGE_LIBRARY_DIR, safe_package_id)
    
    # Additional security check: ensure resolved path is within PACKAGE_LIBRARY_DIR
    resolved_path = os.path.realpath(package_root)
    if not resolved_path.startswith(os.path.realpath(PACKAGE_LIBRARY_DIR)):
        raise HTTPException(status_code=400, detail="Invalid package ID")
    
    metadata_path = os.path.join(package_root, "metadata.json")
    if not os.path.exists(metadata_path):
        raise HTTPException(status_code=404, detail="Package not found")

    with open(metadata_path, "r", encoding="utf-8") as handle:
        metadata = json.load(handle)

    package_source_dir = metadata.get("source_dir") or "package"
    package_files_root = os.path.join(package_root, "package", package_source_dir)
    files = []
    for root, dirs, filenames in os.walk(package_files_root):
        dirs[:] = [d for d in dirs if d != "__MACOSX"]
        for filename in sorted(filenames):
            if filename.startswith("._"):
                continue
            absolute_path = os.path.join(root, filename)
            relative_path = os.path.relpath(absolute_path, package_files_root).replace("\\", "/")
            if relative_path.startswith("__MACOSX/") or "/__MACOSX/" in relative_path:
                continue
            files.append(_deployment_file_entry(relative_path, Path(absolute_path).read_bytes()))

    return {
        **metadata,
        "files": files,
    }


def _read_package_dir(package_dir: str):
    package_root = Path(package_dir).resolve()
    if not package_root.exists() or not package_root.is_dir():
        raise HTTPException(status_code=404, detail="Template package directory not found")

    files = []
    skip_dirs = {"__pycache__", ".git", "node_modules", "data", "logs", "db"}
    for root, dirs, filenames in os.walk(package_root):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for filename in sorted(filenames):
            if filename.startswith("._"):
                continue
            absolute_path = Path(root) / filename
            relative_path = absolute_path.resolve().relative_to(package_root).as_posix()
            files.append(_deployment_file_entry(relative_path, absolute_path.read_bytes()))
    return files


def _safe_template_id(template_id: str) -> str:
    safe_id = os.path.basename(template_id or "")
    if not safe_id or safe_id != template_id or ".." in template_id:
        raise HTTPException(status_code=400, detail="Invalid template ID")
    return safe_id


def _load_service_template(template_id: str):
    safe_id = _safe_template_id(template_id)
    template_root = os.path.join(SERVICE_TEMPLATES_DIR, safe_id)
    resolved_root = os.path.realpath(template_root)
    if not resolved_root.startswith(os.path.realpath(SERVICE_TEMPLATES_DIR)):
        raise HTTPException(status_code=400, detail="Invalid template ID")

    metadata_path = os.path.join(template_root, "template.json")
    if not os.path.exists(metadata_path):
        raise HTTPException(status_code=404, detail="Service template not found")

    with open(metadata_path, "r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    metadata["_root"] = template_root
    return metadata


def _list_service_templates():
    if not os.path.isdir(SERVICE_TEMPLATES_DIR):
        return []

    templates = []
    for template_id in sorted(os.listdir(SERVICE_TEMPLATES_DIR)):
        metadata_path = os.path.join(SERVICE_TEMPLATES_DIR, template_id, "template.json")
        if not os.path.exists(metadata_path):
            continue
        try:
            with open(metadata_path, "r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            templates.append({
                "id": metadata.get("id") or template_id,
                "name": metadata.get("name") or template_id,
                "description": metadata.get("description") or "",
                "category": metadata.get("category") or "custom",
                "deployment_count": len(metadata.get("deployments") or []),
            })
        except Exception:
            continue
    return templates


def _instantiate_service_template(template_id: str):
    template = _load_service_template(template_id)
    template_root = template.pop("_root")
    suffix = uuid.uuid4().hex[:8]
    now_ms = int(time.time() * 1000)
    deployments = []

    for index, item in enumerate(template.get("deployments") or []):
        package_dir = item.get("package_dir")
        if not package_dir:
            raise HTTPException(status_code=400, detail=f"Template deployment {index} missing package_dir")
        package_path = os.path.realpath(os.path.join(template_root, package_dir))
        if not package_path.startswith(os.path.realpath(template_root)):
            raise HTTPException(status_code=400, detail="Invalid template package path")

        base_id = _slugify(item.get("id") or item.get("name") or f"deployment-{index + 1}", f"deployment-{index + 1}")
        deployment_id = f"{base_id}-{suffix}"
        deployment = {
            "id": deployment_id,
            "name": item.get("name") or base_id,
            "template": item.get("template") or template.get("id") or template_id,
            "enabled": item.get("enabled", True),
            "source_dir": item.get("source_dir") or base_id,
            "log_paths": item.get("log_paths") or [],
            "proxies": item.get("proxies") or [],
            "files": _read_package_dir(package_path),
            "files_updated_at": now_ms,
            "library_package_id": "",
            "library_package_name": template.get("name") or template_id,
        }
        deployments.append(deployment)

    return {
        "status": "ok",
        "template": {
            "id": template.get("id") or template_id,
            "name": template.get("name") or template_id,
            "description": template.get("description") or "",
            "category": template.get("category") or "custom",
        },
        "deployments": deployments,
    }


@app.post("/api/import_package_zip", dependencies=[Depends(require_session)])
async def import_package_zip(archive: UploadFile = File(...)):
    filename = archive.filename or "package.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are supported")

    import_id = uuid.uuid4().hex
    import_root = os.path.join(UPLOADS_DIR, "imports", import_id)
    extract_dir = os.path.join(import_root, "extracted")
    archive_path = os.path.join(import_root, filename)
    os.makedirs(import_root, exist_ok=True)
    os.makedirs(extract_dir, exist_ok=True)

    try:
        async with aiofiles.open(archive_path, "wb") as handle:
            while True:
                chunk = await archive.read(1024 * 1024)
                if not chunk:
                    break
                await handle.write(chunk)

        extracted_files = _safe_extract_zip(archive_path, extract_dir)
        result = _read_extracted_files(extracted_files, extract_dir)
        package_name = Path(filename).stem
        library_package = _save_package_to_library(
            name=package_name,
            source_dir=result["source_dir"],
            files=result["files"],
            archive_name=filename,
        )
        response = {
            "status": "ok",
            "import_id": import_id,
            "source_dir": result["source_dir"],
            "files": result["files"],
            "package_id": library_package["id"],
            "package_name": library_package["name"],
        }
        shutil.rmtree(import_root, ignore_errors=True)
        return response
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail=f"Invalid zip archive: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/import_package_json", dependencies=[Depends(require_session)])
async def import_package_json(
    config: UploadFile = File(...),
    protocol: str = Form(...),
    name: str = Form(""),
):
    """
    Generate a deployable honeypot package from a single JSON config file.

    The user uploads only the data (e.g. register map for modbus, or a
    streetlight command_response_map for mqtt) and selects a protocol.
    The server fills in the Dockerfile, compose file, and simulator script.
    """
    proto = (protocol or "").strip().lower()
    if proto not in SUPPORTED_PROTOCOLS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported protocol '{protocol}'. Choose one of: {', '.join(SUPPORTED_PROTOCOLS)}",
        )

    raw = await config.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Config file is empty")

    try:
        config_data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Config file must be UTF-8 encoded")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}")

    package_name = (name or "").strip() or Path(config.filename or f"{proto}-from-json").stem

    try:
        generated = generate_package(proto, config_data, package_name)
    except PackageGenerationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    library_package = _save_package_to_library(
        name=package_name,
        source_dir=generated["source_dir"],
        files=generated["files"],
        archive_name=config.filename or f"{proto}-from-json.json",
    )

    return {
        "status": "ok",
        "protocol": generated["protocol"],
        "source_dir": library_package["source_dir"],
        "files": library_package["files"],
        "package_id": library_package["id"],
        "package_name": library_package["name"],
    }


@app.get("/api/package_library", dependencies=[Depends(require_session)])
async def list_package_library():
    return _list_package_library()


@app.get("/api/package_library/{package_id}", dependencies=[Depends(require_session)])
async def get_package_library_item(package_id: str):
    return _load_package_from_library(package_id)


@app.delete("/api/package_library/{package_id}", dependencies=[Depends(require_session)])
async def delete_package_library_item(package_id: str):
    safe_package_id = os.path.basename(package_id)
    if not safe_package_id or safe_package_id != package_id or ".." in package_id:
        raise HTTPException(status_code=400, detail="Invalid package ID")

    package_root = os.path.join(PACKAGE_LIBRARY_DIR, safe_package_id)
    resolved_path = os.path.realpath(package_root)
    if not resolved_path.startswith(os.path.realpath(PACKAGE_LIBRARY_DIR)):
        raise HTTPException(status_code=400, detail="Invalid package ID")

    if not os.path.exists(package_root):
        raise HTTPException(status_code=404, detail="Package not found")

    try:
        shutil.rmtree(package_root)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete package: {e}")
    return {"status": "deleted"}


@app.get("/api/service_templates", dependencies=[Depends(require_session)])
async def list_service_templates():
    return _list_service_templates()


@app.post("/api/service_templates/{template_id}/instantiate", dependencies=[Depends(require_session)])
async def instantiate_service_template(template_id: str):
    return _instantiate_service_template(template_id)


# --- Web UI Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not request.session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})

@app.get("/config/{node_id}", response_class=HTMLResponse)
async def config_page(request: Request, node_id: str):
    if not request.session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="config.html", context={"request": request, "node_id": node_id})

@app.get("/api/agents", dependencies=[Depends(require_session)])
async def get_agents():
    agents = await db.get_all_agents()
    return agents

@app.post("/api/agents", dependencies=[Depends(require_session)])
async def add_agent(
    node_id: str = Form(...), 
    name: str = Form(...),
    ip: str = Form("0.0.0.0"),
    config_json: str = Form(...) # Expecting JSON string
):
    try:
        config_dict = json.loads(config_json)
    except json.JSONDecodeError:
        config_dict = {
            "node_id": node_id,
            "server_url": get_server_public_url(),
            "deployments": []
        }
        
    await db.register_agent(node_id, name=name, ip=ip, config=config_dict)
    return {"status": "added"}

@app.post("/api/agents/{node_id}/toggle", dependencies=[Depends(require_session)])
async def toggle_agent(node_id: str, payload: Dict[str, bool]):
    is_active = payload.get("is_active", True)
    await db.toggle_agent_active(node_id, is_active)
    return {"status": "toggled", "is_active": is_active}

@app.delete("/api/agents/{node_id}", dependencies=[Depends(require_session)])
async def delete_agent(node_id: str):
    await db.delete_agent(node_id)
    return {"status": "deleted"}

@app.post("/api/agents/{node_id}/reset", dependencies=[Depends(require_session)])
async def reset_agent(node_id: str):
    """Factory reset: completely forget the agent so it can re-register as new"""
    try:
        # Get the agent first to verify it exists
        agent = await db.get_agent(node_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Delete the agent completely (same as delete operation)
        # This makes the server forget all information about this agent
        await db.delete_agent(node_id)
        
        return {"status": "reset", "message": "Agent has been factory reset. It can now re-register as a new agent."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/recent_logs", dependencies=[Depends(require_session)])
async def recent_logs(limit: str = "50"):
    if str(limit).lower() == "all":
        parsed_limit = 500
    else:
        try:
            parsed_limit = max(1, min(int(limit), 1000))
        except (TypeError, ValueError):
            parsed_limit = 50
    try:
        logs = await db.get_recent_logs(limit=parsed_limit)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="Recent logs query timed out; retry shortly")
    return logs


@app.get("/api/dashboard_stats", dependencies=[Depends(require_session)])
async def dashboard_stats():
    return await db.get_dashboard_stats()


# ── IP-grouped log analysis (powers the panel below the Attack Map) ──

def _normalize_to_utc_iso(value: Optional[str]) -> Optional[str]:
    """Convert any user-supplied ISO timestamp to a UTC ISO string with
    ``+00:00`` offset. Naive (TZ-less) input is interpreted as local time —
    that's what HTML's ``<input type="datetime-local">`` emits.

    Logs in the DB are stored with UTC offsets (the proxy generates
    ``...+00:00`` timestamps), so comparing against UTC strings is the
    only correct path. Local-naive ``datetime.now().isoformat()`` strings
    silently produce empty results in TZ != UTC environments.
    """
    if not value:
        return None
    from datetime import datetime as _dt, timezone as _tz
    try:
        dt = _dt.fromisoformat(value)
    except ValueError:
        return value  # let SQLite do its best — fail open
    if dt.tzinfo is None:
        dt = dt.astimezone()  # attach local tz
    return dt.astimezone(_tz.utc).isoformat()


@app.get("/api/ip_analysis", dependencies=[Depends(require_session)])
async def ip_analysis(
    limit: int = 200,
    page: int = 1,
    page_size: int = 100,
    search: Optional[str] = None,
    hide_agent_ips: bool = False,
    hide_private_ips: bool = False,
    hours: Optional[int] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
):
    """Return attacker-IP rollups: counts, protocols, agents touched, alert stats.

    Time-range options (mutually exclusive — precedence: explicit range > hours):
    - ``from_ts`` / ``to_ts``: ISO timestamps for a custom window (either may be omitted)
    - ``hours``: rolling window of the last N hours
    """
    since: Optional[str] = None
    until: Optional[str] = None
    if from_ts or to_ts:
        since = _normalize_to_utc_iso(from_ts)
        until = _normalize_to_utc_iso(to_ts)
    elif hours:
        from datetime import timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    try:
        page_size = max(25, min(int(page_size or limit or 100), 500))
        page = max(1, int(page or 1))
        exclude_ips = await db.get_agent_ips() if hide_agent_ips else []
        offset = (page - 1) * page_size
        summary = await db.get_ip_summary(
            limit=page_size,
            offset=offset,
            since=since,
            until=until,
            ip_search=(search or "").strip() or None,
            exclude_ips=exclude_ips,
            hide_private_ips=hide_private_ips,
        )
    except sqlite3.OperationalError as e:
        detail = str(e)
        if "locked" in detail.lower() or "busy" in detail.lower():
            raise HTTPException(status_code=503, detail="IP analysis database is busy; retry shortly")
        if "interrupted" in detail.lower():
            raise HTTPException(status_code=503, detail="IP analysis query timed out; retry with a shorter time range")
        raise HTTPException(status_code=500, detail=f"IP analysis database error: {detail}")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="IP analysis query timed out; retry with a shorter time range")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IP analysis failed: {e}")

    if isinstance(summary, dict):
        rows = summary.get("rows", [])
        total = summary.get("total", len(rows))
    else:
        rows = summary
        total = len(rows)

    # Suricata severity is 1=high, 2=medium, 3=low. max_severity from SQL is
    # the MIN (because lower number = higher severity). Normalize null=0.
    for r in rows:
        sev = r.get("max_severity") or 0
        r["max_severity"] = sev if sev else 0
        r["protocols"] = (r.get("protocols") or "").split(",") if r.get("protocols") else []
        r["node_ids"] = (r.get("node_ids") or "").split(",") if r.get("node_ids") else []
    return {
        "rows": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": offset + len(rows) < total,
        "has_prev": page > 1,
    }


@app.get("/api/ip_details/{ip}", dependencies=[Depends(require_session)])
async def ip_details(ip: str, limit: int = 200):
    """Return packets + alerts for one attacker IP."""
    ip = (ip or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")
    logs = await db.get_logs_by_ip(ip, limit=limit)
    alerts = await db.get_alerts(limit=limit, ip=ip)
    return {"ip": ip, "logs": logs, "alerts": alerts}


@app.get("/api/alerts", dependencies=[Depends(require_session)])
async def list_alerts(limit: int = 200, ip: Optional[str] = None):
    return await db.get_alerts(limit=limit, ip=ip)


# ── External alert ingest (ElastAlert webhook, etc.) ──

# Sentinel signature_id used when an external tool forgets to supply one.
_INGEST_FALLBACK_SID = 7000000


def _coerce_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@app.post("/api/alerts/ingest", dependencies=[Depends(require_api_key)])
async def ingest_alert(payload: Dict[str, Any]):
    """Accept a single alert from an external tool (ElastAlert, Suricata
    forwarder, custom rule engines).

    Required: ``signature`` and ``attacker_ip``. Everything else is
    optional — unknown fields are preserved in the metadata column so
    no information is lost.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object expected")

    signature = (payload.get("signature") or "").strip()
    attacker_ip = (payload.get("attacker_ip") or payload.get("src_ip") or "").strip()
    if not signature:
        raise HTTPException(status_code=400, detail="`signature` is required")
    if not attacker_ip:
        raise HTTPException(status_code=400, detail="`attacker_ip` is required")

    # Normalize severity (Suricata convention: 1=high, 2=med, 3=low). If
    # an external tool sends 0 or something weird, fall back to "low".
    severity = _coerce_int(payload.get("severity"), default=3)
    if severity < 1 or severity > 4:
        severity = 3

    timestamp = (payload.get("timestamp") or "").strip() or datetime.now().isoformat()

    alert = {
        "timestamp": timestamp,
        "attacker_ip": attacker_ip,
        "node_id": (payload.get("node_id") or "").strip(),
        "protocol": (payload.get("protocol") or "").lower(),
        "signature": signature,
        "signature_id": _coerce_int(payload.get("signature_id"), default=_INGEST_FALLBACK_SID),
        "category": payload.get("category") or "Misc activity",
        "severity": severity,
        "src_ip": payload.get("src_ip") or attacker_ip,
        "src_port": _coerce_int(payload.get("src_port"), default=0),
        "dst_ip": payload.get("dst_ip") or "",
        "dst_port": _coerce_int(payload.get("dst_port"), default=0),
        "log_id": None,
        "source": payload.get("source") or "elastalert",
        "metadata": payload,
    }
    inserted = await db.insert_alert(alert)
    return {"status": "ok", "inserted": bool(inserted)}


@app.get("/api/whitelist_logs", dependencies=[Depends(require_session)])
async def recent_whitelist_logs(limit: int = 100, node_id: Optional[str] = None):
    """Return recent whitelist (friendly) traffic entries.

    Optional query params:
    - ``limit``: max rows to return (default 100)
    - ``node_id``: filter to a single agent
    """
    logs = await db.get_recent_whitelist_logs(limit=limit, node_id=node_id)
    return logs

def validate_config_proxy_settings(config: Dict[str, Any]) -> tuple[bool, str]:
    """Validate proxy config across all deployments.

    Each deployment may carry either a legacy ``proxy`` dict or a ``proxies``
    list. Every enabled proxy must have unique listen and backend ports across
    the entire agent.
    """
    if not isinstance(config.get("deployments"), list):
        return True, ""

    used_ports: Dict[int, str] = {}
    errors = []

    for dep in config["deployments"]:
        if not dep.get("enabled", True):
            continue

        dep_name = dep.get("name", dep.get("id", "unknown"))

        proxies = dep.get("proxies")
        if not isinstance(proxies, list):
            legacy = dep.get("proxy")
            proxies = [legacy] if isinstance(legacy, dict) else []

        names_seen = set()
        for index, proxy in enumerate(proxies):
            if not isinstance(proxy, dict) or not proxy.get("enabled"):
                continue

            proxy_name = str(proxy.get("name") or f"proxy-{index + 1}")
            label = f'"{dep_name}" / proxy "{proxy_name}"'

            if proxy_name in names_seen:
                errors.append(f'{label}: duplicate proxy name within deployment')
            names_seen.add(proxy_name)

            listen_port = proxy.get("listen_port")
            backend_port = proxy.get("backend_port")

            if not listen_port or not backend_port:
                errors.append(f'{label}: Proxy enabled but ports not configured')
                continue

            if not (1 <= int(listen_port) <= 65535):
                errors.append(f'{label}: Invalid listen port {listen_port}')
            if not (1 <= int(backend_port) <= 65535):
                errors.append(f'{label}: Invalid backend port {backend_port}')

            if listen_port in used_ports:
                errors.append(f'Port conflict: Listen port {listen_port} used by {label} and {used_ports[listen_port]}')
            if backend_port in used_ports:
                errors.append(f'Port conflict: Backend port {backend_port} used by {label} and {used_ports[backend_port]}')

            used_ports[listen_port] = label
            used_ports[backend_port] = label

    if errors:
        return False, "; ".join(errors)
    return True, ""


@app.post("/api/update_agent_config", dependencies=[Depends(require_session)])
async def update_agent_config(payload: Dict[str, Any]):
    current_node_id = payload.get("node_id")
    new_node_id = payload.get("new_node_id")
    config = payload.get("config")
    name = payload.get("name")
    
    if not current_node_id or not config:
        return {"status": "error", "message": "Missing node_id or config"}
    
    # Validate proxy configuration
    is_valid, error_msg = validate_config_proxy_settings(config)
    if not is_valid:
        return {"status": "error", "message": f"Configuration validation failed: {error_msg}"}

    # Handle Rename
    target_node_id = current_node_id
    if new_node_id and new_node_id != current_node_id:
        success, msg = await db.rename_agent(current_node_id, new_node_id)
        if not success:
            return {"status": "error", "message": f"Rename failed: {msg}"}
        target_node_id = new_node_id
        
        # Update config object to match new ID
        config['node_id'] = target_node_id
        
        # KEY CHANGE: Store original ID so we can track adoption
        config['original_id'] = current_node_id 

    # Update Config and Name
    await db.update_agent_config(target_node_id, config, name=name)
    
    return {"status": "updated", "new_node_id": target_node_id}

@app.post("/api/admin/sync_elk", dependencies=[Depends(require_session)])
async def sync_elk():
    try:
        import importlib
        elk_exporter = importlib.import_module("elk_exporter")
        elk_exporter.export_logs()
        return {"status": "ok", "message": "Logs exported to JSON for Filebeat"}
    except ModuleNotFoundError:
        return {"status": "error", "message": "elk_exporter module is not available in this build"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False, access_log=False)
