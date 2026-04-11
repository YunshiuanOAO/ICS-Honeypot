from fastapi import FastAPI, Request, HTTPException, Form, UploadFile, File, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import uvicorn
import os
import shutil
import uuid
import zipfile
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from database import ServerDB
from auth_config import load_secrets, verify_password, verify_api_key

# Resolve paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "server.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
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
        try:
            content = absolute_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = absolute_path.read_text(encoding="utf-8", errors="replace")

        files.append({
            "path": display_path.as_posix(),
            "content": content,
        })

    return {
        "source_dir": source_dir,
        "files": files,
    }


def _slugify(text: str, fallback: str = "package"):
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(text or ""))
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned or fallback


def _save_package_to_library(name: str, source_dir: str, files: List[Dict[str, str]], archive_name: str):
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
        content = item.get("content") or ""
        with open(target_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        normalized_files.append({
            "path": "/".join(safe_parts),
            "content": content,
        })

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
    for root, _, filenames in os.walk(package_files_root):
        for filename in sorted(filenames):
            absolute_path = os.path.join(root, filename)
            relative_path = os.path.relpath(absolute_path, package_files_root).replace("\\", "/")
            try:
                content = Path(absolute_path).read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = Path(absolute_path).read_text(encoding="utf-8", errors="replace")
            files.append({
                "path": relative_path,
                "content": content,
            })

    return {
        **metadata,
        "files": files,
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
        return {
            "status": "ok",
            "import_id": import_id,
            "source_dir": result["source_dir"],
            "files": result["files"],
            "package_id": library_package["id"],
            "package_name": library_package["name"],
        }
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail=f"Invalid zip archive: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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
async def recent_logs():
    logs = await db.get_recent_logs(limit=50)
    return logs


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
    """
    Validate proxy configuration in the config object.
    Returns (is_valid, error_message)
    """
    if not isinstance(config.get("deployments"), list):
        return True, ""  # No deployments is ok
    
    deployment_ports = {}
    errors = []
    
    for dep in config["deployments"]:
        if not dep.get("enabled", True):
            continue
        
        proxy = dep.get("proxy")
        if not proxy or not proxy.get("enabled"):
            continue
        
        dep_name = dep.get("name", dep.get("id", "unknown"))
        listen_port = proxy.get("listen_port")
        backend_port = proxy.get("backend_port")
        
        # Check if ports are configured
        if not listen_port or not backend_port:
            errors.append(f'Deployment "{dep_name}": Proxy enabled but ports not configured')
            continue
        
        # Check port ranges
        if not (1 <= listen_port <= 65535):
            errors.append(f'Deployment "{dep_name}": Invalid listen port {listen_port}')
        if not (1 <= backend_port <= 65535):
            errors.append(f'Deployment "{dep_name}": Invalid backend port {backend_port}')
        
        # Check for port conflicts
        if listen_port in deployment_ports:
            other_dep = deployment_ports[listen_port]
            errors.append(f'Port conflict: Listen port {listen_port} used by "{dep_name}" and "{other_dep}"')
        
        if backend_port in deployment_ports:
            other_dep = deployment_ports[backend_port]
            errors.append(f'Port conflict: Backend port {backend_port} used by "{dep_name}" and "{other_dep}"')
        
        deployment_ports[listen_port] = dep_name
        deployment_ports[backend_port] = dep_name
    
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
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
