from fastapi import FastAPI, Request, HTTPException, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import uvicorn
import os
import shutil
import uuid
import zipfile
from pathlib import Path
from datetime import datetime
from database import ServerDB

app = FastAPI(title="Honeypot Central Server")

# Resolve paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "server.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

db = ServerDB(DB_PATH)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

import json

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

@app.post("/api/heartbeat")
async def heartbeat(hb: Heartbeat):
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
        pending_config = hb.config or {
            "node_id": hb.node_id,
            "server_url": "http://localhost:8000",
            "deployments": [],
        }
        pending_config["node_id"] = hb.node_id
        pending_config.setdefault("server_url", "http://localhost:8000")
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
            client_config.setdefault("server_url", server_config.get("server_url") or "http://localhost:8000")
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

@app.get("/api/config/{node_id}")
async def get_config(node_id: str):
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
            "server_url": "http://localhost:8000", 
            "deployments": []
        }
        
    response_data['name'] = agent['name'] # Ensure we return the authoritative name
    return JSONResponse(content=response_data)

@app.post("/api/logs")
async def upload_logs(batch: LogBatch):
    count = await db.insert_logs(batch.node_id, batch.logs)
    return {"status": "received", "count": count}

# --- Profile Endpoints ---
 
# Point to client/profiles directory
# Assuming structure: /root/server/main.py and /root/client/profiles
PROFILES_DIR = os.path.join(os.path.dirname(BASE_DIR), "client", "profiles")

import aiofiles

@app.get("/api/profiles")
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

@app.get("/api/profiles/{name}")
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


DEPLOYMENT_TEMPLATES_DIR = os.path.join(BASE_DIR, "deployment_templates")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
PACKAGE_LIBRARY_DIR = os.path.join(UPLOADS_DIR, "library")


@app.get("/api/deployment_templates")
async def list_deployment_templates():
    if not os.path.exists(DEPLOYMENT_TEMPLATES_DIR):
        return []

    templates_data = []
    for filename in sorted(os.listdir(DEPLOYMENT_TEMPLATES_DIR)):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(DEPLOYMENT_TEMPLATES_DIR, filename)
        try:
            async with aiofiles.open(file_path, 'r') as handle:
                content = await handle.read()
                templates_data.append(json.loads(content))
        except Exception:
            continue

    return templates_data


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
            relative_paths.append(Path(file_path).resolve().relative_to(extract_root))
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


@app.post("/api/import_package_zip")
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


@app.get("/api/package_library")
async def list_package_library():
    return _list_package_library()


@app.get("/api/package_library/{package_id}")
async def get_package_library_item(package_id: str):
    return _load_package_from_library(package_id)


# --- Web UI Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/config/{node_id}", response_class=HTMLResponse)
async def config_page(request: Request, node_id: str):
    return templates.TemplateResponse("config.html", {"request": request, "node_id": node_id})

@app.get("/api/agents")
async def get_agents():
    agents = await db.get_all_agents()
    return agents

@app.post("/api/agents")
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
            "server_url": "http://localhost:8000",
            "deployments": []
        }
        
    await db.register_agent(node_id, name=name, ip=ip, config=config_dict)
    return {"status": "added"}

@app.post("/api/agents/{node_id}/toggle")
async def toggle_agent(node_id: str, payload: Dict[str, bool]):
    is_active = payload.get("is_active", True)
    await db.toggle_agent_active(node_id, is_active)
    return {"status": "toggled", "is_active": is_active}

@app.delete("/api/agents/{node_id}")
async def delete_agent(node_id: str):
    await db.delete_agent(node_id)
    return {"status": "deleted"}

@app.post("/api/agents/{node_id}/reset")
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

@app.get("/api/recent_logs")
async def recent_logs():
    logs = await db.get_recent_logs(limit=50)
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


@app.post("/api/update_agent_config")
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

@app.post("/api/admin/sync_elk")
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
