from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import uvicorn
import os
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

# --- API Endpoints ---

@app.post("/api/heartbeat")
async def heartbeat(hb: Heartbeat):
    # Register or update status
    existing = db.get_agent(hb.node_id)
    
    command = "start" # Default command
    response_extras = {}

    if not existing:
        # 1. Adoption Check: Check if this node_id was renamed to something else
        # Scan all agents to see if 'original_id' matches hb.node_id
        # (Optimization: In a large system this should be a DB query, but fine for prototype)
        all_agents = db.get_all_agents()
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
            return {
                "status": "adopted", 
                "command": "stop", # Stop temporarily to reload
                "new_node_id": adopted_agent['node_id']
            }

        # 2. Auto-Registration for Unknown Agents
        print(f"Auto-registering new agent: {hb.node_id} ({hb.ip})")
        # Create a default pending config
        pending_config = {
            "node_id": hb.node_id,
            "server_url": "http://localhost:8000",
            "plcs": [], # Empty PLCs
            "original_id": hb.node_id # Track itself initially
        }
        db.register_agent(hb.node_id, name=f"Pending ({hb.node_id})", ip=hb.ip, config=pending_config)
        # Mark as standby initially? Or let it run (with 0 PLCs it does nothing)
        # We'll just return OK.
        return {"status": "registered", "command": "start"}

    else:
        # Existing Agent
        db.update_heartbeat(hb.node_id)
        
        # Check active status
        if existing['is_active'] == 0:
            command = "stop"
    
    return {"status": "ok", "command": command}

@app.get("/api/config/{node_id}")
async def get_config(node_id: str):
    agent = db.get_agent(node_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found. please wait for auto-registration.")

    response_data = json.loads(agent['config_json'])
    response_data['name'] = agent['name'] # Ensure we return the authoritative name
    return JSONResponse(content=response_data)

@app.post("/api/logs")
async def upload_logs(batch: LogBatch):
    count = db.insert_logs(batch.node_id, batch.logs)
    return {"status": "recieved", "count": count}

# --- Profile Endpoints ---
 
# Point to client/profiles directory
# Assuming structure: /root/server/main.py and /root/client/profiles
PROFILES_DIR = os.path.join(os.path.dirname(BASE_DIR), "client", "profiles")

@app.get("/api/profiles")
async def list_profiles():
    """List available profile files"""
    if not os.path.exists(PROFILES_DIR):
        print(f"Warning: Profiles dir not found: {PROFILES_DIR}")
        return []
    
    profiles = []
    for f in os.listdir(PROFILES_DIR):
        if f.endswith(".json"):
            name = f.replace(".json", "")
            # Read minimal metadata
            try:
                with open(os.path.join(PROFILES_DIR, f), 'r') as file:
                    data = json.load(file)
                    desc = data.get("description", "No description")
                    profiles.append({
                        "name": name,
                        "description": desc,
                        # Check protocols
                        "type": "modbus" if "modbus" in data else "s7comm" # Simple heuristic
                    })
            except:
                continue
    return profiles

@app.get("/api/profiles/{name}")
async def get_profile(name: str):
    """Get full content of a profile"""
    file_path = os.path.join(PROFILES_DIR, f"{name}.json")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Profile not found")
    
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Web UI Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/agents")
async def get_agents():
    agents = db.get_all_agents()
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
            "plcs": []
        }
        
    db.register_agent(node_id, name=name, ip=ip, config=config_dict)
    return {"status": "added"}

@app.post("/api/agents/{node_id}/toggle")
async def toggle_agent(node_id: str, payload: Dict[str, bool]):
    is_active = payload.get("is_active", True)
    db.toggle_agent_active(node_id, is_active)
    return {"status": "toggled", "is_active": is_active}

@app.delete("/api/agents/{node_id}")
async def delete_agent(node_id: str):
    db.delete_agent(node_id)
    return {"status": "deleted"}

@app.get("/api/recent_logs")
async def recent_logs():
    logs = db.get_recent_logs(limit=50)
    return logs

@app.post("/api/update_agent_config")
async def update_agent_config(payload: Dict[str, Any]):
    current_node_id = payload.get("node_id")
    new_node_id = payload.get("new_node_id")
    config = payload.get("config")
    name = payload.get("name")
    
    if not current_node_id or not config:
        return {"status": "error", "message": "Missing node_id or config"}

    # Handle Rename
    target_node_id = current_node_id
    if new_node_id and new_node_id != current_node_id:
        success, msg = db.rename_agent(current_node_id, new_node_id)
        if not success:
            return {"status": "error", "message": f"Rename failed: {msg}"}
        target_node_id = new_node_id
        
        # Update config object to match new ID
        config['node_id'] = target_node_id
        
        # KEY CHANGE: Store original ID so we can track adoption
        config['original_id'] = current_node_id 

    # Update Config and Name
    db.update_agent_config(target_node_id, config, name=name)
    
    return {"status": "updated", "new_node_id": target_node_id}

@app.post("/api/admin/sync_elk")
async def sync_elk():
    import elk_exporter
    try:
        elk_exporter.export_logs()
        return {"status": "ok", "message": "Logs exported to JSON for Filebeat"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
