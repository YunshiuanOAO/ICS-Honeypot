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
    
    if not existing:
        # Prevent auto-registration.
        # Unknown agent logic: Return unregistered status and stop command.
        return {"status": "unregistered", "command": "stop"}
    else:
        # Check if we should adopt client config (First sync)
        try:
            current_server_conf = json.loads(existing['config_json'])
            # Only adopt if server has no PLCs AND user didn't manually set it (we assume manual set has priority)
            # Actually, if existing logic was "adoption", we keep it. 
            if not current_server_conf.get('plcs') and hb.config and hb.config.get('plcs'):
                print(f"Adopting config from agent {hb.node_id}")
                db.update_agent_config(hb.node_id, hb.config)
        except Exception as e:
            print(f"Error syncing config: {e}")

        db.update_heartbeat(hb.node_id)
        
        # Check active status
        if existing['is_active'] == 0:
            command = "stop"
    
    return {"status": "ok", "command": command}

@app.get("/api/config/{node_id}")
async def get_config(node_id: str):
    agent = db.get_agent(node_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found. Please register manually.")

    return JSONResponse(content=json.loads(agent['config_json']))

@app.post("/api/logs")
async def upload_logs(batch: LogBatch):
    count = db.insert_logs(batch.node_id, batch.logs)
    return {"status": "recieved", "count": count}

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
    node_id = payload.get("node_id")
    config = payload.get("config")
    if node_id and config:
        db.update_agent_config(node_id, config)
        return {"status": "updated"}
    return {"status": "error"}

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
