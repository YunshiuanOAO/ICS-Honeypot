import time
import threading
import requests
from config_loader import ConfigLoader
from db.database import LogDB
from plc.modbus_plc import ModbusPLC
from plc.s7_plc import S7PLC

class NodeAgent:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self.config = self.config_loader.load_config()
        self.db = LogDB()
        self.plcs = []
        self.running = False
        self.server_url = self.config.get("server_url", "http://localhost:8000")
        self.node_id = self.config.get("node_id", "node_unknown")

    def start(self):
        self.running = True
        print(f"Node Agent {self.node_id} starting...")
        
        # Check if we have valid PLC config
        # If not (e.g. fresh install or empty config), wait for server
        while not self.config.get("plcs"):
            print(f"[{self.node_id}] No PLC configuration found. Waiting for config from Server...")
            self._send_heartbeat() # Send heartbeat so server knows we are alive
            self._fetch_config()
            
            if self.config.get("plcs"):
                print(f"[{self.node_id}] Configuration received!")
                break
                
            time.sleep(5)

        # Start PLCs based on config
        # self._start_plcs() <--- REMOVED: Wait for server heartbeat command

        
        # Start background tasks (Log sync, Config sync)
        self.sync_thread = threading.Thread(target=self._sync_loop)
        self.sync_thread.daemon = True
        self.sync_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        print("Stopping Node Agent...")
        self._stop_plcs()
        print("Node Agent stopped.")

    def _stop_plcs(self):
        for plc in self.plcs:
            try:
                plc.stop()
            except Exception as e:
                print(f"Error stopping PLC: {e}")
        self.plcs = []

    def _start_plcs(self):
        print("Starting PLCs...")
        plc_configs = self.config.get("plcs", [])
        for plc_conf in plc_configs:
            if plc_conf.get("enabled"):
                plc_type = plc_conf.get("type")
                port = plc_conf.get("port")
                
                try:
                    if plc_type == "modbus":
                        plc = ModbusPLC(
                            port=port, 
                            db=self.db, 
                            model=plc_conf.get("model", "Unknown Modbus Device"),
                            devices=plc_conf.get("devices")
                        )
                        plc.start()
                        self.plcs.append(plc)
                    elif plc_type == "s7comm":
                        plc = S7PLC(port=port, db=self.db, model=plc_conf.get("model", "Unknown S7 Device"))
                        plc.start()
                        self.plcs.append(plc)
                    else:
                        print(f"Unknown PLC type: {plc_type}")
                except Exception as e:
                    print(f"Failed to start PLC {plc_type}: {e}")

    def _sync_loop(self):
        while self.running:
            try:
                # 0. Heartbeat
                self._send_heartbeat()

                # 1. Fetch config updates (Prioritized)
                self._fetch_config()

                # 2. Send unsent logs to server
                self._upload_logs()
                
            except Exception as e:
                print(f"Sync error: {e}")
            
            time.sleep(5) # Sync every 5 seconds

    def _send_heartbeat(self):
        try:
            payload = {
                "node_id": self.node_id,
                "ip": "127.0.0.1", # In real deployment, get actual IP
                "name": f"Agent {self.node_id}",
                "config": self.config # Send current config
            }
            response = requests.post(f"{self.server_url}/api/heartbeat", json=payload, timeout=2)
            
            if response.status_code == 200:
                data = response.json()
                command = data.get("command", "start")
                
                # Check status change
                # Check status change
                if command == "stop":
                    if self.plcs:
                        print(f"[{self.node_id}] Received STOP command. Stopping PLCs and entering Standby Mode.")
                        self._stop_plcs()
                    # Else: Already in Standby Mode
                    
                elif command == "start":
                    if not self.plcs and self.config.get("plcs"):
                        print(f"[{self.node_id}] Received START command. Starting PLCs...")
                        self._start_plcs()
                    
        except Exception:
            # Server unreachable or error
            if self.plcs:
                 print(f"[{self.node_id}] Heartbeat failed (Server Unreachable). Safety Stop.")
                 self._stop_plcs()

    def _upload_logs(self):
        # Fetch unsent logs (assuming get_logs returns recent ones, we might duplicate-upload here without ack mechanism)
        # For prototype: Just upload recent 10 logs. In prod, we need an 'uploaded' flag in DB.
        logs = self.db.get_logs(limit=10)
        if logs:
            # logs is a list of tuples (id, timestamp, ...). Wait, get_logs returns logs from DB.
            # Convert tuple to dict if needed? db.get_logs returns cursor.fetchall().
            # Let's check db.get_logs implementation. It returns rows.
            # Row[2] is request_data which might be huge.
            
            # Need to convert logs to dict list
            log_list = []
            log_ids = []
            for row in logs:
                # Row structure: id(0), timestamp(1), attacker_ip(2), protocol(3), request(4), response(5), meta(6), uploaded(7)
                log_id = row[0]
                log_ids.append(log_id)
                
                log_dict = {
                    "timestamp": row[1],
                    "attacker_ip": row[2],
                    "protocol": row[3],
                    "request_data": row[4],
                    "response_data": row[5],
                    "metadata": row[6]
                }
                log_list.append(log_dict)

            payload = {
                "node_id": self.node_id,
                "logs": log_list
            }
            
            try:
                # print(f"Uploading {len(logs)} logs to {self.server_url}/api/logs")
                response = requests.post(f"{self.server_url}/api/logs", json=payload, timeout=2)
                if response.status_code == 200:
                    self.db.mark_uploaded(log_ids)
            except Exception:
                pass

    def _fetch_config(self):
        try:
            # print(f"Checking for config updates from {self.server_url}/api/config/{self.node_id}")
            response = requests.get(f"{self.server_url}/api/config/{self.node_id}", timeout=2)
            if response.status_code == 200:
                new_config = response.json()
                
                # Compare critical sections (PLCs)
                # Simple check: If serializing matches
                import json
                if json.dumps(new_config.get("plcs")) != json.dumps(self.config.get("plcs")):
                    print("Config change detected! Reloading PLCs...")
                    self.config = new_config
                    self._stop_plcs() # Stop existing plcs
                    
                    # Restart if we are in active state? 
                    # If we are "stopped" by server command, we shouldn't restart yet.
                    # But config update usually implies intention to run?
                    # Let the heartbeat loop handle the restart if command is "start".
                    # We just load the new config.
                    
                    # However, if we don't start here, and command IS "start", heartbeat will see 
                    # "start" and "no plcs" and start them.
                    # So just stopping PLCs here is sufficient.
                     
        except Exception as e:
            # print(f"Config fetch failed: {e}")
            pass
        except Exception as e:
            # print(f"Config fetch failed: {e}")
            pass
