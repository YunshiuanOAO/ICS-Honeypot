import time
import threading
import json
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
        
        # 防止無限重啟的機制
        self.start_attempt_count = 0
        self.max_start_attempts = 3
        self.last_start_attempt_time = 0
        self.start_cooldown = 10  # 秒

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
        """
        啟動 PLCs
        
        Returns:
            bool: 是否至少有一個 PLC 成功啟動
        """
        print(f"[{self.node_id}] Starting PLCs...")
        plc_configs = self.config.get("plcs", [])
        
        if not plc_configs:
            print(f"[{self.node_id}] No PLC configurations found.")
            return False
        
        success_count = 0
        total_enabled = 0
        
        for i, plc_conf in enumerate(plc_configs):
            if not plc_conf.get("enabled"):
                print(f"[{self.node_id}] PLC #{i+1} is disabled, skipping.")
                continue
            
            total_enabled += 1
            plc_type = plc_conf.get("type")
            port = plc_conf.get("port")
            model = plc_conf.get("model", "Unknown")
            
            # 獲取模擬配置（可選）
            simulation_config = plc_conf.get("simulation")
            
            try:
                print(f"[{self.node_id}] Starting {plc_type} PLC on port {port} (Model: {model})...")
                
                if plc_type == "modbus":
                    plc = ModbusPLC(
                        port=port, 
                        db=self.db, 
                        model=model,
                        vendor=plc_conf.get("vendor", "Unknown Vendor"),
                        revision=plc_conf.get("revision", "V1.0"),
                        devices=plc_conf.get("devices"),
                        simulation_config=simulation_config
                    )
                    plc.start()
                    self.plcs.append(plc)
                    success_count += 1
                    print(f"[{self.node_id}] ✓ Modbus PLC started on port {port}")
                    
                elif plc_type == "s7comm":
                    plc = S7PLC(
                        port=port, 
                        db=self.db, 
                        model=model,
                        simulation_config=simulation_config
                    )
                    plc.start()
                    self.plcs.append(plc)
                    success_count += 1
                    print(f"[{self.node_id}] ✓ S7 PLC started on port {port}")
                    
                else:
                    print(f"[{self.node_id}] ✗ Unknown PLC type: {plc_type}")
                    
            except OSError as e:
                if "Address already in use" in str(e) or "Only one usage" in str(e):
                    print(f"[{self.node_id}] ✗ Port {port} is already in use. Cannot start {plc_type} PLC.")
                else:
                    print(f"[{self.node_id}] ✗ OS Error starting {plc_type} PLC on port {port}: {e}")
            except Exception as e:
                print(f"[{self.node_id}] ✗ Failed to start {plc_type} PLC on port {port}: {e}")
                import traceback
                traceback.print_exc()
        
        if success_count == 0:
            print(f"[{self.node_id}] ERROR: No PLCs started successfully! (0/{total_enabled})")
            return False
        elif success_count < total_enabled:
            print(f"[{self.node_id}] WARNING: Only {success_count}/{total_enabled} PLCs started successfully.")
            return True  # 部分成功也算成功
        else:
            print(f"[{self.node_id}] All {success_count} PLCs started successfully!")
            return True

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

                # 1. Check for Identity Update (Adoption) - PRIORITY
                new_node_id = data.get("new_node_id")
                if new_node_id and new_node_id != self.node_id:
                    print(f"[{self.node_id}] Agent adopted! Switching Identity: {self.node_id} -> {new_node_id}")
                    self.node_id = new_node_id
                    self.config["node_id"] = new_node_id
                    # Persist the new identity immediately
                    self.config_loader.save_config(self.config)
                    
                    # Force a restart/reload
                    self._stop_plcs()
                    self.start_attempt_count = 0 
                    return 
                
                # 2. Check status change
                if command == "stop":
                    if self.plcs:
                        print(f"[{self.node_id}] Received STOP command. Stopping PLCs and entering Standby Mode.")
                        self._stop_plcs()
                        # 重置啟動計數器
                        self.start_attempt_count = 0
                    # Else: Already in Standby Mode
                    
                elif command == "start":
                    if not self.plcs and self.config.get("plcs"):
                        # 檢查冷卻時間
                        current_time = time.time()
                        if current_time - self.last_start_attempt_time < self.start_cooldown:
                            # 仍在冷卻期，不嘗試啟動
                            return
                        
                        # 檢查重試次數
                        if self.start_attempt_count >= self.max_start_attempts:
                            if self.start_attempt_count == self.max_start_attempts:
                                print(f"[{self.node_id}] ERROR: Failed to start PLCs after {self.max_start_attempts} attempts. "
                                      f"Please check port availability and configuration.")
                                self.start_attempt_count += 1  # 只打印一次錯誤
                            return
                        
                        print(f"[{self.node_id}] Received START command. Starting PLCs... (Attempt {self.start_attempt_count + 1}/{self.max_start_attempts})")
                        self.last_start_attempt_time = current_time
                        self.start_attempt_count += 1
                        
                        success = self._start_plcs()
                        if success:
                            # 啟動成功，重置計數器
                            self.start_attempt_count = 0
                            # Save config if successful start (to ensure setup persists)
                            self.config_loader.save_config(self.config)
                            print(f"[{self.node_id}] PLCs started successfully!")
                        else:
                            print(f"[{self.node_id}] Failed to start PLCs. Will retry after {self.start_cooldown}s cooldown.")
                    
        except Exception as e:
            # Server unreachable or error
            print(f"[{self.node_id}] Heartbeat error: {e}")
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
        """
        從 server 獲取配置更新
        
        會自動：
        1. 清理無效欄位
        2. 驗證配置結構
        3. 標準化配置格式
        """
        try:
            # print(f"Checking for config updates from {self.server_url}/api/config/{self.node_id}")
            response = requests.get(f"{self.server_url}/api/config/{self.node_id}", timeout=2)
            if response.status_code == 200:
                raw_config = response.json()
                
                # 使用 ConfigLoader 解析和清理配置
                success, new_config, error = self.config_loader.parse_server_config(raw_config)
                
                if not success:
                    print(f"[{self.node_id}] Config validation failed: {error}")
                    return
                
                # Compare critical sections (PLCs)
                # Simple check: If serializing matches
                if json.dumps(new_config.get("plcs"), sort_keys=True) != json.dumps(self.config.get("plcs"), sort_keys=True):
                    print(f"[{self.node_id}] Config change detected! Reloading PLCs...")
                    self.config = new_config
                    self._stop_plcs() # Stop existing plcs
                    
                    # 重置啟動計數器，允許新配置重新嘗試
                    self.start_attempt_count = 0
                    self.last_start_attempt_time = 0
                    
                    # Restart if we are in active state? 
                    # If we are "stopped" by server command, we shouldn't restart yet.
                    # But config update usually implies intention to run?
                    # Let the heartbeat loop handle the restart if command is "start".
                    # We just load the new config.
                    
                    # However, if we don't start here, and command IS "start", heartbeat will see 
                    # "start" and "no plcs" and start them.
                    # So just stopping PLCs here is sufficient.
                     
        except requests.exceptions.RequestException as e:
            # Network error, silently ignore
            pass
        except json.JSONDecodeError as e:
            print(f"[{self.node_id}] Invalid JSON from server: {e}")
        except Exception as e:
            print(f"[{self.node_id}] Config fetch error: {e}")
