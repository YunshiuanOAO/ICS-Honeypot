import json
import os
import threading
import time

import requests

from config_loader import ConfigLoader
from db.database import LogDB
from docker_manager import DockerDeploymentManager
from log_collector import ContainerLogCollector


class NodeAgent:
    def __init__(self):
        self.client_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_loader = ConfigLoader()
        self.config = self.config_loader.load_config() or {}
        self.db = LogDB(os.path.join(self.client_dir, "client_logs.db"))
        self.deployment_manager = DockerDeploymentManager(self.client_dir, self.config.get("node_id", "node_unknown"))
        self.log_collector = ContainerLogCollector(self.deployment_manager.node_runtime_dir, self.db)
        self.running = False
        self.server_url = self.config.get("server_url", "http://localhost:8000")
        self.node_id = self.config.get("node_id", "node_unknown")

        self.start_attempt_count = 0
        self.max_start_attempts = 3
        self.last_start_attempt_time = 0
        self.start_cooldown = 10
        self._stopped = False
        self._last_sent_config_fingerprint = None

    def start(self):
        self.running = True
        print(f"Node Agent {self.node_id} starting...")

        while not self.config.get("deployments"):
            print(f"[{self.node_id}] No deployment configuration found. Waiting for config from Server...")
            self._send_heartbeat()
            self._fetch_config()
            if self.config.get("deployments"):
                print(f"[{self.node_id}] Configuration received!")
                break
            time.sleep(5)

        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        self.running = False
        print("Stopping Node Agent...")
        self._stop_all_services()
        print("Node Agent stopped.")

    def _sync_loop(self):
        while self.running:
            try:
                self._send_heartbeat()
                self._fetch_config()
                self._collect_container_logs()
                self._upload_logs()
            except Exception as exc:
                print(f"Sync error: {exc}")
            time.sleep(5)

    def _stop_all_services(self):
        self.deployment_manager.stop_all()

    def _has_running_services(self):
        return self.deployment_manager.has_active_deployments()

    def _deployment_status(self):
        return self.deployment_manager.get_status()

    def _apply_deployments(self):
        deployments = self.config.get("deployments", [])
        if not deployments:
            print(f"[{self.node_id}] No deployments configured.")
            return False

        docker_deployments = [
            deployment
            for deployment in deployments
            if deployment.get("enabled", True)
        ]
        docker_success, docker_message = self.deployment_manager.apply_deployments(docker_deployments)
        if docker_deployments and not docker_success:
            print(f"[{self.node_id}] Docker deployment error: {docker_message}")

        return docker_success or not docker_deployments

    def _is_fully_deployed(self):
        deployments = self.config.get("deployments", [])
        status = self._deployment_status()
        for d in deployments:
            if d.get("enabled", True):
                s = status.get(d["id"])
                if not s or s.get("state") != "running":
                    return False
        return True

    def _send_heartbeat(self):
        try:
            config_fingerprint = json.dumps(self.config, sort_keys=True, ensure_ascii=False)
            include_config = config_fingerprint != self._last_sent_config_fingerprint
            payload = {
                "node_id": self.node_id,
                "ip": "127.0.0.1",
                "name": f"Agent {self.node_id}",
                "config": self.config if include_config else None,
                "deployment_status": self._deployment_status(),
            }
            response = requests.post(f"{self.server_url}/api/heartbeat", json=payload, timeout=10)
            if response.status_code != 200:
                return

            if include_config:
                self._last_sent_config_fingerprint = config_fingerprint

            data = response.json()
            command = data.get("command", "start")
            new_node_id = data.get("new_node_id")

            if new_node_id and new_node_id != self.node_id:
                print(f"[{self.node_id}] Agent adopted! Switching identity to {new_node_id}")
                self.node_id = new_node_id
                self.config["node_id"] = new_node_id
                self.deployment_manager.set_node_id(new_node_id)
                self.log_collector = ContainerLogCollector(self.deployment_manager.node_runtime_dir, self.db)
                self.config_loader.save_config(self.config)
                self._stop_all_services()
                self.start_attempt_count = 0
                self._last_sent_config_fingerprint = None
                return

            if command == "stop":
                if self._has_running_services():
                    print(f"[{self.node_id}] Received STOP command. Entering standby mode.")
                    self._stop_all_services()
                    self.start_attempt_count = 0
                return

            if command == "start" and self.config.get("deployments") and not self._is_fully_deployed():
                current_time = time.time()
                if current_time - self.last_start_attempt_time < self.start_cooldown:
                    return
                if self.start_attempt_count >= self.max_start_attempts:
                    if self.start_attempt_count == self.max_start_attempts:
                        print(f"[{self.node_id}] ERROR: failed to start deployments after {self.max_start_attempts} attempts.")
                        self.start_attempt_count += 1
                    return

                if not getattr(self, "_is_applying", False):
                    print(f"[{self.node_id}] Received START command. Applying deployments in background... ({self.start_attempt_count + 1}/{self.max_start_attempts})")
                    self.last_start_attempt_time = current_time
                    self.start_attempt_count += 1
                    self._is_applying = True
                    
                    def _do_apply():
                        try:
                            success = self._apply_deployments()
                            if success:
                                self.start_attempt_count = 0
                                self.config_loader.save_config(self.config)
                                print(f"[{self.node_id}] Deployments started successfully.")
                            else:
                                print(f"[{self.node_id}] Failed to start deployments. Retrying after cooldown.")
                        finally:
                            self._is_applying = False
                            
                    threading.Thread(target=_do_apply, daemon=True).start()
        except Exception as exc:
            print(f"[{self.node_id}] Heartbeat error: {exc}")
            if self._has_running_services():
                print(f"[{self.node_id}] Heartbeat failed. Safety stop.")
                self._stop_all_services()

    def _collect_container_logs(self):
        self.log_collector.collect(self.config.get("deployments", []))

    def _upload_logs(self):
        logs = self.db.get_logs(limit=50)
        if not logs:
            return

        log_list = []
        log_ids = []
        for row in logs:
            log_ids.append(row[0])
            log_list.append({
                "timestamp": row[1],
                "attacker_ip": row[2],
                "protocol": row[3],
                "request_data": row[4],
                "response_data": row[5],
                "metadata": row[6],
            })

        payload = {"node_id": self.node_id, "logs": log_list}
        try:
            response = requests.post(f"{self.server_url}/api/logs", json=payload, timeout=3)
            if response.status_code == 200:
                self.db.mark_uploaded(log_ids)
        except Exception:
            pass

    def _fetch_config(self):
        try:
            response = requests.get(f"{self.server_url}/api/config/{self.node_id}", timeout=3)
            if response.status_code != 200:
                return

            raw_config = response.json()
            success, new_config, error = self.config_loader.parse_server_config(raw_config)
            if not success:
                print(f"[{self.node_id}] Config validation failed: {error}")
                return

            if not new_config:
                return

            new_config["deployments"] = self.deployment_manager.merge_local_deployments(new_config.get("deployments", []))

            current_deployments = json.dumps(self.config.get("deployments", []), sort_keys=True)
            incoming_deployments = json.dumps(new_config.get("deployments", []), sort_keys=True)

            if current_deployments != incoming_deployments or new_config.get("server_url") != self.server_url:
                print(f"[{self.node_id}] Config change detected. Reloading deployments...")
                self.config = new_config
                self.server_url = new_config.get("server_url", self.server_url)
                self._stop_all_services()
                self.start_attempt_count = 0
                self.last_start_attempt_time = 0
                self._last_sent_config_fingerprint = None
                self.config_loader.save_config(self.config)
        except requests.exceptions.RequestException:
            pass
        except json.JSONDecodeError as exc:
            print(f"[{self.node_id}] Invalid JSON from server: {exc}")
        except Exception as exc:
            print(f"[{self.node_id}] Config fetch error: {exc}")
