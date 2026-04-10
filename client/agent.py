import json
import os
import threading
import time
from dotenv import load_dotenv

import requests

# Load .env from client directory
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from config_loader import ConfigLoader
from db.database import LogDB
from docker_manager import DockerDeploymentManager
from log_collector import ContainerLogCollector
from proxy.proxy_manager import ProxyManager


def _get_local_ip():
    """Auto-detect the outbound IP address of this machine.
    Uses a UDP socket trick (no actual data sent) to determine the
    interface IP that would route to the internet.
    """
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


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

        # Initialize Proxy Manager for protocol-aware traffic capture
        self.proxy_manager = ProxyManager(
            log_root=os.path.join(self.deployment_manager.node_runtime_dir, "proxy_logs"),
            node_id=self.node_id,
        )

        self.api_key = os.environ.get("API_KEY", "")

        self.start_attempt_count = 0
        self.max_start_attempts = 3
        self.last_start_attempt_time = 0
        self.start_cooldown = 10
        self._stopped = False
        self._last_sent_config_fingerprint = None
        
        # Heartbeat failure tracking - don't stop services on single failure
        self._heartbeat_consecutive_failures = 0
        self._max_heartbeat_failures = 3  # Stop only after this many consecutive failures

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
                self._collect_proxy_logs()  # NEW: Collect proxy logs
                self._upload_logs()
            except Exception as exc:
                print(f"Sync error: {exc}")
            time.sleep(5)

    def _auth_headers(self):
        """Return headers with API key for server requests."""
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _stop_all_services(self):
        # Stop proxies first
        self.proxy_manager.stop_all()
        # Then stop Docker containers
        self.deployment_manager.stop_all()

    def _has_running_services(self):
        return self.deployment_manager.has_active_deployments()

    def _deployment_status(self):
        status = self.deployment_manager.get_status()
        # Add proxy status to deployment status
        proxy_status = self.proxy_manager.get_status()
        for deployment_id, proxy_info in proxy_status.items():
            if deployment_id in status:
                status[deployment_id]["proxy"] = proxy_info
        return status

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
        
        # Apply proxies first to determine backend ports
        self._apply_proxies(docker_deployments)
        
        # Inject backend ports from proxy manager into deployment configs
        # This ensures Docker uses the same port that the proxy expects
        port_mapping = self.proxy_manager.get_backend_port_mapping()
        for deployment in docker_deployments:
            if deployment["id"] in port_mapping:
                deployment.setdefault("proxy", {})
                deployment["proxy"]["backend_port"] = port_mapping[deployment["id"]]
        
        # Then apply Docker deployments
        docker_success, docker_message = self.deployment_manager.apply_deployments(docker_deployments)
        if docker_deployments and not docker_success:
            print(f"[{self.node_id}] Docker deployment error: {docker_message}")

        # Wait for containers to be ready before starting proxies
        self._wait_for_backends_ready()
        
        # Start all proxies after containers are up
        self.proxy_manager.start_all()
        
        return docker_success or not docker_deployments
    
    def _wait_for_backends_ready(self, timeout: int = 30):
        """Wait for backend containers to accept connections"""
        import socket as sock
        
        for deployment_id, instance in self.proxy_manager.get_all_proxies().items():
            backend_host = instance.proxy.config.backend_host
            backend_port = instance.backend_port
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                try:
                    test_sock = sock.create_connection((backend_host, backend_port), timeout=1)
                    test_sock.close()
                    print(f"[{self.node_id}] Backend ready: {deployment_id} ({backend_host}:{backend_port})")
                    break
                except (ConnectionRefusedError, sock.timeout, OSError):
                    time.sleep(0.5)
            else:
                print(f"[{self.node_id}] WARNING: Backend not ready after {timeout}s: {deployment_id} ({backend_host}:{backend_port})")

    def _apply_proxies(self, deployments):
        """Configure and add proxies for deployments that have proxy config"""
        for deployment in deployments:
            if not deployment.get("enabled", True):
                continue
            
            proxy_config = deployment.get("proxy", {})
            if not proxy_config.get("enabled", False):
                continue
            
            deployment_id = deployment["id"]
            protocol = proxy_config.get("protocol") or deployment.get("template") or "tcp"
            listen_port = proxy_config.get("listen_port")
            backend_port = proxy_config.get("backend_port")
            
            if not listen_port:
                print(f"[{self.node_id}] Proxy for {deployment_id} skipped: no listen_port")
                continue
            
            try:
                self.proxy_manager.add_proxy(
                    deployment_id=deployment_id,
                    protocol=protocol,
                    listen_port=listen_port,
                    backend_port=backend_port,
                    extra_config=proxy_config.get("extra_config"),
                )
                print(f"[{self.node_id}] Proxy configured for {deployment_id}: {protocol} :{listen_port} -> :{backend_port}")
            except Exception as e:
                print(f"[{self.node_id}] Failed to configure proxy for {deployment_id}: {e}")

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
                "ip": _get_local_ip(),
                "name": f"Agent {self.node_id}",
                "config": self.config if include_config else None,
                "deployment_status": self._deployment_status(),
            }
            url = f"{self.server_url}/api/heartbeat"
            response = requests.post(url, json=payload, headers=self._auth_headers(), timeout=10)
            if response.status_code != 200:
                # Treat non-200 as a failure
                self._heartbeat_consecutive_failures += 1
                print(f"[{self.node_id}] Heartbeat to {url} returned status {response.status_code}: {response.text[:200]} ({self._heartbeat_consecutive_failures}/{self._max_heartbeat_failures})")
                return
            
            # Reset failure counter on successful heartbeat
            self._heartbeat_consecutive_failures = 0

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
                self.proxy_manager.node_id = new_node_id  # Update proxy manager node_id
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
            self._heartbeat_consecutive_failures += 1
            print(f"[{self.node_id}] Heartbeat error ({self._heartbeat_consecutive_failures}/{self._max_heartbeat_failures}): {exc}")
            
            # Only stop services after multiple consecutive failures
            if self._heartbeat_consecutive_failures >= self._max_heartbeat_failures:
                if self._has_running_services():
                    print(f"[{self.node_id}] Multiple heartbeat failures. Safety stop.")
                    self._stop_all_services()
                    self._heartbeat_consecutive_failures = 0  # Reset after stopping

    def _collect_container_logs(self):
        """Collect logs from container log files (legacy method)"""
        self.log_collector.collect(self.config.get("deployments", []))

    def _collect_proxy_logs(self):
        """
        Collect logs from proxy unified logger.
        Proxy logs are already in unified format, so we just need to
        read them and insert into the local database for upload.
        """
        for deployment_id, instance in self.proxy_manager.get_all_proxies().items():
            log_path = instance.logger.log_path
            if not os.path.exists(log_path):
                continue

            # Use log_collector's offset tracking mechanism
            state_key = f"proxy:{log_path}"
            offset = self.log_collector.offsets.get(state_key, 0)

            # If file was truncated/recreated (e.g. after restart), reset offset
            file_size = os.path.getsize(log_path)
            if offset > file_size:
                print(f"[{self.node_id}] Proxy log truncated, resetting offset for {deployment_id}")
                offset = 0
                self.log_collector.offsets[state_key] = 0

            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    f.seek(offset)
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            entry = json.loads(line)
                            protocol_name = entry.get("protocol", {}).get("name", "unknown")
                            req_parsed = entry.get("request", {}).get("parsed", {})
                            resp_parsed = entry.get("response", {}).get("parsed", {})

                            # Build flat metadata for frontend compatibility
                            metadata = {
                                "deployment.id": entry.get("deployment_id", deployment_id),
                                "deployment.name": deployment_id,
                                "event_id": entry.get("event_id", ""),
                                "session.id": entry.get("session", {}).get("id", ""),
                                "source": "proxy",
                            }

                            # Build a human-readable log.message and add
                            # protocol-specific flat keys the frontend expects
                            src_ip = entry.get("network", {}).get("src_ip", "unknown")
                            log_message = self._build_proxy_log_message(
                                protocol_name, req_parsed, resp_parsed, src_ip
                            )
                            metadata["log.message"] = log_message

                            # Flatten protocol-specific parsed fields for frontend
                            for key, value in req_parsed.items():
                                metadata[key] = value
                            for key, value in resp_parsed.items():
                                if key not in metadata:
                                    metadata[key] = value

                            # Also store full unified entry for detailed analysis
                            metadata["_unified_entry"] = entry

                            self.db.log_interaction(
                                attacker_ip=src_ip,
                                protocol=protocol_name,
                                request_data=entry.get("request", {}).get("raw_hex", ""),
                                response_data=entry.get("response", {}).get("raw_hex", ""),
                                metadata=metadata,
                                timestamp=entry.get("timestamp"),
                            )
                        except json.JSONDecodeError:
                            continue

                    self.log_collector.offsets[state_key] = f.tell()
                    self.log_collector._save_state()
            except Exception as e:
                print(f"[{self.node_id}] Error collecting proxy logs for {deployment_id}: {e}")

    @staticmethod
    def _build_proxy_log_message(protocol, req_parsed, resp_parsed, src_ip):
        """Build a human-readable log message from parsed proxy data"""
        if protocol == "http":
            method = req_parsed.get("http.method", "")
            uri = req_parsed.get("http.uri", "")
            status = resp_parsed.get("http.status_code", "")
            if method:
                msg = f"{method} {uri}"
                if status:
                    msg += f" → {status}"
                return msg
            return f"HTTP request from {src_ip}"

        if protocol == "mqtt":
            pkt_type = req_parsed.get("mqtt.packet_type_name", "")
            topic = req_parsed.get("mqtt.topic", "")
            client_id = req_parsed.get("mqtt.client_id", "")
            if pkt_type == "CONNECT":
                return f"MQTT CONNECT client_id={client_id}" if client_id else "MQTT CONNECT"
            if pkt_type == "PUBLISH" and topic:
                return f"MQTT PUBLISH topic={topic}"
            if pkt_type == "SUBSCRIBE":
                topics = req_parsed.get("mqtt.topics", [])
                topic_names = [t.get("topic", "") for t in topics] if isinstance(topics, list) else []
                return f"MQTT SUBSCRIBE topics={topic_names}" if topic_names else "MQTT SUBSCRIBE"
            return f"MQTT {pkt_type}" if pkt_type else f"MQTT event from {src_ip}"

        if protocol == "modbus":
            func_name = req_parsed.get("modbus.function_name", "")
            unit_id = req_parsed.get("modbus.unit_id", "")
            is_exception = resp_parsed.get("modbus.is_exception", False)
            if func_name:
                msg = f"{func_name}"
                if unit_id:
                    msg += f" (unit {unit_id})"
                if is_exception:
                    exc_name = resp_parsed.get("modbus.exception_name", "Exception")
                    msg += f" → {exc_name}"
                return msg
            return f"Modbus request from {src_ip}"

        return f"{protocol} interaction from {src_ip}"

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
            response = requests.post(f"{self.server_url}/api/logs", json=payload, headers=self._auth_headers(), timeout=3)
            if response.status_code == 200:
                self.db.mark_uploaded(log_ids)
        except Exception:
            pass

    def _fetch_config(self):
        try:
            response = requests.get(f"{self.server_url}/api/config/{self.node_id}", headers=self._auth_headers(), timeout=3)
            if response.status_code != 200:
                return

            raw_config = response.json()
            success, new_config, error = self.config_loader.parse_server_config(raw_config)
            if not success:
                print(f"[{self.node_id}] Config validation failed: {error}")
                return

            if not new_config:
                return

            new_config["deployments"] = self.deployment_manager.merge_local_deployments(
                new_config.get("deployments", []),
                current_deployments=self.config.get("deployments", [])
            )

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
