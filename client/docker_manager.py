import json
import os
import re
import shutil
import subprocess
from copy import deepcopy


class DockerDeploymentManager:
    def __init__(self, client_dir, node_id):
        self.client_dir = client_dir
        self.runtime_root = os.path.join(client_dir, "runtime")
        self.status = {}
        self._pending_rematerialize = set()
        self.set_node_id(node_id)
        os.makedirs(self.runtime_root, exist_ok=True)

    def set_node_id(self, node_id):
        self.node_id = node_id
        self.node_slug = self._slug(node_id, "node")
        self.project_prefix = f"honeypot-{self.node_slug}"
        self.node_runtime_dir = os.path.join(self.runtime_root, self.node_slug)
        os.makedirs(self.node_runtime_dir, exist_ok=True)

    def _slug(self, text, fallback="service"):
        cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(text or ""))
        cleaned = "-".join(part for part in cleaned.split("-") if part)
        return cleaned or fallback

    def _run(self, args, cwd=None):
        return subprocess.run(args, capture_output=True, text=True, cwd=cwd)

    def _docker_available(self):
        return self._run(["docker", "version", "--format", "{{.Server.Version}}"])

    def _project_name(self, deployment):
        return f"{self.project_prefix}-{self._slug(deployment['id'])}"

    def _deployment_root(self, deployment):
        return os.path.join(self.node_runtime_dir, deployment["id"])

    def _package_root(self, deployment):
        return os.path.join(self._deployment_root(deployment), "package")

    def _data_root(self, deployment):
        return os.path.join(self._deployment_root(deployment), "data")

    def _logs_root(self, deployment):
        return os.path.join(self._deployment_root(deployment), "logs")

    def _source_root(self, deployment):
        return os.path.join(self._package_root(deployment), deployment.get("source_dir") or deployment["id"])

    def _compose_path(self, deployment):
        return os.path.join(self._source_root(deployment), "docker-compose.yml")

    def _compose_override_path(self, deployment):
        return os.path.join(self._source_root(deployment), "docker-compose.override.generated.yml")

    def _dockerfile_path(self, deployment):
        return os.path.join(self._source_root(deployment), "Dockerfile")

    def _container_name(self, deployment):
        return f"{self._project_name(deployment)}-honeypot"

    def _image_name(self, deployment):
        return f"{self._project_name(deployment)}:latest"

    def _discover_source_dir(self, deployment_id):
        package_root = os.path.join(self.node_runtime_dir, deployment_id, "package")
        if not os.path.isdir(package_root):
            return None
        candidates = [name for name in os.listdir(package_root) if os.path.isdir(os.path.join(package_root, name))]
        return candidates[0] if candidates else None

    def _read_local_files(self, source_root):
        files = []
        if not os.path.isdir(source_root):
            return files
        for root, _, filenames in os.walk(source_root):
            for filename in sorted(filenames):
                if filename in {".env", ".env.runtime", "docker-compose.override.generated.yml"}:
                    continue
                absolute_path = os.path.join(root, filename)
                relative_path = os.path.relpath(absolute_path, source_root).replace("\\", "/")
                try:
                    content = open(absolute_path, "r", encoding="utf-8").read()
                except UnicodeDecodeError:
                    content = open(absolute_path, "r", encoding="utf-8", errors="replace").read()
                files.append({"path": relative_path, "content": content})
        return files

    def _infer_exposed_ports(self, deployment):
        dockerfile_path = self._dockerfile_path(deployment)
        if not os.path.exists(dockerfile_path):
            return []

        try:
            content = open(dockerfile_path, "r", encoding="utf-8").read()
        except Exception:
            return []

        ports = []
        for match in re.finditer(r"^\s*EXPOSE\s+(.+)$", content, re.MULTILINE | re.IGNORECASE):
            for token in match.group(1).split():
                port = token.split("/")[0].strip()
                if port.isdigit() and port not in ports:
                    ports.append(port)
        return ports

    def _deployment_mode(self, deployment):
        if os.path.exists(self._compose_path(deployment)):
            return "compose"
        if os.path.exists(self._dockerfile_path(deployment)):
            return "dockerfile"
        return "missing"

    def _remove_container_if_exists(self, container_name):
        inspect = self._run(["docker", "container", "inspect", container_name])
        if inspect.returncode == 0:
            self._run(["docker", "rm", "-f", container_name])

    def _run_dockerfile_deployment(self, deployment):
        source_root = self._source_root(deployment)
        image_name = self._image_name(deployment)
        container_name = self._container_name(deployment)

        build_result = self._run([
            "docker", "build", "-t", image_name, ".",
        ], cwd=source_root)
        if build_result.returncode != 0:
            return build_result

        self._remove_container_if_exists(container_name)

        command = [
            "docker", "run", "-d",
            "--name", container_name,
            "--restart", "unless-stopped",
            "-e", "HONEYPOT_LOGS_DIR=/honeypot/logs",
            "-e", "HONEYPOT_DATA_DIR=/honeypot/data",
            "-v", f"{self._logs_root(deployment)}:/honeypot/logs",
            "-v", f"{self._data_root(deployment)}:/honeypot/data",
        ]

        # Check if proxy is configured - if so, use backend_port for host mapping
        proxy_config = deployment.get("proxy", {})
        backend_port = proxy_config.get("backend_port")
        
        # Reserved ports that should not be auto-mapped (e.g., server port)
        reserved_ports = {8000}  # FastAPI server port
        
        for port in self._infer_exposed_ports(deployment):
            if backend_port:
                # Use proxy's backend_port for host mapping
                command.extend(["-p", f"{backend_port}:{port}"])
            elif int(port) in reserved_ports:
                # Skip reserved ports - don't auto-map them
                print(f"[DockerManager] Skipping reserved port {port} for {deployment.get('id')}")
                continue
            else:
                command.extend(["-p", f"{port}:{port}"])

        command.append(image_name)
        return self._run(command, cwd=source_root)

    def _compose_files_args(self, deployment):
        args = ["-f", self._compose_path(deployment)]
        override_path = self._compose_override_path(deployment)
        if os.path.exists(override_path):
            args.extend(["-f", override_path])
        return args

    def _service_names(self, deployment):
        compose_path = self._compose_path(deployment)
        source_root = self._source_root(deployment)
        if not os.path.exists(compose_path):
            return []

        result = self._run([
            "docker", "compose", "-f", compose_path,
            "config", "--services",
        ], cwd=source_root)
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _declared_container_names(self, deployment):
        compose_path = self._compose_path(deployment)
        if not os.path.exists(compose_path):
            return []

        try:
            content = open(compose_path, "r", encoding="utf-8").read()
        except Exception:
            return []

        names = []
        for match in re.finditer(r"^\s*container_name\s*:\s*(.+?)\s*$", content, re.MULTILINE):
            name = match.group(1).strip().strip('"\'')
            if name:
                names.append(name)
        return names

    def _cleanup_stale_declared_containers(self, deployment):
        expected = {
            f"{self._project_name(deployment)}-{self._slug(service_name)}"
            for service_name in self._service_names(deployment)
        }
        for container_name in self._declared_container_names(deployment):
            if container_name in expected:
                continue
            inspect = self._run(["docker", "container", "inspect", container_name])
            if inspect.returncode == 0:
                self._run(["docker", "rm", "-f", container_name])

    def _write_compose_override(self, deployment):
        service_names = self._service_names(deployment)
        override_path = self._compose_override_path(deployment)
        if not service_names:
            if os.path.exists(override_path):
                os.remove(override_path)
            return

        lines = ["services:"]
        for service_name in service_names:
            unique_name = f"{self._project_name(deployment)}-{self._slug(service_name)}"
            lines.append(f"  {service_name}:")
            lines.append(f"    container_name: {json.dumps(unique_name)}")

        with open(override_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def merge_local_deployments(self, deployments, current_deployments=None):
        current_by_id = {}
        if current_deployments:
            for d in current_deployments:
                if d.get("id"):
                    current_by_id[d["id"]] = d

        merged = []
        for deployment in deployments:
            deployment_copy = deepcopy(deployment)
            deployment_id = deployment_copy.get("id")
            discovered_source_dir = self._discover_source_dir(deployment_id)
            if discovered_source_dir:
                server_updated = deployment_copy.get("files_updated_at")
                current = current_by_id.get(deployment_id)
                local_updated = current.get("files_updated_at") if current else None

                if server_updated and server_updated != local_updated:
                    self._pending_rematerialize.add(deployment_id)
                else:
                    deployment_copy["source_dir"] = discovered_source_dir
                    source_root = os.path.join(self.node_runtime_dir, deployment_id, "package", discovered_source_dir)
                    deployment_copy["files"] = self._read_local_files(source_root)
                    deployment_copy["client_authoritative"] = True
            merged.append(deployment_copy)
        return merged

    def has_active_deployments(self):
        return any(item.get("state") == "running" for item in self.status.values())

    def get_status(self):
        return deepcopy(self.status)

    def stop_all(self):
        if not os.path.exists(self.node_runtime_dir):
            return True, "No runtime directory to stop"

        docker_check = self._docker_available()
        if docker_check.returncode != 0:
            return False, docker_check.stderr.strip() or "Docker is not available"

        known = {}
        for deployment_id, item in self.status.items():
            known[deployment_id] = {
                "source_dir": item.get("source_dir") or deployment_id,
                "project_name": item.get("project_name") or f"{self.project_prefix}-{self._slug(deployment_id)}",
            }

        for deployment_id in os.listdir(self.node_runtime_dir):
            deployment_root = os.path.join(self.node_runtime_dir, deployment_id)
            if not os.path.isdir(deployment_root) or deployment_id in known:
                continue
            discovered_source_dir = self._discover_source_dir(deployment_id)
            if not discovered_source_dir:
                continue
            known[deployment_id] = {
                "source_dir": discovered_source_dir,
                "project_name": f"{self.project_prefix}-{self._slug(deployment_id)}",
            }

        messages = []
        for deployment_id, item in known.items():
            deployment_root = os.path.join(self.node_runtime_dir, deployment_id)
            source_dir = item.get("source_dir") or deployment_id
            deployment_ref = {"id": deployment_id, "source_dir": source_dir}
            compose_path = self._compose_path(deployment_ref)
            mode = self._deployment_mode(deployment_ref)
            if mode == "missing":
                if deployment_id in self.status:
                    self.status[deployment_id]["state"] = "stopped"
                continue

            if mode == "compose":
                result = self._run([
                    "docker", "compose", *self._compose_files_args(deployment_ref),
                    "--project-name", item.get("project_name") or f"{self.project_prefix}-{self._slug(deployment_id)}",
                    "down", "--remove-orphans",
                ], cwd=os.path.dirname(compose_path))
            else:
                self._remove_container_if_exists(self._container_name(deployment_ref))
                class Result:
                    returncode = 0
                    stdout = "Stopped dockerfile container"
                    stderr = ""
                result = Result()
            if result.returncode == 0:
                if deployment_id in self.status:
                    self.status[deployment_id]["state"] = "stopped"
            else:
                if deployment_id in self.status:
                    self.status[deployment_id]["state"] = "error"
                    self.status[deployment_id]["message"] = result.stderr.strip() or result.stdout.strip()
            output = result.stderr.strip() or result.stdout.strip()
            if output:
                messages.append(f"{deployment_id}: {output}")

        return True, "\n".join(messages) if messages else "Stopped"

    def apply_deployments(self, deployments):
        deployments = [deployment for deployment in deployments if deployment.get("enabled", True)]
        if not deployments:
            return self.stop_all()

        docker_check = self._docker_available()
        if docker_check.returncode != 0:
            error = docker_check.stderr.strip() or "Docker is not available"
            self.status = {
                deployment["id"]: {
                    "state": "error",
                    "template": deployment.get("template") or deployment.get("type"),
                    "source_dir": deployment.get("source_dir"),
                    "message": error,
                }
                for deployment in deployments
            }
            return False, error

        desired_ids = {deployment["id"] for deployment in deployments}
        for deployment_id, item in list(self.status.items()):
            if deployment_id not in desired_ids:
                deployment_ref = {"id": deployment_id, "source_dir": item.get("source_dir") or deployment_id}
                compose_path = self._compose_path(deployment_ref)
                mode = self._deployment_mode(deployment_ref)
                if mode == "compose" and os.path.exists(compose_path):
                    self._run([
                        "docker", "compose", *self._compose_files_args(deployment_ref),
                        "--project-name", item.get("project_name") or f"{self.project_prefix}-{self._slug(deployment_id)}",
                        "down", "--remove-orphans",
                    ], cwd=os.path.dirname(compose_path))
                elif mode == "dockerfile":
                    self._remove_container_if_exists(self._container_name(deployment_ref))
                self.status.pop(deployment_id, None)

        messages = []
        success = True
        for deployment in deployments:
            deployment_root = self._deployment_root(deployment)
            source_root = self._source_root(deployment)
            self._materialize_package(deployment, deployment_root, source_root)

            compose_path = self._compose_path(deployment)
            mode = self._deployment_mode(deployment)
            if mode == "missing":
                missing_msg = f"{deployment['id']}: Neither docker-compose.yml nor Dockerfile found in {source_root}"
                self.status[deployment["id"]] = {
                    "state": "error",
                    "template": deployment.get("template") or deployment.get("type"),
                    "source_dir": deployment.get("source_dir"),
                    "project_name": self._project_name(deployment),
                    "message": missing_msg,
                }
                messages.append(missing_msg)
                success = False
                continue

            if mode == "compose":
                self._write_compose_override(deployment)
                self._cleanup_stale_declared_containers(deployment)
                result = self._run([
                    "docker", "compose", *self._compose_files_args(deployment),
                    "--project-name", self._project_name(deployment),
                    "up", "-d", "--build", "--remove-orphans",
                ], cwd=source_root)
            else:
                result = self._run_dockerfile_deployment(deployment)
            self._update_single_status(deployment, result)
            if result.returncode != 0:
                success = False
            output = result.stderr.strip() or result.stdout.strip()
            if output:
                messages.append(f"{deployment['id']}: {output}")

        return success, "\n".join(messages) if messages else "Applied"

    def _materialize_package(self, deployment, deployment_root, source_root):
        os.makedirs(deployment_root, exist_ok=True)
        os.makedirs(self._package_root(deployment), exist_ok=True)
        os.makedirs(self._data_root(deployment), exist_ok=True)
        os.makedirs(self._logs_root(deployment), exist_ok=True)

        force_write = deployment["id"] in self._pending_rematerialize
        source_exists = os.path.isdir(source_root) and any(os.scandir(source_root))

        if force_write and source_exists:
            package_root = self._package_root(deployment)
            if os.path.isdir(package_root):
                shutil.rmtree(package_root)
            os.makedirs(package_root, exist_ok=True)
            source_exists = False
            self._pending_rematerialize.discard(deployment["id"])

        if not source_exists:
            if os.path.exists(source_root):
                shutil.rmtree(source_root)
            os.makedirs(source_root, exist_ok=True)

            files = deployment.get("files") or []
            for item in files:
                relative_path = str(item.get("path") or "").replace("\\", "/").strip("/")
                if not relative_path:
                    continue
                safe_parts = [part for part in relative_path.split("/") if part not in ("", ".", "..")]
                file_path = os.path.join(source_root, *safe_parts)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "w", encoding="utf-8") as handle:
                    handle.write(item.get("content") or "")

        env_path = os.path.join(source_root, ".env")
        with open(env_path, "w", encoding="utf-8") as handle:
            handle.write(f"HONEYPOT_DATA_DIR={self._data_root(deployment)}\n")
            handle.write(f"HONEYPOT_LOGS_DIR={self._logs_root(deployment)}\n")
            
            # Add proxy backend port if configured
            proxy_config = deployment.get("proxy", {})
            backend_port = proxy_config.get("backend_port")
            if backend_port:
                handle.write(f"BACKEND_PORT={backend_port}\n")

    def _update_single_status(self, deployment, compose_result=None):
        deployment_id = deployment["id"]
        compose_path = self._compose_path(deployment)
        source_root = self._source_root(deployment)
        message = ""
        if compose_result is not None and compose_result.returncode != 0:
            message = compose_result.stderr.strip() or compose_result.stdout.strip()

        mode = self._deployment_mode(deployment)
        if mode == "dockerfile":
            inspect = self._run([
                "docker", "container", "inspect", self._container_name(deployment),
            ], cwd=source_root)
            ports = []
            if inspect.returncode != 0:
                state = "error" if message else "stopped"
            else:
                state = "running" if not message else "error"
                if inspect.stdout.strip():
                    try:
                        row = json.loads(inspect.stdout)[0]
                        state = row.get("State", {}).get("Status", state).lower()
                        port_map = row.get("NetworkSettings", {}).get("Ports", {}) or {}
                        for container_port, bindings in port_map.items():
                            if not bindings:
                                continue
                            for binding in bindings:
                                ports.append(f"{binding.get('HostIp')}:{binding.get('HostPort')}->{container_port}")
                    except Exception:
                        pass

            self.status[deployment_id] = {
                "state": state,
                "template": deployment.get("template") or deployment.get("type"),
                "source_dir": deployment.get("source_dir"),
                "project_name": self._project_name(deployment),
                "ports": ports,
                "message": message,
                "client_authoritative": True,
                "mode": "dockerfile",
            }
            return

        ps_result = self._run([
            "docker", "compose", *self._compose_files_args(deployment),
            "--project-name", self._project_name(deployment),
            "ps", "--format", "json",
        ], cwd=source_root)

        services = []
        if ps_result.returncode == 0 and ps_result.stdout.strip():
            try:
                rows = json.loads(ps_result.stdout)
                services = rows if isinstance(rows, list) else [rows]
            except json.JSONDecodeError:
                services = []

        ports = []
        if not services:
            state = "error" if message else "stopped"
        else:
            state = "running" if not message else "error"
            for row in services:
                # Use the state of the first service as the overall state for now
                # or we could aggregate them.
                state = (row.get("State") or state).lower()
                for item in row.get("Publishers") or []:
                    url = item.get("URL")
                    published = item.get("PublishedPort")
                    target = item.get("TargetPort")
                    if url and published and target:
                        ports.append(f"{url}:{published}->{target}")

        self.status[deployment_id] = {
            "state": state,
            "template": deployment.get("template") or deployment.get("type"),
            "source_dir": deployment.get("source_dir"),
            "project_name": self._project_name(deployment),
            "ports": ports,
            "message": message,
            "client_authoritative": True,
            "mode": "compose",
        }
