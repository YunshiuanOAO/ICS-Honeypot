import json
import os
import re
from datetime import datetime


class ContainerLogCollector:
    def __init__(self, runtime_root, db):
        self.runtime_root = runtime_root
        self.db = db
        self.state_file = os.path.join(runtime_root, "log_offsets.json")
        os.makedirs(runtime_root, exist_ok=True)
        self.offsets = self._load_state()

    def _load_state(self):
        if not os.path.exists(self.state_file):
            return {}
        try:
            with open(self.state_file, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            return {}

    def _save_state(self):
        with open(self.state_file, "w", encoding="utf-8") as handle:
            json.dump(self.offsets, handle, indent=2, ensure_ascii=False)

    def _read_new_lines(self, file_path):
        offset = self.offsets.get(file_path, 0)
        if not os.path.exists(file_path):
            return []

        lines = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(offset)
            for line in handle:
                lines.append(line.rstrip("\n"))
            self.offsets[file_path] = handle.tell()
        return lines

    def collect(self, deployments):
        changed = False
        for deployment in deployments:
            if not deployment.get("enabled", True):
                continue

            deployment_root = os.path.join(self.runtime_root, deployment["id"])
            source_dir = deployment.get("source_dir") or deployment["id"]
            package_root = os.path.join(deployment_root, "package", source_dir)
            logs_root = os.path.join(deployment_root, "logs")
            data_root = os.path.join(deployment_root, "data")
            log_paths = deployment.get("log_paths") or []

            for path in log_paths:
                resolved = self._resolve_log_path(path, package_root, logs_root, data_root)
                changed |= self._collect_file(resolved, deployment)

        if changed:
            self._save_state()

    def _resolve_log_path(self, path, package_root, logs_root, data_root):
        if os.path.isabs(path):
            return path

        normalized = str(path or "").replace("\\", "/").strip()
        if normalized.startswith("logs/"):
            return os.path.join(logs_root, normalized[len("logs/"):])
        if normalized.startswith("data/"):
            return os.path.join(data_root, normalized[len("data/"):])
        return os.path.join(package_root, normalized)

    def _collect_file(self, file_path, deployment):
        lines = self._read_new_lines(file_path)
        if not lines:
            return False

        protocol = deployment.get("template") or deployment.get("type") or "custom"
        if file_path.endswith(".jsonl") or file_path.endswith(".json"):
            for line in lines:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    self._log_plain_line(line, protocol, deployment, file_path)
                    continue

                metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
                metadata.update({
                    "deployment.id": deployment.get("id"),
                    "deployment.name": deployment.get("name"),
                    "log.file": os.path.basename(file_path),
                })
                self.db.log_interaction(
                    attacker_ip=entry.get("attacker_ip") or entry.get("remote_addr") or "unknown",
                    protocol=entry.get("protocol") or protocol,
                    request_data=entry.get("request_data") or entry.get("message") or json.dumps(entry, ensure_ascii=False),
                    response_data=entry.get("response_data") or "",
                    metadata=metadata,
                    timestamp=entry.get("timestamp") or datetime.now().isoformat(),
                )
            return True

        for line in lines:
            self._log_plain_line(line, protocol, deployment, file_path)
        return True

    def _log_plain_line(self, line, protocol, deployment, file_path):
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line or "")
        metadata = {
            "deployment.id": deployment.get("id"),
            "deployment.name": deployment.get("name"),
            "log.file": os.path.basename(file_path),
            "log.message": line,
        }
        self.db.log_interaction(
            attacker_ip=ip_match.group(1) if ip_match else "unknown",
            protocol=protocol,
            request_data=line,
            response_data="",
            metadata=metadata,
            timestamp=datetime.now().isoformat(),
        )
