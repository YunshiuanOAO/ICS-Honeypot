import json
import os
import re
from copy import deepcopy


class ConfigLoader:
    def __init__(self, config_path=None):
        if config_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.config_path = os.path.join(base_dir, "client_config.json")
        else:
            self.config_path = config_path

        self.config = self._load_default_config()

    def _load_default_config(self):
        import uuid

        random_suffix = uuid.uuid4().hex[:8]
        return {
            "server_url": os.environ.get("CLIENT_SERVER_URL", "").strip() or "http://localhost:8000",
            "node_id": f"pending_{random_suffix}",
            "deployments": [],
        }

    def _slugify(self, text, fallback="deployment"):
        cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(text or "").strip()).strip("-").lower()
        return cleaned or fallback

    def _normalize_file(self, item, deployment_id, index):
        if isinstance(item, dict):
            path = str(item.get("path") or "").strip()
            content = item.get("content")
        else:
            path = ""
            content = ""

        if not path:
            path = f"file-{index + 1}.txt"

        return {
            "path": path.replace("\\", "/"),
            "content": "" if content is None else str(content),
        }

    def _default_files(self, deployment_type):
        defaults = {
            "modbus": [
                {"path": "Dockerfile", "content": ""},
                {"path": "docker-compose.yml", "content": ""},
                {"path": "app.py", "content": ""},
            ],
            "http": [
                {"path": "Dockerfile", "content": ""},
                {"path": "docker-compose.yml", "content": ""},
                {"path": "site/index.html", "content": ""},
            ],
            "mqtt": [
                {"path": "Dockerfile", "content": ""},
                {"path": "docker-compose.yml", "content": ""},
                {"path": "mosquitto.conf", "content": ""},
            ],
        }
        return deepcopy(defaults.get(deployment_type, [{"path": "Dockerfile", "content": ""}, {"path": "docker-compose.yml", "content": ""}]))

    def _normalize_deployment(self, deployment, index=0):
        normalized = deepcopy(deployment or {})
        deployment_type = normalized.get("type") or normalized.get("template") or "custom"
        normalized["type"] = deployment_type
        normalized["template"] = normalized.get("template") or deployment_type
        normalized["enabled"] = bool(normalized.get("enabled", True))
        normalized["name"] = normalized.get("name") or f"{deployment_type.upper()} Deployment {index + 1}"
        normalized["id"] = self._slugify(normalized.get("id") or normalized["name"], f"deployment-{index + 1}")
        normalized["source_dir"] = self._slugify(normalized.get("source_dir") or normalized["id"], normalized["id"])

        raw_log_paths = normalized.get("log_paths") or []
        if isinstance(raw_log_paths, str):
            raw_log_paths = [raw_log_paths]
        normalized["log_paths"] = [str(path).strip() for path in raw_log_paths if str(path).strip()]

        files = normalized.get("files") or []
        if not isinstance(files, list):
            files = []
        normalized["files"] = [
            self._normalize_file(item, normalized["id"], idx)
            for idx, item in enumerate(files)
        ]

        return normalized

    def clean_config(self, config):
        if not isinstance(config, dict):
            return config

        cleaned = {}
        for key, value in config.items():
            if key.startswith("_"):
                continue

            if isinstance(value, dict):
                cleaned[key] = self.clean_config(value)
            elif isinstance(value, list):
                cleaned[key] = [
                    self.clean_config(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                cleaned[key] = value

        return cleaned

    def validate_config(self, config):
        if not isinstance(config, dict):
            return False, "Config must be a dictionary"

        if "deployments" not in config:
            return False, "Missing 'deployments' field"

        if not isinstance(config["deployments"], list):
            return False, "'deployments' must be a list"

        for i, deployment in enumerate(config["deployments"]):
            if not isinstance(deployment, dict):
                return False, f"Deployment at index {i} must be a dictionary"

            files = deployment.get("files")
            if files is not None and not isinstance(files, list):
                return False, f"Deployment at index {i} files must be a list"

            if isinstance(files, list):
                for j, file_item in enumerate(files):
                    if not isinstance(file_item, dict):
                        return False, f"Deployment at index {i} file {j} must be a dictionary"
                    if not str(file_item.get("path") or "").strip():
                        return False, f"Deployment at index {i} file {j} missing path"

            log_paths = deployment.get("log_paths")
            if log_paths is not None and not isinstance(log_paths, (list, str)):
                return False, f"Deployment at index {i} log_paths must be a list or string"

        return True, None

    def normalize_config(self, config):
        normalized = deepcopy(config)
        deployments = normalized.get("deployments") or []
        normalized["deployments"] = [
            self._normalize_deployment(deployment, index=i)
            for i, deployment in enumerate(deployments)
        ]
        return normalized

    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as handle:
                    raw_config = json.load(handle)

                cleaned = self.clean_config(raw_config)
                is_valid, error = self.validate_config(cleaned)
                if is_valid:
                    self.config = self.normalize_config(cleaned)
                else:
                    print(f"Config validation failed: {error}, using default.")
                    self.config = self._load_default_config()
            except json.JSONDecodeError as exc:
                print(f"JSON decode error: {exc}, using default.")
                self.config = self._load_default_config()
            except Exception as exc:
                print(f"Error loading config: {exc}, using default.")
                self.config = self._load_default_config()
        return self.config

    def parse_server_config(self, raw_config):
        try:
            cleaned = self.clean_config(raw_config)
            is_valid, error = self.validate_config(cleaned)
            if not is_valid:
                return False, None, error
            normalized = self.normalize_config(cleaned)
            return True, normalized, None
        except Exception as exc:
            return False, None, f"Config parsing error: {str(exc)}"

    def save_config(self, config):
        cleaned = self.clean_config(config)
        self.config = cleaned
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(cleaned, handle, indent=4, ensure_ascii=False)
