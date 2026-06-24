"""
Proxy Manager
Manages multiple protocol proxies for honeypot deployments.

A single deployment can host multiple proxies (e.g. one service that
exposes both Modbus and HTTP). Proxies are keyed by ``(deployment_id, name)``;
``name`` is unique within a deployment and used to build the log directory and
Docker env-var name.

Backwards compatibility: deployments that still carry a single ``proxy`` dict
are normalised into a one-element ``proxies`` list (with name ``"default"``).
"""

import os
import re
from typing import Dict, List, Optional, Tuple, Type
from dataclasses import dataclass

from .base_proxy import BaseProxy, ProxyConfig
from .unified_logger import UnifiedLogger
from .tcp_proxy import TCPProxy
from .modbus_proxy import ModbusProxy
from .http_proxy import HTTPProxy
from .https_proxy import HTTPSProxy
from .mqtt_proxy import MQTTProxy


PROTOCOL_PROXY_MAP: Dict[str, Type[BaseProxy]] = {
    "tcp": TCPProxy,
    "modbus": ModbusProxy,
    "http": HTTPProxy,
    "https": HTTPSProxy,
    "mqtt": MQTTProxy,
}

DEFAULT_PORT_PROTOCOLS = {
    502: "modbus",
    5020: "modbus",
    80: "http",
    8080: "http",
    443: "https",
    8443: "https",
    1883: "mqtt",
    8883: "mqtt",
}


def _slugify_name(name: str, fallback: str = "proxy") -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(name or "").strip()).strip("-").lower()
    return cleaned or fallback


def normalize_deployment_proxies(deployment: dict) -> List[dict]:
    """Return a list of proxy dicts for a deployment.

    Accepts either the new ``proxies`` list or the legacy ``proxy`` dict.
    Each entry is augmented with a unique ``name`` field if not present.
    """
    raw = deployment.get("proxies")
    if not raw:
        legacy = deployment.get("proxy")
        if legacy:
            raw = [legacy]
        else:
            raw = []

    if not isinstance(raw, list):
        return []

    seen = set()
    result = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        proxy = dict(entry)
        name = _slugify_name(proxy.get("name") or proxy.get("protocol") or f"proxy-{index + 1}",
                             fallback=f"proxy-{index + 1}")
        # Ensure uniqueness within deployment
        candidate = name
        suffix = 2
        while candidate in seen:
            candidate = f"{name}-{suffix}"
            suffix += 1
        proxy["name"] = candidate
        seen.add(candidate)
        result.append(proxy)
    return result


@dataclass
class ProxyInstance:
    """Represents a running proxy instance."""
    deployment_id: str
    name: str
    protocol: str
    listen_port: int
    backend_port: int
    container_port: Optional[int]
    proxy: BaseProxy
    logger: UnifiedLogger
    whitelist_logger: Optional[UnifiedLogger] = None

    @property
    def key(self) -> Tuple[str, str]:
        return (self.deployment_id, self.name)


class ProxyManager:
    """Central manager for all protocol proxies.

    Proxies are keyed by ``(deployment_id, proxy_name)``. Logs are written to
    ``log_root/<deployment_id>/<proxy_name>/events.jsonl``.
    """

    def __init__(
        self,
        log_root: str,
        node_id: str = "",
        default_backend_host: str = "127.0.0.1",
        whitelist=None,
    ):
        self.log_root = log_root
        self.node_id = node_id
        self.default_backend_host = default_backend_host
        self.whitelist = whitelist

        self._proxies: Dict[Tuple[str, str], ProxyInstance] = {}
        self._next_backend_port = 10000

        os.makedirs(log_root, exist_ok=True)

    def add_proxy(
        self,
        deployment_id: str,
        protocol: str,
        listen_port: int,
        name: str = "default",
        backend_host: str = None,
        backend_port: int = None,
        container_port: int = None,
        extra_config: dict = None,
    ) -> ProxyInstance:
        """Add (or replace) a proxy keyed by (deployment_id, name)."""
        proxy_name = _slugify_name(name, fallback="default")
        key = (deployment_id, proxy_name)

        if key in self._proxies:
            self.remove_proxy(deployment_id, proxy_name)

        if backend_port is None:
            backend_port = self._allocate_backend_port()

        proxy_class = self._get_proxy_class(protocol, listen_port)

        log_dir = os.path.join(self.log_root, deployment_id, proxy_name)
        logger = UnifiedLogger(
            log_dir=log_dir,
            node_id=self.node_id,
            deployment_id=deployment_id,
        )
        whitelist_logger = UnifiedLogger(
            log_dir=log_dir,
            node_id=self.node_id,
            deployment_id=deployment_id,
            filename="whitelist.jsonl",
        )

        config = ProxyConfig(
            listen_host="0.0.0.0",
            listen_port=listen_port,
            backend_host=backend_host or self.default_backend_host,
            backend_port=backend_port,
            protocol=protocol,
            node_id=self.node_id,
            deployment_id=deployment_id,
            extra_config=extra_config or {},
        )

        proxy = proxy_class(
            config,
            logger,
            whitelist_logger=whitelist_logger,
            whitelist=self.whitelist,
        )

        instance = ProxyInstance(
            deployment_id=deployment_id,
            name=proxy_name,
            protocol=protocol,
            listen_port=listen_port,
            backend_port=backend_port,
            container_port=container_port,
            proxy=proxy,
            logger=logger,
            whitelist_logger=whitelist_logger,
        )

        self._proxies[key] = instance

        print(f"[ProxyManager] Added {protocol} proxy {deployment_id}/{proxy_name}: :{listen_port} -> :{backend_port}")
        return instance

    def remove_proxy(self, deployment_id: str, name: str = "default") -> bool:
        """Remove and stop a single proxy."""
        proxy_name = _slugify_name(name, fallback="default")
        key = (deployment_id, proxy_name)
        if key not in self._proxies:
            return False
        instance = self._proxies.pop(key)
        instance.proxy.stop()
        print(f"[ProxyManager] Removed proxy {deployment_id}/{proxy_name}")
        return True

    def remove_deployment(self, deployment_id: str) -> int:
        """Remove all proxies belonging to a deployment. Returns count removed."""
        keys = [k for k in self._proxies.keys() if k[0] == deployment_id]
        for key in keys:
            instance = self._proxies.pop(key)
            instance.proxy.stop()
            print(f"[ProxyManager] Removed proxy {key[0]}/{key[1]}")
        return len(keys)

    def start_all(self):
        for instance in self._proxies.values():
            if not instance.proxy.is_running:
                instance.proxy.start()

    def stop_all(self):
        for instance in self._proxies.values():
            if instance.proxy.is_running:
                instance.proxy.stop()

    def get_proxies_for_deployment(self, deployment_id: str) -> List[ProxyInstance]:
        return [inst for (dep, _), inst in self._proxies.items() if dep == deployment_id]

    def get_all_proxies(self) -> Dict[Tuple[str, str], ProxyInstance]:
        return dict(self._proxies)

    def get_status(self) -> Dict[str, dict]:
        """Per-deployment status. Each entry has a ``proxies`` list with one
        item per proxy. The single-proxy convenience fields are kept for the
        first proxy to preserve the existing dashboard contract.
        """
        status: Dict[str, dict] = {}
        for (dep_id, name), instance in self._proxies.items():
            entry = status.setdefault(dep_id, {"proxies": []})
            proxy_status = {
                "name": name,
                "protocol": instance.protocol,
                "listen_port": instance.listen_port,
                "backend_port": instance.backend_port,
                "container_port": instance.container_port,
                "running": instance.proxy.is_running,
                "connection_count": instance.proxy.connection_count,
            }
            entry["proxies"].append(proxy_status)
            # Keep legacy fields populated from the first proxy added.
            for key in ("protocol", "listen_port", "backend_port", "running", "connection_count"):
                entry.setdefault(key, proxy_status[key])
        return status

    def _get_proxy_class(self, protocol: str, listen_port: int) -> Type[BaseProxy]:
        proto = (protocol or "").lower()
        if proto and proto != "tcp" and proto in PROTOCOL_PROXY_MAP:
            return PROTOCOL_PROXY_MAP[proto]
        if listen_port in DEFAULT_PORT_PROTOCOLS:
            return PROTOCOL_PROXY_MAP[DEFAULT_PORT_PROTOCOLS[listen_port]]
        if proto in PROTOCOL_PROXY_MAP:
            return PROTOCOL_PROXY_MAP[proto]
        return TCPProxy

    def _allocate_backend_port(self) -> int:
        port = self._next_backend_port
        self._next_backend_port += 1
        return port

    def apply_deployments(self, deployments: List[dict]) -> dict:
        """Reconcile running proxies with the desired deployment config.

        For each enabled deployment, iterate its ``proxies`` list (or legacy
        ``proxy`` dict) and add/update each entry. Drops proxies that are no
        longer desired.
        """
        desired_keys = set()
        for deployment in deployments:
            if not deployment.get("enabled", True):
                continue
            dep_id = deployment["id"]
            for proxy_cfg in normalize_deployment_proxies(deployment):
                if not proxy_cfg.get("enabled", True):
                    continue
                desired_keys.add((dep_id, proxy_cfg["name"]))

        for key in list(self._proxies.keys()):
            if key not in desired_keys:
                self.remove_proxy(*key)

        result: Dict[str, dict] = {}
        for deployment in deployments:
            if not deployment.get("enabled", True):
                continue
            dep_id = deployment["id"]
            dep_result = result.setdefault(dep_id, {"proxies": {}})

            for proxy_cfg in normalize_deployment_proxies(deployment):
                if not proxy_cfg.get("enabled", True):
                    continue
                name = proxy_cfg["name"]
                protocol = proxy_cfg.get("protocol") or deployment.get("template") or "tcp"
                listen_port = proxy_cfg.get("listen_port") or 0
                backend_port = proxy_cfg.get("backend_port")
                container_port = proxy_cfg.get("container_port")

                if not listen_port:
                    dep_result["proxies"][name] = {"error": "No listen port configured"}
                    continue

                try:
                    existing = self._proxies.get((dep_id, name))
                    if (
                        existing
                        and existing.listen_port == listen_port
                        and existing.protocol == protocol
                        and existing.backend_port == (backend_port or existing.backend_port)
                    ):
                        dep_result["proxies"][name] = {
                            "status": "unchanged",
                            "running": existing.proxy.is_running,
                            "listen_port": existing.listen_port,
                            "backend_port": existing.backend_port,
                        }
                        continue

                    instance = self.add_proxy(
                        deployment_id=dep_id,
                        name=name,
                        protocol=protocol,
                        listen_port=listen_port,
                        backend_port=backend_port,
                        container_port=container_port,
                        extra_config=proxy_cfg.get("extra_config"),
                    )
                    dep_result["proxies"][name] = {
                        "status": "added",
                        "listen_port": instance.listen_port,
                        "backend_port": instance.backend_port,
                    }
                except Exception as e:
                    dep_result["proxies"][name] = {"error": str(e)}

        return result

    def get_backend_port_mapping(self) -> Dict[str, Dict[str, int]]:
        """Return ``{deployment_id: {proxy_name: backend_port}}``.

        Callers (DockerManager) use this to wire container port bindings to
        the backend ports the proxies expect.
        """
        mapping: Dict[str, Dict[str, int]] = {}
        for (dep_id, name), instance in self._proxies.items():
            mapping.setdefault(dep_id, {})[name] = instance.backend_port
        return mapping
