"""
Proxy Manager
Manages multiple protocol proxies for honeypot deployments.
Handles proxy lifecycle, configuration, and coordination with Docker containers.
"""

import os
from typing import Dict, List, Optional, Type
from dataclasses import dataclass, field

from .base_proxy import BaseProxy, ProxyConfig
from .unified_logger import UnifiedLogger
from .tcp_proxy import TCPProxy
from .modbus_proxy import ModbusProxy
from .http_proxy import HTTPProxy
from .mqtt_proxy import MQTTProxy


# Protocol to Proxy class mapping
PROTOCOL_PROXY_MAP: Dict[str, Type[BaseProxy]] = {
    "tcp": TCPProxy,
    "modbus": ModbusProxy,
    "http": HTTPProxy,
    "mqtt": MQTTProxy,
}

# Default protocol detection based on common ports
DEFAULT_PORT_PROTOCOLS = {
    502: "modbus",
    5020: "modbus",
    80: "http",
    8080: "http",
    443: "http",  # HTTPS still uses HTTP proxy (TLS termination handled separately)
    1883: "mqtt",
    8883: "mqtt",
}


@dataclass
class ProxyInstance:
    """Represents a running proxy instance"""
    deployment_id: str
    protocol: str
    listen_port: int
    backend_port: int
    proxy: BaseProxy
    logger: UnifiedLogger


class ProxyManager:
    """
    Central manager for all protocol proxies.
    
    Features:
    - Automatic proxy type selection based on protocol/port
    - Unified logging across all proxies
    - Lifecycle management (start/stop)
    - Dynamic port allocation for backends
    
    Architecture:
    
        ProxyManager
            │
            ├── ModbusProxy (:502 -> container:5020)
            │       └── UnifiedLogger -> logs/modbus/events.jsonl
            │
            ├── HTTPProxy (:80 -> container:8080)
            │       └── UnifiedLogger -> logs/http/events.jsonl
            │
            └── MQTTProxy (:1883 -> container:11883)
                    └── UnifiedLogger -> logs/mqtt/events.jsonl
    
    Example:
        manager = ProxyManager(
            log_root="/var/log/honeypot",
            node_id="node-01",
        )
        
        # Add proxy for a deployment
        manager.add_proxy(
            deployment_id="plc-01",
            protocol="modbus",
            listen_port=502,
            backend_host="127.0.0.1",
            backend_port=5020,
        )
        
        # Start all proxies
        manager.start_all()
        
        # Stop all proxies
        manager.stop_all()
    """
    
    def __init__(
        self,
        log_root: str,
        node_id: str = "",
        default_backend_host: str = "127.0.0.1",
    ):
        self.log_root = log_root
        self.node_id = node_id
        self.default_backend_host = default_backend_host
        
        self._proxies: Dict[str, ProxyInstance] = {}
        self._next_backend_port = 10000  # Start backend ports from 10000
        
        os.makedirs(log_root, exist_ok=True)
    
    def add_proxy(
        self,
        deployment_id: str,
        protocol: str,
        listen_port: int,
        backend_host: str = None,
        backend_port: int = None,
        extra_config: dict = None,
    ) -> ProxyInstance:
        """
        Add a new proxy for a deployment.
        
        Args:
            deployment_id: Unique identifier for the deployment
            protocol: Protocol name (modbus, http, mqtt, tcp)
            listen_port: Port to listen on for incoming connections
            backend_host: Host where the actual service runs (default: 127.0.0.1)
            backend_port: Port of the actual service (default: auto-assigned)
            extra_config: Additional protocol-specific configuration
            
        Returns:
            ProxyInstance: The created proxy instance
        """
        # Stop existing proxy if any
        if deployment_id in self._proxies:
            self.remove_proxy(deployment_id)
        
        # Determine backend port
        if backend_port is None:
            backend_port = self._allocate_backend_port()
        
        # Get proxy class
        proxy_class = self._get_proxy_class(protocol, listen_port)
        
        # Create logger for this deployment
        log_dir = os.path.join(self.log_root, deployment_id)
        logger = UnifiedLogger(
            log_dir=log_dir,
            node_id=self.node_id,
            deployment_id=deployment_id,
        )
        
        # Create proxy config
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
        
        # Create proxy instance
        proxy = proxy_class(config, logger)
        
        instance = ProxyInstance(
            deployment_id=deployment_id,
            protocol=protocol,
            listen_port=listen_port,
            backend_port=backend_port,
            proxy=proxy,
            logger=logger,
        )
        
        self._proxies[deployment_id] = instance
        
        print(f"[ProxyManager] Added {protocol} proxy for {deployment_id}: :{listen_port} -> :{backend_port}")
        
        return instance
    
    def remove_proxy(self, deployment_id: str) -> bool:
        """
        Remove and stop a proxy.
        
        Args:
            deployment_id: The deployment to remove
            
        Returns:
            bool: True if removed, False if not found
        """
        if deployment_id not in self._proxies:
            return False
        
        instance = self._proxies.pop(deployment_id)
        instance.proxy.stop()
        
        print(f"[ProxyManager] Removed proxy for {deployment_id}")
        
        return True
    
    def start_proxy(self, deployment_id: str) -> bool:
        """Start a specific proxy"""
        if deployment_id not in self._proxies:
            return False
        
        self._proxies[deployment_id].proxy.start()
        return True
    
    def stop_proxy(self, deployment_id: str) -> bool:
        """Stop a specific proxy"""
        if deployment_id not in self._proxies:
            return False
        
        self._proxies[deployment_id].proxy.stop()
        return True
    
    def start_all(self):
        """Start all proxies"""
        for instance in self._proxies.values():
            if not instance.proxy.is_running:
                instance.proxy.start()
    
    def stop_all(self):
        """Stop all proxies"""
        for instance in self._proxies.values():
            if instance.proxy.is_running:
                instance.proxy.stop()
    
    def get_proxy(self, deployment_id: str) -> Optional[ProxyInstance]:
        """Get a proxy instance by deployment ID"""
        return self._proxies.get(deployment_id)
    
    def get_all_proxies(self) -> Dict[str, ProxyInstance]:
        """Get all proxy instances"""
        return dict(self._proxies)
    
    def get_status(self) -> Dict[str, dict]:
        """Get status of all proxies"""
        status = {}
        for deployment_id, instance in self._proxies.items():
            status[deployment_id] = {
                "protocol": instance.protocol,
                "listen_port": instance.listen_port,
                "backend_port": instance.backend_port,
                "running": instance.proxy.is_running,
                "connection_count": instance.proxy.connection_count,
            }
        return status
    
    def _get_proxy_class(self, protocol: str, listen_port: int) -> Type[BaseProxy]:
        """Get the appropriate proxy class for a protocol/port"""
        proto = (protocol or "").lower()

        # If an explicit protocol other than generic "tcp" is given, use it
        if proto and proto != "tcp" and proto in PROTOCOL_PROXY_MAP:
            return PROTOCOL_PROXY_MAP[proto]

        # Try port-based detection (overrides generic "tcp")
        if listen_port in DEFAULT_PORT_PROTOCOLS:
            detected_protocol = DEFAULT_PORT_PROTOCOLS[listen_port]
            return PROTOCOL_PROXY_MAP[detected_protocol]

        # Use explicit "tcp" or default
        if proto in PROTOCOL_PROXY_MAP:
            return PROTOCOL_PROXY_MAP[proto]

        return TCPProxy
    
    def _allocate_backend_port(self) -> int:
        """Allocate a unique backend port"""
        port = self._next_backend_port
        self._next_backend_port += 1
        return port
    
    def apply_deployments(self, deployments: List[dict]) -> dict:
        """
        Apply deployment configuration - add/remove proxies as needed.
        
        Args:
            deployments: List of deployment configurations from server
            
        Returns:
            dict: Status of each deployment
        """
        desired_ids = {d["id"] for d in deployments if d.get("enabled", True)}
        
        # Remove proxies for disabled/removed deployments
        for deployment_id in list(self._proxies.keys()):
            if deployment_id not in desired_ids:
                self.remove_proxy(deployment_id)
        
        # Add/update proxies for enabled deployments
        result = {}
        for deployment in deployments:
            if not deployment.get("enabled", True):
                continue
            
            deployment_id = deployment["id"]
            
            # Get proxy configuration from deployment
            proxy_config = deployment.get("proxy", {})
            protocol = proxy_config.get("protocol") or deployment.get("template") or "tcp"
            listen_port = proxy_config.get("listen_port") or deployment.get("port") or 0
            backend_port = proxy_config.get("backend_port") or deployment.get("container_port")
            
            if listen_port == 0:
                result[deployment_id] = {"error": "No listen port configured"}
                continue
            
            try:
                # Check if proxy already exists and is unchanged
                existing = self._proxies.get(deployment_id)
                if existing and existing.listen_port == listen_port and existing.protocol == protocol:
                    result[deployment_id] = {"status": "unchanged", "running": existing.proxy.is_running}
                    continue
                
                # Add or update proxy
                instance = self.add_proxy(
                    deployment_id=deployment_id,
                    protocol=protocol,
                    listen_port=listen_port,
                    backend_port=backend_port,
                    extra_config=proxy_config.get("extra_config"),
                )
                
                result[deployment_id] = {
                    "status": "added",
                    "listen_port": instance.listen_port,
                    "backend_port": instance.backend_port,
                }
                
            except Exception as e:
                result[deployment_id] = {"error": str(e)}
        
        return result
    
    def get_backend_port_mapping(self) -> Dict[str, int]:
        """
        Get mapping of deployment_id to backend port.
        Used by DockerManager to configure container port bindings.
        """
        return {
            deployment_id: instance.backend_port
            for deployment_id, instance in self._proxies.items()
        }


def create_proxy_for_deployment(
    deployment: dict,
    log_root: str,
    node_id: str,
    backend_host: str = "127.0.0.1",
) -> Optional[ProxyInstance]:
    """
    Convenience function to create a proxy for a single deployment.
    
    Args:
        deployment: Deployment configuration dict
        log_root: Root directory for logs
        node_id: Node identifier
        backend_host: Host where container runs
        
    Returns:
        ProxyInstance or None if creation fails
    """
    deployment_id = deployment.get("id")
    if not deployment_id:
        return None
    
    proxy_config = deployment.get("proxy", {})
    protocol = proxy_config.get("protocol") or deployment.get("template") or "tcp"
    listen_port = proxy_config.get("listen_port") or deployment.get("port")
    backend_port = proxy_config.get("backend_port") or deployment.get("container_port")
    
    if not listen_port:
        return None
    
    # Get proxy class
    proxy_class = PROTOCOL_PROXY_MAP.get(protocol.lower(), TCPProxy)
    
    # Create logger
    log_dir = os.path.join(log_root, deployment_id)
    logger = UnifiedLogger(
        log_dir=log_dir,
        node_id=node_id,
        deployment_id=deployment_id,
    )
    
    # Create config
    config = ProxyConfig(
        listen_host="0.0.0.0",
        listen_port=listen_port,
        backend_host=backend_host,
        backend_port=backend_port or listen_port + 10000,
        protocol=protocol,
        node_id=node_id,
        deployment_id=deployment_id,
    )
    
    # Create proxy
    proxy = proxy_class(config, logger)
    
    return ProxyInstance(
        deployment_id=deployment_id,
        protocol=protocol,
        listen_port=listen_port,
        backend_port=config.backend_port,
        proxy=proxy,
        logger=logger,
    )
