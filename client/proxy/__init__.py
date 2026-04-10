# Proxy Layer for Honeypot Traffic Capture
# This module provides protocol-aware proxies that intercept and log all traffic
# before forwarding to the actual honeypot containers.

from .base_proxy import BaseProxy, ProxyConfig
from .unified_logger import UnifiedLogger, LogEntry
from .tcp_proxy import TCPProxy
from .modbus_proxy import ModbusProxy
from .http_proxy import HTTPProxy
from .mqtt_proxy import MQTTProxy
from .proxy_manager import ProxyManager

__all__ = [
    "BaseProxy",
    "ProxyConfig",
    "UnifiedLogger",
    "LogEntry",
    "TCPProxy",
    "ModbusProxy",
    "HTTPProxy",
    "MQTTProxy",
    "ProxyManager",
]
