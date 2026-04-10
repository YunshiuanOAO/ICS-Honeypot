"""
Generic TCP Proxy
Captures and logs raw TCP traffic without protocol-specific parsing.
Useful as a fallback for unknown protocols or as a base for custom proxies.
"""

from .base_proxy import BaseProxy, ProxyConfig
from .unified_logger import UnifiedLogger, ProtocolInfo


class TCPProxy(BaseProxy):
    """
    Generic TCP proxy that captures all traffic without protocol parsing.
    
    Use cases:
    - Unknown protocols
    - Raw traffic capture
    - Quick deployment without protocol analysis
    - Fallback when no specific proxy is available
    
    Example:
        config = ProxyConfig(
            listen_port=5020,
            backend_host="127.0.0.1",
            backend_port=15020,
            protocol="tcp",
            node_id="node-01",
            deployment_id="unknown-service",
        )
        logger = UnifiedLogger("/var/log/honeypot", "node-01", "unknown-service")
        proxy = TCPProxy(config, logger)
        proxy.start()
    """
    
    def parse_request(self, data: bytes, session_id: str = "") -> dict:
        """
        Generic request parsing - just provide basic byte info.
        No protocol-specific parsing.
        """
        return {
            "byte_length": len(data),
            "first_bytes_hex": data[:16].hex() if data else "",
            "is_printable": self._is_printable(data),
            "printable_preview": self._get_printable_preview(data),
        }
    
    def parse_response(self, data: bytes, request_context: dict = None) -> dict:
        """
        Generic response parsing - just provide basic byte info.
        """
        if not data:
            return {"empty": True}
        
        return {
            "byte_length": len(data),
            "first_bytes_hex": data[:16].hex(),
            "is_printable": self._is_printable(data),
            "printable_preview": self._get_printable_preview(data),
        }
    
    def get_protocol_info(self) -> ProtocolInfo:
        """Return generic TCP protocol info"""
        return ProtocolInfo(
            name=self.config.protocol or "tcp",
            layer="transport",
            version=self.config.protocol_version or "",
        )
    
    def _is_printable(self, data: bytes, threshold: float = 0.8) -> bool:
        """Check if data is mostly printable ASCII"""
        if not data:
            return False
        
        printable_count = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        return (printable_count / len(data)) >= threshold
    
    def _get_printable_preview(self, data: bytes, max_length: int = 100) -> str:
        """Get printable preview of data"""
        if not data:
            return ""
        
        try:
            # Try to decode as UTF-8
            text = data[:max_length].decode("utf-8", errors="replace")
            # Replace non-printable characters
            text = "".join(c if c.isprintable() or c in "\n\r\t" else "." for c in text)
            return text
        except Exception:
            return ""
