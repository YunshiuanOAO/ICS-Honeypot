"""
Unified Logger for Honeypot Traffic
Provides a standardized log format for all protocols to enable cross-protocol analysis.
"""

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional
from threading import Lock


@dataclass
class NetworkInfo:
    """Network layer information"""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    transport: str = "tcp"  # tcp, udp


@dataclass
class ProtocolInfo:
    """Protocol identification"""
    name: str = "unknown"  # modbus, http, mqtt, s7, dnp3, etc.
    layer: str = "application"
    version: str = ""


@dataclass
class RequestData:
    """Request payload and parsed data"""
    raw_hex: str = ""
    raw_base64: str = ""
    size_bytes: int = 0
    parsed: dict = field(default_factory=dict)


@dataclass
class ResponseData:
    """Response payload and parsed data"""
    raw_hex: str = ""
    raw_base64: str = ""
    size_bytes: int = 0
    parsed: dict = field(default_factory=dict)


@dataclass
class SessionInfo:
    """Session tracking information"""
    id: str = ""
    request_count: int = 1
    duration_ms: int = 0
    start_time: str = ""


@dataclass
class ThreatIntel:
    """Threat intelligence metadata (for future ML/analysis)"""
    is_scan: bool = False
    attack_type: Optional[str] = None
    confidence: float = 0.0
    tags: list = field(default_factory=list)


@dataclass
class LogEntry:
    """
    Unified log entry format for all honeypot protocols.
    This standardized format enables:
    - Cross-protocol analysis
    - ELK/Splunk ingestion
    - Machine learning pipelines
    - Threat hunting queries
    """
    timestamp: str = ""
    event_id: str = ""
    node_id: str = ""
    deployment_id: str = ""
    
    network: NetworkInfo = field(default_factory=NetworkInfo)
    protocol: ProtocolInfo = field(default_factory=ProtocolInfo)
    request: RequestData = field(default_factory=RequestData)
    response: ResponseData = field(default_factory=ResponseData)
    session: SessionInfo = field(default_factory=SessionInfo)
    threat_intel: ThreatIntel = field(default_factory=ThreatIntel)
    
    # Additional metadata for extensibility
    metadata: dict = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "node_id": self.node_id,
            "deployment_id": self.deployment_id,
            "network": asdict(self.network),
            "protocol": asdict(self.protocol),
            "request": asdict(self.request),
            "response": asdict(self.response),
            "session": asdict(self.session),
            "threat_intel": asdict(self.threat_intel),
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: dict) -> "LogEntry":
        """Create LogEntry from dictionary"""
        return cls(
            timestamp=data.get("timestamp", ""),
            event_id=data.get("event_id", ""),
            node_id=data.get("node_id", ""),
            deployment_id=data.get("deployment_id", ""),
            network=NetworkInfo(**data.get("network", {})),
            protocol=ProtocolInfo(**data.get("protocol", {})),
            request=RequestData(**data.get("request", {})),
            response=ResponseData(**data.get("response", {})),
            session=SessionInfo(**data.get("session", {})),
            threat_intel=ThreatIntel(**data.get("threat_intel", {})),
            metadata=data.get("metadata", {}),
        )


class UnifiedLogger:
    """
    Thread-safe unified logger that writes structured JSON logs.
    Supports multiple output destinations and log rotation.
    """
    
    def __init__(
        self,
        log_dir: str,
        node_id: str = "",
        deployment_id: str = "",
        filename: str = "events.jsonl",
        max_file_size_mb: int = 100,
        backup_count: int = 5,
    ):
        self.log_dir = log_dir
        self.node_id = node_id
        self.deployment_id = deployment_id
        self.filename = filename
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.backup_count = backup_count
        
        self._lock = Lock()
        self._sessions: dict[str, SessionInfo] = {}
        
        os.makedirs(log_dir, exist_ok=True)
    
    @property
    def log_path(self) -> str:
        return os.path.join(self.log_dir, self.filename)
    
    def _rotate_if_needed(self):
        """Rotate log file if it exceeds max size"""
        if not os.path.exists(self.log_path):
            return
        
        if os.path.getsize(self.log_path) < self.max_file_size_bytes:
            return
        
        # Rotate existing backups
        for i in range(self.backup_count - 1, 0, -1):
            old_path = f"{self.log_path}.{i}"
            new_path = f"{self.log_path}.{i + 1}"
            if os.path.exists(old_path):
                if os.path.exists(new_path):
                    os.remove(new_path)
                os.rename(old_path, new_path)
        
        # Move current to .1
        backup_path = f"{self.log_path}.1"
        if os.path.exists(backup_path):
            os.remove(backup_path)
        os.rename(self.log_path, backup_path)
    
    def log(self, entry: LogEntry) -> str:
        """
        Write a log entry to the unified log file.
        Returns the event_id for reference.
        """
        # Ensure node_id and deployment_id are set
        if not entry.node_id:
            entry.node_id = self.node_id
        if not entry.deployment_id:
            entry.deployment_id = self.deployment_id
        
        with self._lock:
            self._rotate_if_needed()
            
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry.to_json() + "\n")
        
        return entry.event_id
    
    def log_raw(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        request_bytes: bytes,
        response_bytes: bytes = b"",
        parsed_request: dict = None,
        parsed_response: dict = None,
        session_id: str = "",
        metadata: dict = None,
    ) -> str:
        """
        Convenience method to log raw traffic data.
        Automatically converts bytes to hex and base64.
        """
        import base64
        
        entry = LogEntry(
            node_id=self.node_id,
            deployment_id=self.deployment_id,
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                transport="tcp",
            ),
            protocol=ProtocolInfo(name=protocol),
            request=RequestData(
                raw_hex=request_bytes.hex() if request_bytes else "",
                raw_base64=base64.b64encode(request_bytes).decode() if request_bytes else "",
                size_bytes=len(request_bytes),
                parsed=parsed_request or {},
            ),
            response=ResponseData(
                raw_hex=response_bytes.hex() if response_bytes else "",
                raw_base64=base64.b64encode(response_bytes).decode() if response_bytes else "",
                size_bytes=len(response_bytes),
                parsed=parsed_response or {},
            ),
            session=SessionInfo(id=session_id) if session_id else SessionInfo(),
            metadata=metadata or {},
        )
        
        return self.log(entry)
    
    def get_or_create_session(self, session_key: str) -> SessionInfo:
        """Get or create a session for tracking multiple requests"""
        with self._lock:
            if session_key not in self._sessions:
                self._sessions[session_key] = SessionInfo(
                    id=str(uuid.uuid4()),
                    request_count=0,
                    start_time=datetime.now(timezone.utc).isoformat(),
                )
            
            session = self._sessions[session_key]
            session.request_count += 1
            return session
    
    def close_session(self, session_key: str):
        """Close and remove a session"""
        with self._lock:
            self._sessions.pop(session_key, None)


# Legacy compatibility adapter
class LegacyLogAdapter:
    """
    Adapter that converts unified log format to legacy format
    for backward compatibility with existing log_collector.py
    """
    
    def __init__(self, unified_logger: UnifiedLogger):
        self.logger = unified_logger
    
    def log_interaction(
        self,
        attacker_ip: str,
        protocol: str,
        request_data: Any,
        response_data: Any = None,
        metadata: dict = None,
        timestamp: str = None,
    ):
        """Legacy-compatible log method"""
        # Convert request data
        if isinstance(request_data, bytes):
            req_bytes = request_data
        elif isinstance(request_data, str):
            try:
                req_bytes = bytes.fromhex(request_data)
            except ValueError:
                req_bytes = request_data.encode("utf-8")
        else:
            req_bytes = str(request_data).encode("utf-8")
        
        # Convert response data
        if isinstance(response_data, bytes):
            resp_bytes = response_data
        elif isinstance(response_data, str):
            try:
                resp_bytes = bytes.fromhex(response_data)
            except (ValueError, TypeError):
                resp_bytes = (response_data or "").encode("utf-8")
        else:
            resp_bytes = b""
        
        self.logger.log_raw(
            src_ip=attacker_ip,
            src_port=0,
            dst_ip="0.0.0.0",
            dst_port=0,
            protocol=protocol,
            request_bytes=req_bytes,
            response_bytes=resp_bytes,
            parsed_request=metadata,
            metadata={"legacy_timestamp": timestamp} if timestamp else {},
        )
