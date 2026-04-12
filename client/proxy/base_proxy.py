"""
Base Proxy Class
Abstract base class for all protocol-specific proxies.
"""

import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Callable, Tuple
from .unified_logger import UnifiedLogger, LogEntry, NetworkInfo, ProtocolInfo, RequestData, ResponseData, SessionInfo


@dataclass
class ProxyConfig:
    """Configuration for a proxy instance"""
    # Listening configuration
    listen_host: str = "0.0.0.0"
    listen_port: int = 0
    
    # Backend (Docker container) configuration
    backend_host: str = "127.0.0.1"
    backend_port: int = 0
    
    # Protocol identification
    protocol: str = "tcp"
    protocol_version: str = ""
    
    # Deployment info for logging
    node_id: str = ""
    deployment_id: str = ""
    
    # Network settings
    buffer_size: int = 4096
    timeout: float = 30.0
    max_connections: int = 100
    
    # Optional custom parser (for protocol-specific handling)
    extra_config: dict = field(default_factory=dict)


class BaseProxy(ABC):
    """
    Abstract base class for all traffic capture proxies.
    
    Architecture:
    
        [Attacker] ---> [Proxy:listen_port] ---> [Container:backend_port]
                              |
                              v
                        [UnifiedLogger]
    
    Subclasses implement:
    - parse_request(): Extract protocol-specific fields from request
    - parse_response(): Extract protocol-specific fields from response
    - get_protocol_info(): Return protocol identification
    """
    
    def __init__(
        self,
        config: ProxyConfig,
        logger: UnifiedLogger,
        whitelist_logger: Optional[UnifiedLogger] = None,
        whitelist=None,
    ):
        self.config = config
        self.logger = logger
        # Optional separate logger for traffic from whitelisted IPs.
        self.whitelist_logger = whitelist_logger
        # WhitelistManager-like object; must expose .is_whitelisted(ip) -> bool.
        self.whitelist = whitelist

        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._connections: list[threading.Thread] = []
        self._connection_count = 0
        self._lock = threading.Lock()
    
    @abstractmethod
    def parse_request(self, data: bytes, session_id: str = "") -> dict:
        """
        Parse raw request bytes and return structured metadata.
        Override in protocol-specific subclasses.
        
        Returns:
            dict: Parsed fields like {"func_code": 3, "start_addr": 100, ...}
        """
        pass
    
    @abstractmethod
    def parse_response(self, data: bytes, request_context: dict = None) -> dict:
        """
        Parse raw response bytes and return structured metadata.
        Override in protocol-specific subclasses.
        
        Args:
            data: Raw response bytes
            request_context: Context from the corresponding request
            
        Returns:
            dict: Parsed fields
        """
        pass
    
    @abstractmethod
    def get_protocol_info(self) -> ProtocolInfo:
        """
        Return protocol identification info.
        Override in protocol-specific subclasses.
        """
        pass
    
    def start(self):
        """Start the proxy server"""
        if self._running:
            return
        
        self._running = True
        self._server_thread = threading.Thread(target=self._run_server, daemon=True)
        self._server_thread.start()
        
        print(f"[{self.config.protocol.upper()} Proxy] Started on :{self.config.listen_port} -> {self.config.backend_host}:{self.config.backend_port}")
    
    def stop(self):
        """Stop the proxy server and wait for the server thread to exit"""
        self._running = False
        
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=3)
        
        print(f"[{self.config.protocol.upper()} Proxy] Stopped")
    
    def _run_server(self):
        """Main server loop - accept connections and spawn handlers"""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.config.listen_host, self.config.listen_port))
            self._server_socket.listen(self.config.max_connections)
            self._server_socket.settimeout(1.0)  # Allow periodic check of _running
            
            while self._running:
                try:
                    client_sock, client_addr = self._server_socket.accept()
                    
                    with self._lock:
                        self._connection_count += 1
                        session_id = f"{client_addr[0]}:{client_addr[1]}-{self._connection_count}"
                    
                    handler = threading.Thread(
                        target=self._handle_connection,
                        args=(client_sock, client_addr, session_id),
                        daemon=True
                    )
                    handler.start()
                    
                    # Add to connections list and clean up completed threads
                    with self._lock:
                        # Remove completed threads to prevent memory leak
                        self._connections = [t for t in self._connections if t.is_alive()]
                        self._connections.append(handler)
                    
                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        raise
                    break
                    
        except Exception as e:
            print(f"[{self.config.protocol.upper()} Proxy] Server error: {e}")
        finally:
            if self._server_socket:
                self._server_socket.close()
    
    @property
    def full_duplex(self) -> bool:
        """Override to True for async protocols like MQTT that need
        bidirectional forwarding (broker can push at any time)."""
        return False

    def _handle_connection(self, client_sock: socket.socket, client_addr: Tuple[str, int], session_id: str):
        """Handle a single client connection - proxy traffic and log"""
        if self.full_duplex:
            return self._handle_connection_full_duplex(client_sock, client_addr, session_id)
        backend_sock = None
        
        try:
            # Connect to backend
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.settimeout(self.config.timeout)
            backend_sock.connect((self.config.backend_host, self.config.backend_port))
            
            client_sock.settimeout(self.config.timeout)
            
            # Get session for tracking
            session = self.logger.get_or_create_session(session_id)
            
            while self._running:
                # Read from client
                try:
                    request_data = client_sock.recv(self.config.buffer_size)
                    if not request_data:
                        break
                except socket.timeout:
                    continue
                except Exception:
                    break
                
                # Parse request for logging
                request_context = self.parse_request(request_data, session_id)
                
                # Forward to backend
                try:
                    backend_sock.sendall(request_data)
                except Exception as e:
                    print(f"[{self.config.protocol.upper()} Proxy] Backend send error: {e}")
                    break
                
                # Read response from backend
                response_data = b""
                try:
                    response_data = self._read_response(backend_sock, request_context)
                except socket.timeout:
                    pass
                except Exception as e:
                    print(f"[{self.config.protocol.upper()} Proxy] Backend recv error: {e}")
                
                # Parse response for logging
                response_context = self.parse_response(response_data, request_context)
                
                # Log the interaction
                self._log_traffic(
                    client_addr=client_addr,
                    request_data=request_data,
                    response_data=response_data,
                    request_context=request_context,
                    response_context=response_context,
                    session=session,
                )
                
                # Forward response to client
                if response_data:
                    try:
                        client_sock.sendall(response_data)
                    except Exception:
                        break
                        
        except Exception as e:
            print(f"[{self.config.protocol.upper()} Proxy] Connection error from {client_addr}: {e}")
        finally:
            if backend_sock:
                backend_sock.close()
            client_sock.close()
            self.logger.close_session(session_id)
            self._cleanup_session(session_id)  # Hook for subclass cleanup
    
    def _handle_connection_full_duplex(self, client_sock: socket.socket, client_addr: Tuple[str, int], session_id: str):
        """Handle connection with bidirectional forwarding (two threads).

        Used by async protocols like MQTT where the backend can push
        messages at any time, not just in response to a client request.
        """
        backend_sock = None

        try:
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.settimeout(self.config.timeout)
            backend_sock.connect((self.config.backend_host, self.config.backend_port))
            client_sock.settimeout(self.config.timeout)

            session = self.logger.get_or_create_session(session_id)
            stop_event = threading.Event()

            def forward(src, dst, direction):
                """Forward data between sockets.
                direction: 'request' (client→backend) or 'response' (backend→client)
                """
                try:
                    while self._running and not stop_event.is_set():
                        try:
                            data = src.recv(self.config.buffer_size)
                            if not data:
                                break
                        except socket.timeout:
                            continue
                        except Exception:
                            break

                        # Parse and log
                        if direction == "request":
                            parsed = self.parse_request(data, session_id)
                            self._log_traffic(
                                client_addr=client_addr,
                                request_data=data,
                                response_data=b"",
                                request_context=parsed,
                                response_context={},
                                session=session,
                            )
                        else:
                            parsed = self.parse_response(data)
                            self._log_traffic(
                                client_addr=client_addr,
                                request_data=b"",
                                response_data=data,
                                request_context={},
                                response_context=parsed,
                                session=session,
                            )

                        # Forward
                        try:
                            dst.sendall(data)
                        except Exception:
                            break
                finally:
                    stop_event.set()

            t_c2b = threading.Thread(target=forward, args=(client_sock, backend_sock, "request"), daemon=True)
            t_b2c = threading.Thread(target=forward, args=(backend_sock, client_sock, "response"), daemon=True)
            t_c2b.start()
            t_b2c.start()

            # Block until either direction closes
            stop_event.wait()
            t_c2b.join(timeout=3)
            t_b2c.join(timeout=3)

        except Exception as e:
            print(f"[{self.config.protocol.upper()} Proxy] Connection error from {client_addr}: {e}")
        finally:
            if backend_sock:
                backend_sock.close()
            client_sock.close()
            self.logger.close_session(session_id)
            self._cleanup_session(session_id)

    def _cleanup_session(self, session_id: str):
        """
        Hook for subclasses to clean up session-specific data.
        Override in protocol-specific proxies if needed.
        """
        pass
    
    def _read_response(self, backend_sock: socket.socket, request_context: dict) -> bytes:
        """
        Read response from backend. Override for protocol-specific reading.
        Default: single recv() call.
        """
        return backend_sock.recv(self.config.buffer_size)
    
    def _log_traffic(
        self,
        client_addr: Tuple[str, int],
        request_data: bytes,
        response_data: bytes,
        request_context: dict,
        response_context: dict,
        session: SessionInfo,
    ):
        """Create and write unified log entry.

        Routes whitelisted source IPs to ``whitelist_logger`` so that friendly
        traffic is still recorded but never enters the attack-log pipeline.
        """
        import base64

        src_ip = client_addr[0]
        is_whitelisted = bool(self.whitelist and self.whitelist.is_whitelisted(src_ip))

        entry = LogEntry(
            node_id=self.config.node_id,
            deployment_id=self.config.deployment_id,
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=client_addr[1],
                dst_ip=self.config.backend_host,
                dst_port=self.config.backend_port,
                transport="tcp",
            ),
            protocol=self.get_protocol_info(),
            request=RequestData(
                raw_hex=request_data.hex(),
                raw_base64=base64.b64encode(request_data).decode(),
                size_bytes=len(request_data),
                parsed=request_context,
            ),
            response=ResponseData(
                raw_hex=response_data.hex() if response_data else "",
                raw_base64=base64.b64encode(response_data).decode() if response_data else "",
                size_bytes=len(response_data),
                parsed=response_context,
            ),
            session=session,
        )

        if is_whitelisted:
            entry.metadata["whitelisted"] = True
            target_logger = self.whitelist_logger or self.logger
            target_logger.log(entry)
        else:
            self.logger.log(entry)
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def connection_count(self) -> int:
        with self._lock:
            return self._connection_count
