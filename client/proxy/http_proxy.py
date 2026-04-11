"""
HTTP Proxy
Captures and parses HTTP/1.x traffic with request/response analysis.
"""

import socket
import re
from typing import Tuple, Optional
from urllib.parse import urlparse, parse_qs

from .base_proxy import BaseProxy, ProxyConfig
from .unified_logger import UnifiedLogger, ProtocolInfo


# Common HTTP methods
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}

# Security-relevant headers
SECURITY_HEADERS = {
    "authorization", "cookie", "x-forwarded-for", "x-real-ip", 
    "user-agent", "referer", "origin", "content-type"
}


class HTTPProxy(BaseProxy):
    """
    HTTP/1.x protocol-aware proxy.
    
    Features:
    - Full HTTP request/response parsing
    - Header extraction
    - Query parameter parsing
    - POST body capture
    - Security-relevant header highlighting
    - Content-Type aware body parsing
    
    Example:
        config = ProxyConfig(
            listen_port=80,
            backend_host="127.0.0.1",
            backend_port=8080,
            protocol="http",
            node_id="node-01",
            deployment_id="web-01",
        )
        logger = UnifiedLogger("/var/log/honeypot", "node-01", "web-01")
        proxy = HTTPProxy(config, logger)
        proxy.start()
    """
    
    def __init__(self, config: ProxyConfig, logger: UnifiedLogger, **kwargs):
        super().__init__(config, logger, **kwargs)
        # Max body size to log (prevent memory issues with large uploads)
        self.max_body_log_size = config.extra_config.get("max_body_log_size", 10 * 1024)  # 10KB default
    
    def parse_request(self, data: bytes, session_id: str = "") -> dict:
        """Parse HTTP request"""
        result = {
            "valid": False,
            "raw_length": len(data),
        }
        
        try:
            # Try to decode as UTF-8
            text = data.decode("utf-8", errors="replace")
            
            # Split headers and body
            if "\r\n\r\n" in text:
                header_section, body = text.split("\r\n\r\n", 1)
            elif "\n\n" in text:
                header_section, body = text.split("\n\n", 1)
            else:
                header_section = text
                body = ""
            
            lines = header_section.split("\r\n") if "\r\n" in header_section else header_section.split("\n")
            
            if not lines or not lines[0].strip():
                result["error"] = "Empty request"
                return result
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(" ")
            
            if len(parts) >= 2:
                method = parts[0].upper()
                uri = parts[1]
                http_version = parts[2] if len(parts) >= 3 else "HTTP/1.0"
                
                result["http.method"] = method
                result["http.uri"] = uri
                result["http.version"] = http_version
                
                # Check if method is valid
                result["http.method_valid"] = method in HTTP_METHODS
                
                # Parse URI
                parsed = urlparse(uri)
                result["http.path"] = parsed.path
                result["http.query_string"] = parsed.query
                
                # Parse query parameters
                if parsed.query:
                    try:
                        result["http.query_params"] = parse_qs(parsed.query)
                    except Exception:
                        result["http.query_params_raw"] = parsed.query
            
            # Parse headers
            headers = {}
            security_headers = {}
            
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    headers[key] = value
                    
                    if key in SECURITY_HEADERS:
                        security_headers[key] = value
            
            result["http.headers"] = headers
            result["http.security_headers"] = security_headers
            
            # Extract common headers
            if "host" in headers:
                result["http.host"] = headers["host"]
            if "user-agent" in headers:
                result["http.user_agent"] = headers["user-agent"]
            if "content-type" in headers:
                result["http.content_type"] = headers["content-type"]
            if "content-length" in headers:
                try:
                    result["http.content_length"] = int(headers["content-length"])
                except ValueError:
                    pass
            
            # Parse body (if present and not too large)
            if body:
                body_bytes = body.encode("utf-8", errors="replace")
                result["http.body_length"] = len(body_bytes)
                
                if len(body_bytes) <= self.max_body_log_size:
                    content_type = headers.get("content-type", "")
                    
                    if "application/json" in content_type:
                        result["http.body"] = body
                        try:
                            import json
                            result["http.body_json"] = json.loads(body)
                        except Exception:
                            pass
                    elif "application/x-www-form-urlencoded" in content_type:
                        try:
                            result["http.body_form"] = parse_qs(body)
                        except Exception:
                            result["http.body"] = body
                    else:
                        # Store as-is for text types
                        if any(t in content_type for t in ["text/", "application/xml", "application/javascript"]):
                            result["http.body"] = body
                        else:
                            result["http.body_preview"] = body[:200] if len(body) > 200 else body
                else:
                    result["http.body_truncated"] = True
            
            result["valid"] = True
            
        except Exception as e:
            result["error"] = f"Parse error: {e}"
        
        return result
    
    def parse_response(self, data: bytes, request_context: dict = None) -> dict:
        """Parse HTTP response"""
        result = {
            "valid": False,
            "raw_length": len(data),
        }
        
        if not data:
            result["empty"] = True
            return result
        
        try:
            # Try to decode as UTF-8
            text = data.decode("utf-8", errors="replace")
            
            # Split headers and body
            if "\r\n\r\n" in text:
                header_section, body = text.split("\r\n\r\n", 1)
            elif "\n\n" in text:
                header_section, body = text.split("\n\n", 1)
            else:
                header_section = text
                body = ""
            
            lines = header_section.split("\r\n") if "\r\n" in header_section else header_section.split("\n")
            
            if not lines:
                result["error"] = "Empty response"
                return result
            
            # Parse status line
            status_line = lines[0]
            parts = status_line.split(" ", 2)
            
            if len(parts) >= 2:
                http_version = parts[0]
                status_code = parts[1]
                status_text = parts[2] if len(parts) >= 3 else ""
                
                result["http.version"] = http_version
                try:
                    result["http.status_code"] = int(status_code)
                except ValueError:
                    result["http.status_code_raw"] = status_code
                result["http.status_text"] = status_text
                
                # Categorize status
                try:
                    code = int(status_code)
                    if 100 <= code < 200:
                        result["http.status_category"] = "informational"
                    elif 200 <= code < 300:
                        result["http.status_category"] = "success"
                    elif 300 <= code < 400:
                        result["http.status_category"] = "redirect"
                    elif 400 <= code < 500:
                        result["http.status_category"] = "client_error"
                    elif 500 <= code < 600:
                        result["http.status_category"] = "server_error"
                except ValueError:
                    pass
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            
            result["http.headers"] = headers
            
            # Extract important headers
            if "content-type" in headers:
                result["http.content_type"] = headers["content-type"]
            if "content-length" in headers:
                try:
                    result["http.content_length"] = int(headers["content-length"])
                except ValueError:
                    pass
            if "server" in headers:
                result["http.server"] = headers["server"]
            
            # Body info
            if body:
                result["http.body_length"] = len(body.encode("utf-8", errors="replace"))
                # Don't log full response body for privacy/size reasons
                result["http.has_body"] = True
            
            result["valid"] = True
            
        except Exception as e:
            result["error"] = f"Parse error: {e}"
        
        return result
    
    def get_protocol_info(self) -> ProtocolInfo:
        """Return HTTP protocol info"""
        return ProtocolInfo(
            name="http",
            layer="application",
            version="1.1",
        )
    
    def _read_response(self, backend_sock: socket.socket, request_context: dict) -> bytes:
        """
        Read complete HTTP response.
        HTTP responses can be chunked or have Content-Length.
        """
        response = b""
        
        # First, read headers
        while b"\r\n\r\n" not in response and b"\n\n" not in response:
            chunk = backend_sock.recv(self.config.buffer_size)
            if not chunk:
                return response
            response += chunk
            
            # Safety limit for headers
            if len(response) > 64 * 1024:  # 64KB max headers
                break
        
        # Find header/body boundary
        if b"\r\n\r\n" in response:
            header_end = response.index(b"\r\n\r\n") + 4
        elif b"\n\n" in response:
            header_end = response.index(b"\n\n") + 2
        else:
            return response
        
        headers_text = response[:header_end].decode("utf-8", errors="replace").lower()
        
        # Check for Content-Length
        content_length = None
        for line in headers_text.split("\n"):
            if line.startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
                break
        
        # Check for chunked transfer encoding
        is_chunked = "transfer-encoding: chunked" in headers_text
        
        if content_length is not None:
            # Read exact content length
            body_received = len(response) - header_end
            while body_received < content_length:
                remaining = content_length - body_received
                chunk = backend_sock.recv(min(remaining, self.config.buffer_size))
                if not chunk:
                    break
                response += chunk
                body_received += len(chunk)
                
        elif is_chunked:
            # Read chunked response (simplified - read until connection close or zero chunk)
            # This is a simplified implementation
            max_body = 1024 * 1024  # 1MB max
            while len(response) - header_end < max_body:
                try:
                    chunk = backend_sock.recv(self.config.buffer_size)
                    if not chunk:
                        break
                    response += chunk
                    # Check for end of chunked response (0\r\n\r\n)
                    if b"0\r\n\r\n" in response[header_end:]:
                        break
                except socket.timeout:
                    break
        else:
            # No Content-Length, no chunked - read with timeout
            # Common for HTTP/1.0 or connection: close
            backend_sock.settimeout(1.0)
            try:
                while True:
                    chunk = backend_sock.recv(self.config.buffer_size)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            finally:
                backend_sock.settimeout(self.config.timeout)
        
        # IMPORTANT: Replace Connection header to prevent client keep-alive issues
        # Since proxy closes connection after each request, we must tell the client
        response = self._rewrite_response_headers(response)
        
        return response
    
    def _rewrite_response_headers(self, response: bytes) -> bytes:
        """
        Rewrite HTTP response headers to fix compatibility issues.
        - Force Connection: close since proxy only handles one request per connection
        - Removes existing Connection and Transfer-Encoding headers
        """
        # Find header/body boundary
        if b"\r\n\r\n" in response:
            header_end = response.index(b"\r\n\r\n")
            delimiter = b"\r\n\r\n"
            line_ending = b"\r\n"
        elif b"\n\n" in response:
            header_end = response.index(b"\n\n")
            delimiter = b"\n\n"
            line_ending = b"\n"
        else:
            return response  # No headers found, return as-is
        
        headers_bytes = response[:header_end]
        body = response[header_end + len(delimiter):]
        
        # Split by line ending
        lines = headers_bytes.split(line_ending)
        new_lines = []
        
        for i, line in enumerate(lines):
            # Always keep the status line (first line)
            if i == 0:
                new_lines.append(line)
                continue
            
            line_str = line.decode("utf-8", errors="replace")
            line_str_lower = line_str.lower()
            
            # Skip connection and transfer-encoding headers
            if line_str_lower.startswith("connection:") or line_str_lower.startswith("transfer-encoding:"):
                continue
            
            new_lines.append(line)
        
        # Add Connection: close
        new_lines.append(b"Connection: close")
        
        # Reconstruct headers with proper line endings
        new_headers_bytes = line_ending.join(new_lines)
        
        # Reconstruct response
        return new_headers_bytes + delimiter + body
