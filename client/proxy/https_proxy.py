"""
HTTPS Proxy
Terminates TLS on the proxy, parses the decrypted HTTP/1.x traffic, and
forwards plain HTTP to the backend honeypot service.
"""

import os
import socket
import ssl
import subprocess
import threading
from pathlib import Path
from typing import Tuple

from .http_proxy import HTTPProxy
from .base_proxy import ProxyConfig
from .unified_logger import UnifiedLogger, ProtocolInfo


class HTTPSProxy(HTTPProxy):
    """
    TLS-terminating HTTP proxy.

    The client connects with HTTPS to ``listen_port``.  The proxy presents a
    certificate, decrypts the HTTP request, logs it with the same parser used
    by HTTPProxy, then forwards plain HTTP to ``backend_host:backend_port``.

    extra_config:
      - cert_file: optional certificate path
      - key_file: optional private key path
      - cert_common_name: CN used when auto-generating a self-signed cert
      - auto_generate_cert: default true
    """

    def __init__(self, config: ProxyConfig, logger: UnifiedLogger, **kwargs):
        super().__init__(config, logger, **kwargs)
        self._tls_session_info = {}
        self.cert_file, self.key_file = self._resolve_cert_paths()
        self._ensure_certificate()
        self._ssl_context = self._build_ssl_context()

    def get_protocol_info(self) -> ProtocolInfo:
        return ProtocolInfo(
            name="https",
            layer="application",
            version="1.1",
        )

    def parse_request(self, data: bytes, session_id: str = "") -> dict:
        parsed = super().parse_request(data, session_id)
        tls_info = self._tls_session_info.get(session_id)
        if tls_info:
            parsed["tls"] = tls_info
            parsed["http.scheme"] = "https"
        return parsed

    def _run_server(self):
        """Accept TCP clients, complete TLS handshake, then use HTTP handling."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.config.listen_host, self.config.listen_port))
            self._server_socket.listen(self.config.max_connections)
            self._server_socket.settimeout(1.0)

            while self._running:
                try:
                    raw_client_sock, client_addr = self._server_socket.accept()

                    with self._lock:
                        self._connection_count += 1
                        session_id = f"{client_addr[0]}:{client_addr[1]}-{self._connection_count}"

                    try:
                        client_sock = self._ssl_context.wrap_socket(raw_client_sock, server_side=True)
                        self._tls_session_info[session_id] = {
                            "version": client_sock.version(),
                            "cipher": client_sock.cipher()[0] if client_sock.cipher() else "",
                            "sni": getattr(client_sock, "_honeypot_sni", ""),
                            "terminated": True,
                        }
                    except ssl.SSLError as exc:
                        print(f"[HTTPS Proxy] TLS handshake failed from {client_addr}: {exc}")
                        raw_client_sock.close()
                        continue

                    handler = threading.Thread(
                        target=self._handle_connection,
                        args=(client_sock, client_addr, session_id),
                        daemon=True,
                    )
                    handler.start()

                    with self._lock:
                        self._connections = [t for t in self._connections if t.is_alive()]
                        self._connections.append(handler)

                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        raise
                    break

        except Exception as e:
            print(f"[HTTPS Proxy] Server error: {e}")
        finally:
            if self._server_socket:
                self._server_socket.close()

    def _cleanup_session(self, session_id: str):
        self._tls_session_info.pop(session_id, None)
        super()._cleanup_session(session_id)

    def _resolve_cert_paths(self) -> Tuple[str, str]:
        extra = self.config.extra_config or {}
        cert_file = extra.get("cert_file") or extra.get("tls_cert_file")
        key_file = extra.get("key_file") or extra.get("tls_key_file")

        default_dir = Path(__file__).resolve().parents[1] / "certs"
        if not cert_file:
            cert_file = default_dir / "honeypot-https.crt"
        if not key_file:
            key_file = default_dir / "honeypot-https.key"

        return str(self._resolve_path(cert_file)), str(self._resolve_path(key_file))

    def _resolve_path(self, path_value) -> Path:
        path = Path(str(path_value)).expanduser()
        if path.is_absolute():
            return path
        return (Path(__file__).resolve().parents[1] / path).resolve()

    def _ensure_certificate(self):
        extra = self.config.extra_config or {}
        auto_generate = extra.get("auto_generate_cert", True)
        if os.path.exists(self.cert_file) and os.path.exists(self.key_file):
            return
        if not auto_generate:
            raise FileNotFoundError(
                f"HTTPS cert/key not found: cert_file={self.cert_file}, key_file={self.key_file}"
            )

        os.makedirs(os.path.dirname(self.cert_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.key_file), exist_ok=True)

        common_name = str(extra.get("cert_common_name") or "ICS-Honeypot HTTPS Proxy")
        san = str(extra.get("cert_subject_alt_name") or "DNS:localhost,IP:127.0.0.1")
        cmd = [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            self.key_file,
            "-out",
            self.cert_file,
            "-days",
            str(int(extra.get("cert_days", 365))),
            "-subj",
            f"/CN={common_name}",
            "-addext",
            f"subjectAltName={san}",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            os.chmod(self.key_file, 0o600)
            print(f"[HTTPS Proxy] Generated self-signed certificate: {self.cert_file}")
        except FileNotFoundError as exc:
            raise RuntimeError("openssl is required to auto-generate HTTPS proxy certificates") from exc
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            raise RuntimeError(f"Failed to generate HTTPS proxy certificate: {detail}") from exc

    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        context.set_alpn_protocols(["http/1.1"])

        def _capture_sni(sock, server_name, _context):
            try:
                sock._honeypot_sni = server_name or ""
            except Exception:
                pass

        context.sni_callback = _capture_sni
        return context
