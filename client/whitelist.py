"""
Whitelist Manager

Loads a JSON file listing IPs/CIDRs that should be treated as "friendly"
traffic. Friendly traffic is still proxied to the honeypot backend, but is
logged to a separate whitelist log file instead of the main attack log so
it does not pollute the attack map / attack log pipeline.

Config file format (client/whitelist.json)::

    {
      "enabled": true,
      "ips": ["1.2.3.4", "203.0.113.7"],
      "cidrs": ["10.0.0.0/8", "192.168.1.0/24"],
      "description": "Optional human-readable note"
    }

Features:
- Hot reload (checks mtime on every lookup; cheap stat call)
- Exact IP match and CIDR match (IPv4 and IPv6)
- Thread-safe
"""

import ipaddress
import json
import os
import threading
from typing import Any, Iterable, List, Optional


class WhitelistManager:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self._lock = threading.Lock()
        self._mtime: float = 0.0
        self._enabled: bool = False
        self._exact_ips: set = set()
        self._networks: List[ipaddress._BaseNetwork] = []
        # Load once at construction so consumers have a valid state.
        self._reload_if_changed()

    # ---------- public API ----------

    def is_whitelisted(self, ip: str) -> bool:
        """Return True if the given IP is on the whitelist."""
        if not ip:
            return False
        self._reload_if_changed()
        with self._lock:
            if not self._enabled:
                return False
            if ip in self._exact_ips:
                return True
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            for net in self._networks:
                try:
                    if addr in net:
                        return True
                except TypeError:
                    # IPv4/IPv6 mismatch, skip
                    continue
            return False

    def snapshot(self) -> dict:
        """Return a copy of the current whitelist state (for debugging/UI)."""
        self._reload_if_changed()
        with self._lock:
            return {
                "enabled": self._enabled,
                "ips": sorted(self._exact_ips),
                "cidrs": [str(n) for n in self._networks],
                "config_path": self.config_path,
                "loaded_mtime": self._mtime,
            }

    def load_from_dict(self, data: Optional[dict]):
        """Replace the in-memory whitelist from a dict (e.g. pushed by server).

        When called, this takes precedence over the on-disk whitelist.json
        until the file mtime advances again. The server pushes whitelist
        updates through the ``/api/config`` response, so this is the normal
        path in production; the local file is a fallback for offline use.
        """
        if data is None:
            return
        enabled = bool(data.get("enabled", True))
        exact_ips = set()
        networks: List[ipaddress._BaseNetwork] = []

        for raw in _as_list(data.get("ips")):
            ip = str(raw).strip()
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
                exact_ips.add(ip)
            except ValueError:
                print(f"[Whitelist] Ignoring invalid IP from server: {ip!r}")

        for raw in _as_list(data.get("cidrs")):
            cidr = str(raw).strip()
            if not cidr:
                continue
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"[Whitelist] Ignoring invalid CIDR from server: {cidr!r}")

        with self._lock:
            changed = (
                enabled != self._enabled
                or exact_ips != self._exact_ips
                or [str(n) for n in networks] != [str(n) for n in self._networks]
            )
            self._enabled = enabled
            self._exact_ips = exact_ips
            self._networks = networks
            # Bump mtime marker so a subsequent file-reload only happens
            # when the local file has *newer* content than what the server
            # just pushed.
            self._mtime = max(self._mtime, 1.0)

        if changed:
            print(
                f"[Whitelist] Updated from server: "
                f"enabled={enabled}, ips={len(exact_ips)}, cidrs={len(networks)}"
            )

    # ---------- internals ----------

    def _reload_if_changed(self):
        try:
            mtime = os.path.getmtime(self.config_path)
        except OSError:
            # File missing — only clear state that was loaded from a local
            # file.  Server-pushed state (set via load_from_dict) marks
            # _mtime=1.0; real file mtimes are large Unix timestamps >> 1.0.
            # Never wipe server-pushed data just because the local file is
            # absent — that is the normal production path.
            with self._lock:
                if self._mtime > 1.0 and (self._enabled or self._exact_ips or self._networks):
                    self._enabled = False
                    self._exact_ips = set()
                    self._networks = []
                    self._mtime = 0.0
            return

        with self._lock:
            if mtime == self._mtime:
                return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[Whitelist] Failed to load {self.config_path}: {e}")
            return

        enabled = bool(data.get("enabled", True))
        exact_ips = set()
        networks: List[ipaddress._BaseNetwork] = []

        for raw in _as_list(data.get("ips")):
            ip = str(raw).strip()
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
                exact_ips.add(ip)
            except ValueError:
                print(f"[Whitelist] Ignoring invalid IP: {ip!r}")

        for raw in _as_list(data.get("cidrs")):
            cidr = str(raw).strip()
            if not cidr:
                continue
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"[Whitelist] Ignoring invalid CIDR: {cidr!r}")

        with self._lock:
            self._enabled = enabled
            self._exact_ips = exact_ips
            self._networks = networks
            self._mtime = mtime

        print(
            f"[Whitelist] Loaded from {self.config_path}: "
            f"enabled={enabled}, ips={len(exact_ips)}, cidrs={len(networks)}"
        )


def _as_list(value) -> Iterable:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
