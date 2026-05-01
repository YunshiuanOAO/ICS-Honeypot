"""
Generate honeypot deployment packages from a single JSON configuration.

Given a protocol selector and a user-supplied JSON file, this module produces a
self-contained set of files (Dockerfile, docker-compose.yml, simulator script,
config.json, README) that can be saved into the package library and deployed
exactly like a manually authored package.

Supported protocols:
- "modbus": TCP Modbus server backed by register banks defined in the JSON
- "mqtt":   MQTT broker + Python simulator that does request/response lookup
            and optional periodic reporting (matches the streetlight format
            with command_response_map / drd10_data)
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List


SUPPORTED_PROTOCOLS = ("modbus", "mqtt")


class PackageGenerationError(ValueError):
    """Raised when the user-supplied JSON or protocol is invalid."""


def _slug(text: str, fallback: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")
    return cleaned or fallback


def generate_package(
    protocol: str,
    config_data: Dict[str, Any],
    name: str,
) -> Dict[str, Any]:
    """
    Build a deployable package from a JSON config.

    Returns a dict shaped like:
        {
            "source_dir": "<slug>",
            "files":      [{"path": "...", "content": "..."}],
            "protocol":   "<protocol>",
        }

    Caller is expected to feed the result into the existing
    `_save_package_to_library()` helper in main.py.
    """
    proto = (protocol or "").strip().lower()
    if proto not in SUPPORTED_PROTOCOLS:
        raise PackageGenerationError(
            f"Unsupported protocol '{protocol}'. Choose one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        )

    if not isinstance(config_data, dict):
        raise PackageGenerationError("Config JSON must be an object at the top level.")

    pkg_name = (name or "").strip() or f"{proto}-from-json"
    source_dir = _slug(pkg_name, fallback=f"{proto}-package")

    if proto == "modbus":
        files = _build_modbus_files(config_data)
    else:
        files = _build_mqtt_files(config_data)

    return {
        "source_dir": source_dir,
        "files": files,
        "protocol": proto,
    }


# ---------------------------------------------------------------------------
# Modbus generator
# ---------------------------------------------------------------------------

def _build_modbus_files(cfg: Dict[str, Any]) -> List[Dict[str, str]]:
    listen_port = int(cfg.get("listen_port") or 5020)
    host_port = int(cfg.get("host_port") or 5020)

    config_json = json.dumps(cfg, indent=2, ensure_ascii=False)

    return [
        {"path": "config.json", "content": config_json},
        {"path": "Dockerfile", "content": _MODBUS_DOCKERFILE},
        {"path": "requirements.txt", "content": "pymodbus==3.6.6\n"},
        {
            "path": "docker-compose.yml",
            "content": _modbus_compose(host_port=host_port, listen_port=listen_port),
        },
        {"path": "simulator.py", "content": _MODBUS_SIMULATOR},
        {"path": "README.md", "content": _MODBUS_README},
    ]


def _modbus_compose(host_port: int, listen_port: int) -> str:
    return f"""version: "3.8"

services:
  modbus-sim:
    build: .
    container_name: modbus-sim
    restart: unless-stopped
    ports:
      - "{host_port}:{listen_port}"
    volumes:
      - ./logs:/app/logs
    environment:
      - MODBUS_PORT={listen_port}
      - PYTHONUNBUFFERED=1
"""


_MODBUS_DOCKERFILE = """FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulator.py config.json ./
RUN mkdir -p /app/logs

EXPOSE 5020

CMD ["python", "simulator.py"]
"""


_MODBUS_SIMULATOR = '''"""
JSON-driven Modbus TCP simulator.

Reads register banks from config.json and exposes them as a Modbus TCP slave.

Expected config.json shape (all keys optional except at least one bank):

    {
      "device_id": 1,
      "listen_port": 5020,
      "holding_registers": {"0": 123, "1": 456, "100": 789},
      "input_registers":   {"0": 50},
      "coils":             {"0": true, "1": false},
      "discrete_inputs":   {"0": true}
    }

Address keys may be int or string. Values are clipped to 16-bit unsigned for
register banks and coerced to bool for coil banks.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartTcpServer

LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "modbus-sim.log"),
    ],
)
log = logging.getLogger("modbus-sim")


def _load_config() -> dict:
    cfg_path = Path(__file__).with_name("config.json")
    with cfg_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _bank_to_block(entries, *, bool_bank: bool) -> ModbusSequentialDataBlock:
    if not entries:
        # Empty block — pymodbus needs a non-zero size to answer reads cleanly.
        return ModbusSequentialDataBlock(0, [0] * 16)

    if isinstance(entries, list):
        items = list(enumerate(entries))
    elif isinstance(entries, dict):
        items = []
        for key, value in entries.items():
            try:
                addr = int(key)
            except (TypeError, ValueError):
                log.warning("skipping non-integer address %r", key)
                continue
            items.append((addr, value))
    else:
        log.warning("unexpected bank type %s, skipping", type(entries).__name__)
        return ModbusSequentialDataBlock(0, [0] * 16)

    if not items:
        return ModbusSequentialDataBlock(0, [0] * 16)

    items.sort(key=lambda pair: pair[0])
    base = items[0][0]
    end = items[-1][0]
    size = max(end - base + 1, 1)
    if bool_bank:
        values = [False] * size
        for addr, value in items:
            values[addr - base] = bool(value)
    else:
        values = [0] * size
        for addr, value in items:
            try:
                values[addr - base] = int(value) & 0xFFFF
            except (TypeError, ValueError):
                log.warning("skipping non-integer value at %d: %r", addr, value)

    return ModbusSequentialDataBlock(base, values)


def main() -> None:
    cfg = _load_config()

    device_id = int(cfg.get("device_id") or 1)
    listen_port = int(os.environ.get("MODBUS_PORT") or cfg.get("listen_port") or 5020)

    slave = ModbusSlaveContext(
        di=_bank_to_block(cfg.get("discrete_inputs"), bool_bank=True),
        co=_bank_to_block(cfg.get("coils"), bool_bank=True),
        hr=_bank_to_block(cfg.get("holding_registers"), bool_bank=False),
        ir=_bank_to_block(cfg.get("input_registers"), bool_bank=False),
        zero_mode=True,
    )
    context = ModbusServerContext(slaves={device_id: slave}, single=False)

    identity = ModbusDeviceIdentification()
    identity.VendorName = cfg.get("vendor_name") or "ICS-Honeypot"
    identity.ProductCode = cfg.get("product_code") or "HP"
    identity.ProductName = cfg.get("product_name") or "JSON Modbus Simulator"
    identity.ModelName = cfg.get("model_name") or "JSON-MODBUS-1"
    identity.MajorMinorRevision = "1.0"

    log.info("starting modbus tcp simulator on 0.0.0.0:%d (slave %d)", listen_port, device_id)
    StartTcpServer(context=context, identity=identity, address=("0.0.0.0", listen_port))


if __name__ == "__main__":
    main()
'''


_MODBUS_README = """# JSON-driven Modbus simulator

Generated from a JSON config. Edit `config.json` to change exposed registers,
then redeploy.

## Config schema

```json
{
  "device_id": 1,
  "listen_port": 5020,
  "holding_registers": {"0": 123, "1": 456},
  "input_registers":   {"0": 50},
  "coils":             {"0": true},
  "discrete_inputs":   {"0": true}
}
```

All bank keys are optional. Unspecified banks return zeros.

## Test from the host

```
pip install pymodbus
python -c "from pymodbus.client import ModbusTcpClient; \\
  c = ModbusTcpClient('127.0.0.1', port=5020); c.connect(); \\
  print(c.read_holding_registers(0, 4, slave=1).registers)"
```
"""


# ---------------------------------------------------------------------------
# MQTT generator
# ---------------------------------------------------------------------------

def _build_mqtt_files(cfg: Dict[str, Any]) -> List[Dict[str, str]]:
    broker_port = int(cfg.get("broker_port") or 1883)
    host_port = int(cfg.get("host_port") or broker_port)

    config_json = json.dumps(cfg, indent=2, ensure_ascii=False)

    return [
        {"path": "config.json", "content": config_json},
        {"path": "simulator/Dockerfile", "content": _MQTT_SIM_DOCKERFILE},
        {"path": "simulator/requirements.txt", "content": "paho-mqtt==1.6.1\n"},
        {"path": "simulator/simulator.py", "content": _MQTT_SIMULATOR},
        {"path": "mosquitto/config/mosquitto.conf", "content": _MOSQUITTO_CONF},
        {
            "path": "docker-compose.yml",
            "content": _mqtt_compose(host_port=host_port, broker_port=broker_port),
        },
        {"path": "README.md", "content": _MQTT_README},
    ]


def _mqtt_compose(host_port: int, broker_port: int) -> str:
    return f"""version: "3.8"

services:
  mqtt-broker:
    image: eclipse-mosquitto:2
    container_name: mqtt-broker
    restart: unless-stopped
    ports:
      - "{host_port}:{broker_port}"
    volumes:
      - ./mosquitto/config:/mosquitto/config
      - ./logs/mosquitto:/mosquitto/log

  simulator:
    build: ./simulator
    container_name: mqtt-simulator
    restart: unless-stopped
    depends_on:
      - mqtt-broker
    volumes:
      - ./config.json:/app/config.json:ro
      - ./logs:/app/logs
    environment:
      - MQTT_BROKER_HOST=mqtt-broker
      - MQTT_BROKER_PORT={broker_port}
      - PYTHONUNBUFFERED=1
"""


_MOSQUITTO_CONF = """listener 1883
allow_anonymous true
persistence false
log_dest stdout
"""


_MQTT_SIM_DOCKERFILE = """FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulator.py .
RUN mkdir -p /app/logs

CMD ["python", "simulator.py"]
"""


_MQTT_SIMULATOR = '''"""
JSON-driven MQTT simulator.

Reads config.json and runs two behaviours against an MQTT broker:

1. Request/response lookup. Subscribes to a command topic; when a message
   arrives, hex-encodes its payload and looks it up in
   `command_response_map`. If found, the corresponding hex string is decoded
   and published to a response topic.

2. Periodic reporting. Every `report_interval_sec` seconds, publishes each
   entry of `drd10_data` (mac -> hex bytes) to the report topic.

Topic templates support `{mac}` substitution. Defaults match the streetlight
example shipped with this simulator.

Expected config.json fields (all optional unless your data depends on them):

    {
      "command_topic":  "streetlight/+/cmd",
      "response_topic": "streetlight/{mac}/rsp",
      "report_topic":   "streetlight/{mac}/report",
      "report_interval_sec": 60,
      "command_response_map": {"<hex_req>": "<hex_rsp>"},
      "drd10_data":           {"<mac>": "<hex_bytes>"}
    }
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt

LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "mqtt-sim.log"),
    ],
)
log = logging.getLogger("mqtt-sim")


def _load_config() -> dict:
    with Path("/app/config.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _normalize_map(raw: dict) -> dict:
    """Return {lowercase_hex_request: hex_response} with non-hex chars stripped."""
    out = {}
    for key, value in (raw or {}).items():
        k = re.sub(r"[^0-9a-fA-F]", "", str(key)).lower()
        v = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower()
        if k and v:
            out[k] = v
    return out


def _topic_to_regex(template: str) -> re.Pattern:
    """Convert an MQTT topic filter (with + / # / {mac}) to a regex with named groups."""
    pattern = re.escape(template)
    pattern = pattern.replace(re.escape("{mac}"), r"(?P<mac>[^/]+)")
    pattern = pattern.replace(re.escape("+"), r"[^/]+")
    pattern = pattern.replace(re.escape("#"), r".*")
    return re.compile(f"^{pattern}$")


class Simulator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.cmd_topic = cfg.get("command_topic") or "streetlight/+/cmd"
        self.rsp_topic = cfg.get("response_topic") or "streetlight/{mac}/rsp"
        self.report_topic = cfg.get("report_topic") or "streetlight/{mac}/report"
        self.report_interval = int(cfg.get("report_interval_sec") or 60)
        self.cmd_regex = _topic_to_regex(self.cmd_topic)
        self.response_map = _normalize_map(cfg.get("command_response_map") or {})
        self.drd10_data = {
            mac.upper(): re.sub(r"[^0-9a-fA-F]", "", str(hex_data)).lower()
            for mac, hex_data in (cfg.get("drd10_data") or {}).items()
        }

        self.client = mqtt.Client(client_id=cfg.get("client_id") or "json-simulator")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        username = cfg.get("username")
        password = cfg.get("password")
        if username:
            self.client.username_pw_set(username, password)

    def _format_topic(self, template: str, mac: str) -> str:
        return template.replace("{mac}", mac)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            log.info("connected to broker, subscribing to %s", self.cmd_topic)
            client.subscribe(self.cmd_topic)
        else:
            log.error("connect failed rc=%s", rc)

    def _on_message(self, client, userdata, msg):
        payload_hex = msg.payload.hex().lower()
        log.info("rx topic=%s payload=%s", msg.topic, payload_hex)

        match = self.cmd_regex.match(msg.topic)
        mac = (match.group("mac") if match and "mac" in match.groupdict() else "unknown")

        rsp_hex = self.response_map.get(payload_hex)
        if not rsp_hex:
            log.info("no canned response for %s", payload_hex)
            return

        try:
            rsp_bytes = bytes.fromhex(rsp_hex)
        except ValueError:
            log.error("response for %s is not valid hex: %s", payload_hex, rsp_hex)
            return

        topic = self._format_topic(self.rsp_topic, mac)
        client.publish(topic, rsp_bytes)
        log.info("tx topic=%s payload=%s", topic, rsp_hex)

    def _periodic_report(self):
        if not self.drd10_data or self.report_interval <= 0:
            return
        while True:
            time.sleep(self.report_interval)
            for mac, hex_data in self.drd10_data.items():
                try:
                    payload = bytes.fromhex(hex_data)
                except ValueError:
                    log.error("drd10_data for %s is not valid hex", mac)
                    continue
                topic = self._format_topic(self.report_topic, mac)
                self.client.publish(topic, payload)
                log.info("periodic tx topic=%s payload=%s", topic, hex_data)

    def run(self):
        host = os.environ.get("MQTT_BROKER_HOST") or self.cfg.get("broker_host") or "mqtt-broker"
        port = int(os.environ.get("MQTT_BROKER_PORT") or self.cfg.get("broker_port") or 1883)

        log.info("connecting to %s:%d", host, port)
        # Retry loop — broker may not be up yet when this container starts.
        while True:
            try:
                self.client.connect(host, port, keepalive=60)
                break
            except Exception as exc:
                log.warning("broker not reachable (%s) — retrying in 3s", exc)
                time.sleep(3)

        threading.Thread(target=self._periodic_report, daemon=True).start()
        self.client.loop_forever()


if __name__ == "__main__":
    Simulator(_load_config()).run()
'''


_MQTT_README = """# JSON-driven MQTT simulator

Generated from a JSON config. Spins up a Mosquitto broker plus a Python
simulator that does request/response lookup and periodic reporting.

## Config schema

```json
{
  "command_topic":  "streetlight/+/cmd",
  "response_topic": "streetlight/{mac}/rsp",
  "report_topic":   "streetlight/{mac}/report",
  "report_interval_sec": 60,
  "command_response_map": {"<hex_req>": "<hex_rsp>"},
  "drd10_data":           {"<mac>": "<hex_bytes>"}
}
```

The simulator hex-encodes incoming MQTT payloads and looks them up in
`command_response_map`; if matched, the response hex is decoded and published
to the response topic. `{mac}` in topic templates is substituted from the
incoming command topic via the `+` wildcard segment.

Streetlight metadata fields (`streetlights`, `cmd_names`, `commands`) in the
JSON are ignored by the simulator — they're documentation for humans.

## Test from the host

```
mosquitto_pub -h 127.0.0.1 -p 1883 -t streetlight/123456789A/cmd \\
  -m "$(printf '\\x02\\x0bR\\x12\\x34\\x56\\x78\\x9a\\x012@')"
mosquitto_sub -h 127.0.0.1 -p 1883 -t 'streetlight/#' -v
```
"""
