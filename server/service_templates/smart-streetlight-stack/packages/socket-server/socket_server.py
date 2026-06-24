"""
TCP Management Server (VM-B)

對 gateway 的「對等雙通道」TCP：兩邊各 listen + 互相 dial。
- 下行：server **dial** GATEWAYS 列表裡每一台 gateway 的 listen port，送 `ROLE manager\n`，
        之後 server 在這條 socket 寫入 hex 指令；gateway 端只『讀』。
- 上行 UPSTREAM_PORT (預設 15567): server **listen**；gateway 主動連入，送 `ROLE gateway\n`，
        之後 gateway 寫 hex 回包；server 只『讀』，解析後寫入 MongoDB 並轉發到 subscriber UI。

對 subscriber 的 Bridge 通道（server listen，subscriber dial）：
- BRIDGE_PORT (預設 15568): subscriber → server 指令橋
  subscriber 維持長連線，先送 `ROLE bridge\n`，之後一行一筆 hex 指令；
  server 收到後寫 `command_logs(destination=gateway, source=subscriber/...)` 沿下行通道下發給
  每一台 gateway，並回寫一行 `OK <gateway_count>` 或 `ERR <reason>`。

本服務完全沒有 HTTP — 所有對外/對內通訊都走 TCP line protocol，跟 gateway 那邊一致。

MQTT 路徑與本檔案無關；MQTT 流量由 mosquitto + gateway/subscriber 自己處理，這裡完全不碰。
"""

import json
import os
import socket
import socketserver
import threading
import time
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
except ImportError:  # pymongo 未安裝時走降級模式（不寫 DB，仍能轉發）
    MongoClient = None
    PyMongoError = Exception


TCP_HOST = os.environ.get("TCP_HOST", "0.0.0.0")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "15567"))
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "15568"))

# 下行：server dial 每一台 gateway。GATEWAYS 是 "host:port,host:port" 形式。
_GATEWAYS_RAW = os.environ.get("GATEWAYS", "").strip()


def _parse_gateways(raw):
    targets = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" in token:
            host, port = token.rsplit(":", 1)
            targets.append((host.strip(), int(port)))
        else:
            targets.append((token, 15566))
    return targets


GATEWAYS = _parse_gateways(_GATEWAYS_RAW)
SUBSCRIBER_API_URL = os.environ.get("SUBSCRIBER_API_URL", "").strip()
API_TOKEN = os.environ.get("API_TOKEN", "").strip()
SUBSCRIBER_API_TOKEN = os.environ.get("SUBSCRIBER_API_TOKEN", API_TOKEN).strip()

MONGO_URI = os.environ.get("MONGO_URI", "").strip()
MONGO_DB = os.environ.get("MONGO_DB", "streetlight").strip()

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "streetlight_data.json")
CMD_NAMES = {}
if os.path.exists(DATA_PATH):
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            CMD_NAMES = json.load(f).get("cmd_names", {})
    except (OSError, ValueError) as e:
        print(f"[TCPManagement] 讀取 streetlight_data.json 失敗: {e}")

_downstream_clients_lock = threading.Lock()


def _enable_tcp_keepalive(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    for opt_name, value in (
        ("TCP_KEEPIDLE", 30),
        ("TCP_KEEPINTVL", 10),
        ("TCP_KEEPCNT", 3),
        ("TCP_USER_TIMEOUT", 30_000),
    ):
        opt = getattr(socket, opt_name, None)
        if opt is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt, value)
        except OSError:
            pass


def is_hex_payload(value):
    return isinstance(value, str) and value.strip() and all(ch in "0123456789abcdefABCDEF" for ch in value.strip())


def parse_meta(hex_data):
    cmd_byte = hex_data[4:6].lower() if len(hex_data) >= 6 else ""
    cmd_name = CMD_NAMES.get(cmd_byte, f"Unknown(0x{cmd_byte})") if cmd_byte else "Unknown"
    mac = None
    if len(hex_data) >= 16 and not hex_data[6:16].startswith("4081"):
        mac = hex_data[6:16].upper()
    return cmd_byte, cmd_name, mac


# ---------- MongoDB ----------

class MongoStore:
    def __init__(self, uri, db_name):
        self.uri = uri
        self.db_name = db_name
        self.client = None
        self.db = None
        self._lock = threading.Lock()
        self._last_attempt = 0.0
        self._retry_interval = float(os.environ.get("MONGO_RETRY_INTERVAL", "5"))
        self._connect()

    def _connect(self):
        if not self.uri or MongoClient is None:
            return False
        now = time.monotonic()
        if self.db is not None:
            return True
        if now - self._last_attempt < self._retry_interval:
            return False
        self._last_attempt = now
        try:
            with self._lock:
                if self.db is not None:
                    return True
                client = MongoClient(self.uri, serverSelectionTimeoutMS=3000)
                client.admin.command("ping")
                db = client[self.db_name]
                db["command_logs"].create_index("ts")
                db["command_logs"].create_index("mac")
                db["runtime"].create_index("mac", unique=True)
                self.client = client
                self.db = db
            print(f"[TCPManagement] [MongoDB] 已連線 {self.uri} db={self.db_name}")
            return True
        except (PyMongoError, OSError) as e:
            print(f"[TCPManagement] [MongoDB] 連線失敗 {self.uri}: {e}")
            if self.client is not None:
                try:
                    self.client.close()
                except Exception:
                    pass
            self.client = None
            self.db = None
            return False

    def enabled(self):
        if self.db is None:
            self._connect()
        return self.db is not None

    def insert_command_log(self, doc):
        if not self.enabled():
            return
        try:
            with self._lock:
                self.db["command_logs"].insert_one(doc)
        except PyMongoError as e:
            print(f"[TCPManagement] [MongoDB] command_logs 寫入失敗: {e}")

    def upsert_runtime(self, mac, doc):
        if not self.enabled() or not mac:
            return
        try:
            with self._lock:
                self.db["runtime"].update_one(
                    {"mac": mac},
                    {"$set": doc},
                    upsert=True,
                )
        except PyMongoError as e:
            print(f"[TCPManagement] [MongoDB] runtime 寫入失敗: {e}")



mongo_store = MongoStore(MONGO_URI, MONGO_DB)


# ---------- Subscriber forwarding ----------

def forward_to_subscriber(hex_data, source):
    if not SUBSCRIBER_API_URL:
        return False

    body = json.dumps(
        {
            "data": hex_data,
            "source": source,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if SUBSCRIBER_API_TOKEN:
        headers["Authorization"] = f"Bearer {SUBSCRIBER_API_TOKEN}"

    req = urlrequest.Request(SUBSCRIBER_API_URL, data=body, headers=headers, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            if 200 <= resp.status < 300:
                return True
            print(f"[TCPManagement] [API] 轉送 subscriber 失敗 {SUBSCRIBER_API_URL}: HTTP {resp.status}")
            return False
    except (HTTPError, URLError, TimeoutError, OSError) as e:
        print(f"[TCPManagement] [API] 轉送 subscriber 失敗 {SUBSCRIBER_API_URL}: {e}")
        return False


# ---------- Downstream (server → gateway) ----------

# {(host, port): socket} — 每台 gateway 一條長連線，由 _downstream_dialer_loop 維護。
_downstream_sockets = {}


def send_to_gateways(hex_data):
    """把 hex 指令推到所有已 dial 起來的 gateway。回傳成功送達的台數。"""
    payload = f"{hex_data}\n".encode("utf-8")
    with _downstream_clients_lock:
        targets = list(_downstream_sockets.items())

    sent = 0
    dead = []
    for key, conn in targets:
        try:
            conn.sendall(payload)
            sent += 1
        except OSError:
            dead.append(key)

    if dead:
        with _downstream_clients_lock:
            for key in dead:
                conn = _downstream_sockets.pop(key, None)
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass

    return sent


def _downstream_dialer_loop(host, port):
    """對單一 gateway 維持長連線：dial 進去後送 `ROLE manager\\n`，再保留 socket 給
    send_to_gateways 寫入；read-loop 偵測 EOF。對端關閉/網路中斷 → 3 秒後重 dial。"""
    key = (host, port)
    while True:
        sock = None
        try:
            print(f"[TCPManagement] [DOWN] dial {host}:{port}...")
            sock = socket.create_connection((host, port), timeout=10)
            sock.settimeout(None)
            _enable_tcp_keepalive(sock)
            sock.sendall(b"ROLE manager\n")
            with _downstream_clients_lock:
                old = _downstream_sockets.get(key)
                _downstream_sockets[key] = sock
            if old is not None:
                try:
                    old.close()
                except OSError:
                    pass
            print(f"[TCPManagement] [DOWN] 已連線 gateway {host}:{port} (現有 {len(_downstream_sockets)})")

            file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
            for line in file_obj:
                stripped = line.strip()
                if stripped:
                    print(f"[TCPManagement] [DOWN] 略過 gateway 在下行通道送出的資料: {stripped}")
        except OSError as e:
            print(f"[TCPManagement] [DOWN] 等待 gateway {host}:{port}... ({e})")
        finally:
            with _downstream_clients_lock:
                if _downstream_sockets.get(key) is sock:
                    _downstream_sockets.pop(key, None)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            time.sleep(3)


def _downstream_heartbeat_loop():
    """每 30 秒對每一條已連起來的下行通道送空白行，維持 NAT conntrack 不被砍。"""
    while True:
        time.sleep(30)
        with _downstream_clients_lock:
            conns = list(_downstream_sockets.values())
        for conn in conns:
            try:
                conn.sendall(b"\n")
            except OSError:
                pass


# ---------- Upstream (gateway → server) ----------

def handle_upstream_line(hex_data):
    cmd_byte, cmd_name, mac = parse_meta(hex_data)
    print(f"[TCPManagement] [UP] 收到 Gateway: {cmd_name} Hex: {hex_data}")

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")

    mongo_store.insert_command_log(
        {
            "ts": now_iso,
            "destination": "server",
            "source": "gateway",
            "hex_data": hex_data,
            "command": cmd_name,
            "cmd_byte": cmd_byte,
            "mac": mac,
        }
    )

    if mac:
        runtime_doc = {
            "mac": mac,
            "last_hex": hex_data,
            "last_command": cmd_name,
            "last_cmd_byte": cmd_byte,
            "updated_at": now_iso,
        }
        if cmd_byte == "80":
            runtime_doc["last_drd10_hex"] = hex_data
            runtime_doc["last_drd10_at"] = now_iso
        mongo_store.upsert_runtime(mac, runtime_doc)

    if forward_to_subscriber(hex_data, source="gateway"):
        print("[TCPManagement] [UP] 已轉送到 subscriber")


class UpstreamHandler(socketserver.BaseRequestHandler):
    """Gateway 接「上行回包通道」。讀 ROLE 後持續讀 hex 行，解析後寫 DB + 轉發。"""

    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        conn = self.request
        _enable_tcp_keepalive(conn)
        print(f"[TCPManagement] [UP] Gateway 上行通道已連線: {peer}")

        file_obj = conn.makefile("r", encoding="utf-8", newline="\n")
        first_line = file_obj.readline()
        if first_line.strip().lower() not in ("role gateway", ""):
            print(f"[TCPManagement] [UP] 拒絕未知角色 {peer}: {first_line.strip()!r}")
            return

        try:
            for line in file_obj:
                hex_data = line.strip().upper()
                if not hex_data:
                    continue
                if not is_hex_payload(hex_data):
                    print(f"[TCPManagement] [UP] 略過非 hex: {hex_data}")
                    continue
                handle_upstream_line(hex_data)
        except OSError as e:
            print(f"[TCPManagement] [UP] 連線錯誤 {peer}: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            print(f"[TCPManagement] [UP] Gateway 上行通道已斷線: {peer}")


# ---------- Inbound command dispatcher (shared by Bridge & HTTP) ----------

def dispatch_command(hex_data, source):
    """寫 command_logs(destination=gateway) → 推到所有 gateway 下行通道 → 轉發 subscriber。
    回傳 (sent_count, forwarded_to_subscriber)。"""
    cmd_byte, cmd_name, mac = parse_meta(hex_data)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")

    mongo_store.insert_command_log(
        {
            "ts": now_iso,
            "destination": "gateway",
            "source": source,
            "hex_data": hex_data,
            "command": cmd_name,
            "cmd_byte": cmd_byte,
            "mac": mac,
        }
    )
    sent = send_to_gateways(hex_data)
    forwarded = forward_to_subscriber(hex_data, source="api") if sent else False
    return sent, forwarded


# ---------- Bridge (subscriber → server, line protocol) ----------

class BridgeHandler(socketserver.BaseRequestHandler):
    """subscriber 的長連線指令橋。`ROLE bridge\\n` 握手後，每行一筆 hex；
    server 寫 mongo + 沿下行通道下發給每一台 gateway，再回一行 `OK <count>` 或 `ERR <reason>`。"""

    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        conn = self.request
        _enable_tcp_keepalive(conn)

        file_obj = conn.makefile("r", encoding="utf-8", newline="\n")
        first_line = file_obj.readline()
        if first_line.strip().lower() != "role bridge":
            print(f"[TCPManagement] [BRIDGE] 拒絕未知角色 {peer}: {first_line.strip()!r}")
            return
        print(f"[TCPManagement] [BRIDGE] subscriber 已連線: {peer}")

        def _reply(text):
            try:
                conn.sendall(f"{text}\n".encode("utf-8"))
            except OSError:
                pass

        try:
            for line in file_obj:
                hex_data = line.strip().upper()
                if not hex_data:
                    continue  # heartbeat 空行
                if not is_hex_payload(hex_data):
                    _reply("ERR not_hex")
                    continue
                sent, _ = dispatch_command(hex_data, source="subscriber")
                if sent == 0:
                    _reply("ERR no_gateway")
                    print(f"[TCPManagement] [BRIDGE] 略過（無 gateway 連線）: {hex_data}")
                else:
                    _reply(f"OK {sent}")
                    print(f"[TCPManagement] [BRIDGE] 已下發到 {sent} 個 gateway: {hex_data}")
        except OSError as e:
            print(f"[TCPManagement] [BRIDGE] 連線錯誤 {peer}: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            print(f"[TCPManagement] [BRIDGE] subscriber 已斷線: {peer}")


# ---------- Server bootstrap ----------

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve_forever(name, host, port, handler_cls):
    while True:
        try:
            with ThreadingTCPServer((host, port), handler_cls) as server:
                print(f"[TCPManagement] [{name}] 監聽 {host}:{port}")
                server.serve_forever()
        except Exception as e:
            print(f"[TCPManagement] [{name}] 監聽錯誤 {host}:{port}: {e!r}，3 秒後重試")
            time.sleep(3)


def main():
    print(f"[TCPManagement] 固定轉送目標: {SUBSCRIBER_API_URL or '(未設定)'}")
    print(f"[TCPManagement] MongoDB: {'已啟用' if mongo_store.enabled() else '未啟用'}")
    print(f"[TCPManagement] Gateway 下行 dial 目標: {GATEWAYS or '(未設定)'}")

    # 上行：listen，等 gateway 主動連入
    threading.Thread(
        target=_serve_forever,
        args=("UP", TCP_HOST, UPSTREAM_PORT, UpstreamHandler),
        daemon=True,
    ).start()
    # 下行：對每一台 gateway 開一個 dialer thread
    for host, port in GATEWAYS:
        threading.Thread(
            target=_downstream_dialer_loop,
            args=(host, port),
            daemon=True,
        ).start()
    threading.Thread(target=_downstream_heartbeat_loop, daemon=True).start()

    # Bridge：listen，等 subscriber 連入；本 thread 不返回（取代之前的 HTTP main loop）
    _serve_forever("BRIDGE", TCP_HOST, BRIDGE_PORT, BridgeHandler)


if __name__ == "__main__":
    main()
