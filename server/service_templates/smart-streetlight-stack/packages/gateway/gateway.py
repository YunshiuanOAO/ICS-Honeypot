"""
Gateway 模擬器
- 訂閱 MQTT topic: streetlight/server_to_gateway
- 發佈 MQTT topic: streetlight/gateway_to_server
- TCP socket 模式採「對等雙通道」（VM-B TCP Management）：兩邊各 listen 一個 port、互相 dial。
  * 下行通道：gateway **listen** GATEWAY_LISTEN_PORT（預設 15566），server 主動 dial 進來
              並送 `ROLE manager\\n`，之後 gateway 只『讀』指令。
  * 上行通道：gateway **dial** server 的 UPSTREAM_PORT（預設 15567），送 `ROLE gateway\\n`
              後只『寫』回包與 DRD_10 定時回報（與 model A 相同）。
- 兩條連線各自開 thread；任一條斷線不影響另一條。下行 server 主動重連，上行 gateway 主動重連。
- 所有資料都從 streetlight_data.json 載入
- MQTT payload 為純 hex 字串，無 JSON 包裝
"""

import json
import os
import socket
import socketserver
import time
import threading
import paho.mqtt.client as mqtt

COMM_MODE = os.environ.get("COMM_MODE", "mqtt").strip().lower()
if COMM_MODE not in ("mqtt", "socket", "both"):
    COMM_MODE = "mqtt"

BROKER_HOST = os.environ.get("BROKER_HOST", "mqtt-broker")
BROKER_PORT = int(os.environ.get("BROKER_PORT", "1883"))
REPORT_INTERVAL = int(os.environ.get("GATEWAY_REPORT_INTERVAL", "30"))
SOCKET_HOST = os.environ.get("SOCKET_HOST", "0.0.0.0")
# 上行通道：gateway 主動 dial server
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "15567"))
# 下行通道：gateway 自己 listen 等 server dial 進來
GATEWAY_LISTEN_HOST = os.environ.get("GATEWAY_LISTEN_HOST", "0.0.0.0")
GATEWAY_LISTEN_PORT = int(os.environ.get("GATEWAY_LISTEN_PORT", os.environ.get("DOWNSTREAM_PORT", "15566")))

TOPIC_CMD = "streetlight/server_to_gateway"
TOPIC_RESP = "streetlight/gateway_to_server"

# 等 MQTT on_connect 成功後再發定時回報，避免 race；搭配 loop_start 讓其他執行緒可安全 publish。
_broker_ready = threading.Event()
# 上行通道狀態（負責寫回包與 DRD_10）；下行只讀，不需要 ready event 給其他 thread 用。
_upstream_ready = threading.Event()
_upstream_conn = None
_upstream_conn_lock = threading.Lock()

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "streetlight_data.json")
with open(DATA_PATH, "r", encoding="utf-8") as f:
    DATA = json.load(f)

CMD_NAMES = DATA["cmd_names"]
COMMAND_RESPONSE_MAP = DATA["command_response_map"]
DRD10_DATA = DATA["drd10_data"]


def _enable_tcp_keepalive(sock):
    """跨雲長連線會被中間 NAT 靜默砍掉。Keepalive 只偵測「完全 idle」連線；若已有 unacked data，
    kernel 走 TCP retransmission（tcp_retries2 預設要十幾分鐘），所以再加 TCP_USER_TIMEOUT 30s
    兜底，buffer 裡 unacked 超時就標 dead → write 立刻拿到 ETIMEDOUT → 重連。
    TCP_USER_TIMEOUT / TCP_KEEP* 都是 Linux-only，其他平台沒有就吞掉。"""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    for opt_name, value in (
        ("TCP_KEEPIDLE", 30),
        ("TCP_KEEPINTVL", 10),
        ("TCP_KEEPCNT", 3),
        ("TCP_USER_TIMEOUT", 30_000),  # 毫秒，跟其他選項單位不同
    ):
        opt = getattr(socket, opt_name, None)
        if opt is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt, value)
        except OSError:
            pass


def get_cmd_name(hex_data):
    if len(hex_data) >= 6:
        cmd_byte = hex_data[4:6].lower()
        return CMD_NAMES.get(cmd_byte, f"Unknown(0x{cmd_byte})")
    return "Unknown"


def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"[Gateway] 已連線到 MQTT Broker ({BROKER_HOST}:{BROKER_PORT})")
        client.subscribe(TOPIC_CMD)
        print(f"[Gateway] 已訂閱 topic: {TOPIC_CMD}")
        _broker_ready.set()
    else:
        print(f"[Gateway] 連線失敗, rc={rc}")
        _broker_ready.clear()


def on_message(client, userdata, msg):
    try:
        hex_data = msg.payload.decode().strip().upper()
        cmd_byte = hex_data[4:6].lower() if len(hex_data) >= 6 else ""
        cmd_name = get_cmd_name(hex_data)
        print(f"[Gateway] 收到指令: {cmd_name}  Hex: {hex_data}")

        # 0x81 (SRD_10) 現在是 server 對 DRD_10 定時回報的 ACK，gateway 不需要再回應
        if cmd_byte == "81":
            print(f"[Gateway] [MQTT] 已收到 server DRD_10 ACK")
            return

        response_hex = COMMAND_RESPONSE_MAP.get(hex_data)
        if response_hex:
            client.publish(TOPIC_RESP, response_hex)
            print(f"[Gateway] 已回應: {get_cmd_name(response_hex)}  Hex: {response_hex}")
        else:
            print(f"[Gateway] 找不到對應的回應指令: {hex_data}")
    except Exception as e:
        print(f"[Gateway] 處理訊息時發生錯誤: {e}")


def send_upstream(hex_data):
    """寫入上行通道（UPSTREAM_PORT）。回包與 DRD_10 定時回報都走這條。"""
    payload = f"{hex_data}\n".encode()
    with _upstream_conn_lock:
        conn = _upstream_conn
        if not conn:
            return False
        try:
            conn.sendall(payload)
            return True
        except OSError as e:
            print(f"[Gateway] [UP] 發送失敗: {e}")
            return False


def handle_socket_command(hex_data):
    cmd_byte = hex_data[4:6].lower() if len(hex_data) >= 6 else ""
    cmd_name = get_cmd_name(hex_data)
    print(f"[Gateway] [DOWN] 收到指令: {cmd_name}  Hex: {hex_data}")

    # 0x81 (SRD_10) 是 server 對 DRD_10 定時回報的 ACK，gateway 不需要再回應
    if cmd_byte == "81":
        print(f"[Gateway] [DOWN] 已收到 server DRD_10 ACK")
        return

    response_hex = COMMAND_RESPONSE_MAP.get(hex_data)
    if response_hex:
        if send_upstream(response_hex):
            print(f"[Gateway] [UP] 已回應: {get_cmd_name(response_hex)}  Hex: {response_hex}")
        else:
            print(f"[Gateway] [UP] 回應失敗: 上行通道尚未連線")
    else:
        print(f"[Gateway] [DOWN] 找不到對應的回應指令: {hex_data}")


class DownstreamHandler(socketserver.BaseRequestHandler):
    """Server 主動 dial 進來；先送 `ROLE manager\\n` 才允許後續 hex line。
    本連線只用來讀指令，回應走上行通道（send_upstream）。"""

    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        conn = self.request
        _enable_tcp_keepalive(conn)

        file_obj = conn.makefile("r", encoding="utf-8", newline="\n")
        first_line = file_obj.readline()
        if first_line.strip().lower() not in ("role manager", ""):
            print(f"[Gateway] [DOWN] 拒絕未知角色 {peer}: {first_line.strip()!r}")
            return
        print(f"[Gateway] [DOWN] Server 已連入: {peer}")

        try:
            for line in file_obj:
                hex_data = line.strip().upper()
                if not hex_data:
                    continue
                handle_socket_command(hex_data)
        except OSError as e:
            print(f"[Gateway] [DOWN] 連線錯誤 {peer}: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            print(f"[Gateway] [DOWN] Server 已斷線: {peer}")


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def downstream_listener_loop():
    """gateway 端 listen，等 server 主動 dial 進來；server 端可有多個（多 manager 群控）。"""
    print(f"[Gateway] [DOWN] listen {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}")
    while True:
        try:
            with _ThreadingTCPServer((GATEWAY_LISTEN_HOST, GATEWAY_LISTEN_PORT), DownstreamHandler) as server:
                server.serve_forever()
        except Exception as e:
            print(f"[Gateway] [DOWN] listen 錯誤 {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}: {e!r}，3 秒後重試")
            time.sleep(3)


def upstream_loop():
    """連到 UPSTREAM_PORT，建立寫專用連線；其他 thread 透過 send_upstream 寫入。"""
    global _upstream_conn
    print(f"[Gateway] [UP] 目標上行通道: {SOCKET_HOST}:{UPSTREAM_PORT}")
    while True:
        sock = None
        try:
            print(f"[Gateway] [UP] 連線 {SOCKET_HOST}:{UPSTREAM_PORT}...")
            sock = socket.create_connection((SOCKET_HOST, UPSTREAM_PORT), timeout=10)
            sock.settimeout(None)
            _enable_tcp_keepalive(sock)
            sock.sendall(b"ROLE gateway\n")
            with _upstream_conn_lock:
                _upstream_conn = sock
            _upstream_ready.set()
            print(f"[Gateway] [UP] 已連線 {SOCKET_HOST}:{UPSTREAM_PORT}")

            # 雖然只用來寫，但仍要 read 以偵測 server 端 EOF / 斷線。
            file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
            for line in file_obj:
                stripped = line.strip()
                if stripped:
                    print(f"[Gateway] [UP] 略過 server 在上行通道送出的資料: {stripped}")
        except Exception as e:
            print(f"[Gateway] [UP] 等待 {SOCKET_HOST}:{UPSTREAM_PORT}... ({e})")
        finally:
            _upstream_ready.clear()
            with _upstream_conn_lock:
                if _upstream_conn is sock:
                    _upstream_conn = None
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
            time.sleep(3)


def heartbeat_loop():
    """每 30 秒在上行通道寫一個 b"\\n"，維持跨雲 NAT conntrack entry 不被砍。
    server 端 strip 後是空字串、直接略過。"""
    while True:
        time.sleep(30)
        if _upstream_ready.is_set():
            send_upstream("")


def periodic_report(client):
    """先發一輪 DRD_10，之後每 REPORT_INTERVAL 秒一輪。"""
    mqtt_enabled = client is not None and COMM_MODE in ("mqtt", "both")
    socket_enabled = COMM_MODE in ("socket", "both")
    if mqtt_enabled:
        print("[Gateway] 定時回報執行緒: 等待 MQTT 連線…")
        _broker_ready.wait()
    else:
        print("[Gateway] 定時回報執行緒: 使用 socket 模式")

    while True:
        try:
            for mac, hex_data in DRD10_DATA.items():
                if mqtt_enabled and _broker_ready.is_set():
                    client.publish(TOPIC_RESP, hex_data, qos=0, retain=False)
                    print(f"[Gateway] [MQTT] 定時回報 DRD_10 - MAC: {mac}  Hex: {hex_data}")
                if socket_enabled:
                    if send_upstream(hex_data):
                        print(f"[Gateway] [UP] 定時回報 DRD_10 - MAC: {mac}  Hex: {hex_data}")
                    else:
                        print(f"[Gateway] [UP] 略過定時回報，上行通道尚未連線 - MAC: {mac}")
        except Exception as e:
            print(f"[Gateway] 定時回報發佈錯誤: {e}")
        time.sleep(REPORT_INTERVAL)


def main():
    print("[Gateway] 啟動中…")
    print(f"[Gateway] 通訊模式: {COMM_MODE}")
    if COMM_MODE in ("socket", "both"):
        threading.Thread(target=downstream_listener_loop, daemon=True).start()
        threading.Thread(target=upstream_loop, daemon=True).start()
        threading.Thread(target=heartbeat_loop, daemon=True).start()

    if COMM_MODE == "socket":
        threading.Thread(target=periodic_report, args=(None,), daemon=True).start()
        while True:
            time.sleep(3600)

    print(
        f"[Gateway] Broker 目標: {BROKER_HOST!s}:{BROKER_PORT} "
        f"(請確認遠端 Mosquitto 的 Security Group / 防火牆允許「本機出口 IP」連此埠)"
    )
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="streetlight-gateway")
    client.on_connect = on_connect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    threading.Thread(target=periodic_report, args=(client,), daemon=True).start()

    while True:
        try:
            _broker_ready.clear()
            client.connect(BROKER_HOST, BROKER_PORT, 60)
            client.loop_start()
            print(f"[Gateway] MQTT loop 已啟動（定時回報間隔 {REPORT_INTERVAL}s）")
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            client.loop_stop()
            client.disconnect()
            raise
        except Exception as e:
            print(f"[Gateway] 連線錯誤 {BROKER_HOST!s}:{BROKER_PORT} → {e!r}，3 秒後重試")
            try:
                client.loop_stop()
            except Exception:
                pass
            time.sleep(3)


if __name__ == "__main__":
    main()
