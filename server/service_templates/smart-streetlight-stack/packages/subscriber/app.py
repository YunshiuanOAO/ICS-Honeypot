"""
Web 訂閱者介面
- 透過 Socket.IO 即時顯示 MQTT / TCP socket / API 訊息
- 發送的 payload 是純 hex 字串 (無 JSON 包裝)
- 收到的 hex 在 server side 解析後再以 Socket.IO 推送到瀏覽器
- 所有資料都從 streetlight_data.json 載入
- MQTT：訂閱走 BROKER_SUB_PORT（預設 11883 直連 broker）；Web 發送（按鈕／自訂 hex）
  走 BROKER_PUB_PORT（預設 1883 經 honeypot proxy）。細節見 subscriber.env。
- TCP socket：COMM_MODE=socket 時連到 gateway SOCKET_HOST:SOCKET_PORT。
- API：COMM_MODE=api 時由獨立 socket server 呼叫 /api/messages 推送資料。
- both：同時走 MQTT 與 socket server TCP 路徑。
"""

import os

# Web UI 長時間後打不開，多半是 eventlet hub 與 Paho「另一條 thread + loop_forever」互卡。
# 預設用 threading（不 monkey_patch）；若要用 eventlet 請設 SOCKETIO_ASYNC_MODE=eventlet。
_SOCKETIO_ASYNC_MODE = os.environ.get("SOCKETIO_ASYNC_MODE", "threading").strip().lower()
if _SOCKETIO_ASYNC_MODE not in ("eventlet", "threading"):
    _SOCKETIO_ASYNC_MODE = "threading"

eventlet = None  # 僅在 async_mode=eventlet 時載入
if _SOCKETIO_ASYNC_MODE == "eventlet":
    try:
        import eventlet as _eventlet_mod

        eventlet = _eventlet_mod
        eventlet.monkey_patch()
    except ImportError:
        _SOCKETIO_ASYNC_MODE = "threading"

import json
import random
import re
import socket
import time
import threading
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, disconnect
import paho.mqtt.client as mqtt

try:
    from pymongo import MongoClient, DESCENDING
    from pymongo.errors import PyMongoError
except ImportError:  # 本機沒裝 pymongo 時降級，UI 仍可跑（只是讀不到歷史）
    MongoClient = None
    DESCENDING = -1
    PyMongoError = Exception

app = Flask(__name__)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Flask session 在部分 Socket.IO 事件（尤其 eventlet）裡不一定與 HTTP 登入共用同一份
# context；connect 當下若已驗證登入，則以 sid 授權後續 emit，避免按鈕無聲被擋。
_socket_authorized_sids = set()
app.secret_key = os.environ.get("SECRET_KEY", "streetlight-dev-secret-change-me")
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode=_SOCKETIO_ASYNC_MODE,
    ping_timeout=120,
    ping_interval=25,
)

COMM_MODE = os.environ.get("COMM_MODE", "mqtt").strip().lower()
if COMM_MODE not in ("mqtt", "socket", "api", "both"):
    COMM_MODE = "mqtt"

BROKER_HOST = os.environ.get("BROKER_HOST", "mqtt-broker")
# SUB 直連真實 broker port (11883) 繞過 proxy；
# PUB 走 honeypot proxy port (1883) 讓所有發送指令都被 proxy 記錄。
# 詳細理由見 subscriber.env 上方註解。
BROKER_SUB_PORT = int(os.environ.get("BROKER_SUB_PORT", "11883"))
BROKER_PUB_PORT = int(os.environ.get("BROKER_PUB_PORT", "1883"))
MQTT_KEEPALIVE = int(os.environ.get("MQTT_KEEPALIVE", "60"))
SOCKET_HOST = os.environ.get("SOCKET_HOST", BROKER_HOST)
SOCKET_PORT = int(os.environ.get("SOCKET_PORT", "9000"))
SOCKET_SERVER_HOST = os.environ.get("SOCKET_SERVER_HOST", BROKER_HOST)
# Bridge 通道：subscriber 對 socket_server 維持 TCP 長連線（line protocol，ROLE bridge\n 握手）。
# 取代之前的 HTTP /api/commands；socket_server 不再有 HTTP server。
SOCKET_SERVER_BRIDGE_PORT = int(os.environ.get("SOCKET_SERVER_BRIDGE_PORT", "15568"))
SOCKET_SERVER_BRIDGE_REPLY_TIMEOUT = float(os.environ.get("SOCKET_SERVER_BRIDGE_REPLY_TIMEOUT", "5"))
API_TOKEN = os.environ.get("API_TOKEN", "").strip()

# MongoDB 連線（讀取 VM-B TCP Management 寫入的 runtime / command_logs）
# 留空則 UI 上的 MongoDB 區塊會回 503，不影響 MQTT/即時推送功能。
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
MONGO_DB = os.environ.get("MONGO_DB", "streetlight").strip()

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")


def _env_int(name, default, min_value=None, max_value=None):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    if min_value is not None:
        value = max(value, min_value)
    if max_value is not None:
        value = min(value, max_value)
    return value


def _env_float(name, default):
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


# HMI honeypot brightness simulation. Default timezone is UTC+8 for the NCKU/Taiwan scenario.
SIM_LIGHT_DAY_START_HOUR = _env_int("SIM_LIGHT_DAY_START_HOUR", 5, 0, 23)
SIM_LIGHT_DAY_END_HOUR = _env_int("SIM_LIGHT_DAY_END_HOUR", 18, 0, 24)
SIM_LIGHT_UTC_OFFSET_HOURS = _env_float("SIM_LIGHT_UTC_OFFSET_HOURS", 8.0)
SIM_LIGHT_RANDOM_MIN = _env_int("SIM_LIGHT_RANDOM_MIN", 20, 0, 100)
SIM_LIGHT_RANDOM_MAX = _env_int("SIM_LIGHT_RANDOM_MAX", 100, 0, 100)
if SIM_LIGHT_RANDOM_MAX < SIM_LIGHT_RANDOM_MIN:
    SIM_LIGHT_RANDOM_MIN, SIM_LIGHT_RANDOM_MAX = SIM_LIGHT_RANDOM_MAX, SIM_LIGHT_RANDOM_MIN
SIM_LIGHT_RANDOM_BUCKET_SECONDS = _env_int("SIM_LIGHT_RANDOM_BUCKET_SECONDS", 300, 1, 86400)


# ---------- MongoDB read-only helper ----------

mongo_client = None
mongo_db = None
_mongo_lock = threading.Lock()
_mongo_last_attempt = 0.0
_MONGO_RETRY_INTERVAL = 5.0  # 連不上時最多每 5s 試一次，避免每個 request 都打一輪握手


def _ensure_mongo():
    """Lazy + 自動重連的 mongo 取得器。
    - 已連 → 直接回 db
    - 沒連 → 加鎖避免 thundering herd，且失敗後 5s 內不重試（避免每個 request 都拖 3s 握手）

    Pymongo 設定（同樣留著三個 timeout，理由見下）：
      serverSelectionTimeoutMS=3000  ── 拓撲找不到 server 時 3 秒放棄
      connectTimeoutMS=3000          ── 新 socket 三向交握 3 秒內完成，否則放棄
      socketTimeoutMS=5000           ── 既有 socket 上單次 op 超過 5 秒就拋出，
                                       retryReads/retryWrites 會自動換條 socket 重試
      maxIdleTimeMS=30000            ── pool 裡空閒 30 秒沒用的 socket 主動回收，
                                       小於 NAT 砍線時間（AWS ~350s）避免撞到 stale
    """
    global mongo_client, mongo_db, _mongo_last_attempt
    if mongo_db is not None:
        return mongo_db
    if not MONGO_URI or MongoClient is None:
        return None
    now = time.monotonic()
    if now - _mongo_last_attempt < _MONGO_RETRY_INTERVAL:
        return None
    with _mongo_lock:
        # double-check：另一條 thread 可能在等鎖時已經連好了
        if mongo_db is not None:
            return mongo_db
        if time.monotonic() - _mongo_last_attempt < _MONGO_RETRY_INTERVAL:
            return None
        _mongo_last_attempt = time.monotonic()
        try:
            client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=3000,
                connectTimeoutMS=3000,
                socketTimeoutMS=5000,
                maxIdleTimeMS=30000,
            )
            client.admin.command("ping")
            mongo_client = client
            mongo_db = client[MONGO_DB]
            print(f"[Subscriber] [MongoDB] 已連線 {MONGO_URI} db={MONGO_DB}")
        except PyMongoError as e:
            print(f"[Subscriber] [MongoDB] 連線失敗 {MONGO_URI}: {e}")
            mongo_client = None
            mongo_db = None
        return mongo_db


# 啟動時主動嘗試一次，讓正常情況下第一個 request 不用等握手；失敗也不影響服務啟動
_ensure_mongo()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def socket_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        sid = getattr(request, "sid", None)
        if not session.get("logged_in") and sid not in _socket_authorized_sids:
            disconnect()
            return
        return f(*args, **kwargs)
    return decorated

TOPIC_CMD = "streetlight/server_to_gateway"
TOPIC_RESP = "streetlight/gateway_to_server"

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "streetlight_data.json")
MAP_EXPORT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "smart-map-export-20260609-165145.json",
)
with open(DATA_PATH, "r", encoding="utf-8") as f:
    DATA = json.load(f)

STREETLIGHTS = DATA["streetlights"]
COMMANDS = DATA["commands"]
CMD_NAMES = DATA["cmd_names"]
_brightness_state = {}
_brightness_lock = threading.Lock()


def _load_map_export():
    """讀取智慧地圖匯出檔；容忍尾端多餘逗號，避免匯出檔小格式錯誤讓 UI 掛掉。"""
    if not os.path.exists(MAP_EXPORT_PATH):
        return {"markers": [], "summary": {"marker_count": 0, "device_count": 0}}
    with open(MAP_EXPORT_PATH, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return json.loads(re.sub(r",\s*([\]}])", r"\1", raw))


def _device_mac(device):
    for key in ("mac", "MAC", "device_mac", "deviceMac", "address", "addr", "id"):
        value = device.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    return None


def _simulation_local_time(now=None):
    timestamp = time.time() if now is None else float(now)
    return time.gmtime(timestamp + SIM_LIGHT_UTC_OFFSET_HOURS * 3600)


def _is_daylight_off_window(now=None):
    hour = _simulation_local_time(now).tm_hour
    start = SIM_LIGHT_DAY_START_HOUR
    end = SIM_LIGHT_DAY_END_HOUR
    if start == end:
        return True
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _hex_byte_at(hex_data, byte_number):
    start = (byte_number - 1) * 2
    end = start + 2
    if len(hex_data) < end:
        return None
    try:
        return int(hex_data[start:end], 16)
    except ValueError:
        return None


def _extract_brightness_from_hex(topic, hex_data):
    if not isinstance(hex_data, str) or len(hex_data) < 6:
        return None
    hex_data = hex_data.strip().upper()
    cmd_byte = hex_data[4:6].lower()
    if topic == TOPIC_CMD and cmd_byte == "52":
        return _hex_byte_at(hex_data, 10)
    if topic == TOPIC_RESP and cmd_byte in ("37", "51", "53"):
        return _hex_byte_at(hex_data, 14)
    if topic == TOPIC_RESP and cmd_byte == "80":
        return _hex_byte_at(hex_data, 24)
    return None


def _set_brightness(mac, brightness):
    if not mac or brightness is None:
        return
    brightness = max(0, min(int(brightness), 100))
    with _brightness_lock:
        _brightness_state[mac.upper()] = brightness


def _get_brightness(mac):
    if not mac:
        return None
    with _brightness_lock:
        return _brightness_state.get(mac.upper())


def _simulated_brightness(mac, marker_index, device_index, now=None):
    current = _get_brightness(mac)
    if current is not None:
        return current
    if _is_daylight_off_window(now):
        return 0
    timestamp = time.time() if now is None else float(now)
    bucket = int(timestamp // SIM_LIGHT_RANDOM_BUCKET_SECONDS)
    seed = f"{mac or 'unknown'}:{marker_index}:{device_index}:{bucket}"
    return random.Random(seed).randint(SIM_LIGHT_RANDOM_MIN, SIM_LIGHT_RANDOM_MAX)


def _map_payload(now=None):
    if now is None:
        now = time.time()
    exported = _load_map_export()
    markers = []
    fallback_device_index = 0
    brightness_mode = "daytime_off" if _is_daylight_off_window(now) else "night_random"
    for index, marker in enumerate(exported.get("markers") or []):
        lat = marker.get("lat")
        lon = marker.get("lon", marker.get("lng"))
        if lat is None or lon is None:
            continue
        devices = []
        for device_index, device in enumerate(marker.get("devices") or []):
            if not isinstance(device, dict):
                continue
            mac = _device_mac(device)
            if not mac and fallback_device_index < len(STREETLIGHTS):
                mac = STREETLIGHTS[fallback_device_index].get("mac")
            fallback_device_index += 1
            device_lat = device.get("lat", lat)
            device_lon = device.get("lon", device.get("lng", lon))
            brightness = _simulated_brightness(mac, index, device_index, now)
            devices.append(
                {
                    **device,
                    "mac": mac,
                    "lat": device_lat,
                    "lon": device_lon,
                    "brightness": brightness,
                    "brightness_simulated": True,
                    "brightness_mode": brightness_mode,
                    "controllable": bool(mac and mac in COMMANDS),
                    "device_index": device_index,
                }
            )
        markers.append(
            {
                "marker_key": marker.get("marker_key") or f"{lat}:{lon}",
                "lat": lat,
                "lon": lon,
                "device_count": marker.get("device_count", len(devices)),
                "devices": devices,
                "marker_index": index,
            }
        )
    summary = dict(exported.get("summary") or {})
    summary["export_marker_count"] = summary.get("marker_count")
    summary["export_device_count"] = summary.get("device_count")
    summary["marker_count"] = len(markers)
    summary["device_count"] = sum(len(m["devices"]) for m in markers)
    summary["brightness_mode"] = brightness_mode
    summary["brightness_day_start_hour"] = SIM_LIGHT_DAY_START_HOUR
    summary["brightness_day_end_hour"] = SIM_LIGHT_DAY_END_HOUR
    return {
        "exported_at": exported.get("exported_at"),
        "summary": summary,
        "markers": markers,
        "controllable_macs": sorted(COMMANDS.keys()),
    }

sub_client = None  # 只訂閱：BROKER_SUB_PORT（預設 11883，直連 Mosquitto）
pub_client = None  # 只發佈：BROKER_PUB_PORT（預設 1883，經 honeypot proxy；Web 按鈕與自訂 hex）
socket_client = None  # TCP socket 模式：連到 gateway SOCKET_HOST:SOCKET_PORT
socket_client_lock = threading.Lock()
socket_ready = threading.Event()
_RECENT_EVENT_TTL_SECONDS = 2.0
_recent_socketio_events = {}
_recent_drd10_acks = {}
_recent_drd10_triggers = {}
_recent_events_lock = threading.Lock()


def _remember_recent(cache, key):
    now = time.monotonic()
    expired_keys = [old_key for old_key, ts in cache.items() if now - ts > _RECENT_EVENT_TTL_SECONDS]
    for old_key in expired_keys:
        cache.pop(old_key, None)
    last_seen = cache.get(key)
    if last_seen is not None and now - last_seen <= _RECENT_EVENT_TTL_SECONDS:
        return False
    cache[key] = now
    return True


def _recent_ack_routes(key):
    now = time.monotonic()
    expired_keys = [old_key for old_key, entry in _recent_drd10_acks.items() if now - entry["ts"] > _RECENT_EVENT_TTL_SECONDS]
    for old_key in expired_keys:
        _recent_drd10_acks.pop(old_key, None)
    entry = _recent_drd10_acks.get(key)
    if not entry:
        return set()
    return set(entry["routes"])


def _mark_ack_route(key, route):
    now = time.monotonic()
    entry = _recent_drd10_acks.setdefault(key, {"ts": now, "routes": set()})
    entry["ts"] = now
    entry["routes"].add(route)


def _emit_mqtt_to_socketio(event):
    """從背景通訊執行緒推到 Socket.IO；不可在 on_message 裡直接 emit（易與 eventlet 死鎖）。"""
    try:
        if COMM_MODE == "both":
            key = (event.get("topic"), event.get("data"))
            with _recent_events_lock:
                if not _remember_recent(_recent_socketio_events, key):
                    print(f"[Subscriber] [BOTH] 略過重複 UI 訊息: {key[0]} {key[1]}")
                    return
        socketio.emit("mqtt_message", event)
    except Exception as e:
        print(f"[Subscriber] [SUB] Socket.IO emit 錯誤: {e}")


def get_cmd_name(hex_data):
    if len(hex_data) >= 6:
        cmd_byte = hex_data[4:6].lower()
        return CMD_NAMES.get(cmd_byte, f"Unknown(0x{cmd_byte})")
    return "Unknown"


def extract_mac(hex_data):
    """從 hex payload 中萃取 MAC (6:16)，群控指令不一定有"""
    if len(hex_data) >= 16 and not hex_data[6:16].startswith("4081"):
        return hex_data[6:16]
    return None


def parse_payload(topic, hex_data):
    """把 raw hex 解析成 UI 用的事件物件"""
    cmd_byte = hex_data[4:6].lower() if len(hex_data) >= 6 else ""
    cmd_name = CMD_NAMES.get(cmd_byte, f"Unknown(0x{cmd_byte})")
    if topic == TOPIC_CMD:
        msg_type = "command"
    elif cmd_byte == "80":
        msg_type = "periodic_report"
    else:
        msg_type = "response"
    mac = extract_mac(hex_data)
    brightness = _extract_brightness_from_hex(topic, hex_data)
    if topic == TOPIC_RESP and brightness is not None:
        _set_brightness(mac, brightness)
    event = {
        "topic": topic,
        "type": msg_type,
        "command": cmd_name,
        "mac": mac,
        "data": hex_data,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if brightness is not None:
        event["brightness"] = brightness
    return event


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


def is_hex_payload(value):
    return isinstance(value, str) and value.strip() and all(ch in "0123456789abcdefABCDEF" for ch in value.strip())


def publish_mqtt_command(hex_data, context):
    if pub_client is None:
        print(f"[Subscriber] [PUB] 略過 {context}: pub_client 尚未初始化")
        return False
    if hasattr(pub_client, "is_connected") and not pub_client.is_connected():
        print(f"[Subscriber] [PUB] 略過 {context}: pub_client 尚未連線")
        return False
    info = pub_client.publish(TOPIC_CMD, hex_data)
    if info.rc != mqtt.MQTT_ERR_SUCCESS:
        print(f"[Subscriber] [PUB] {context} publish 失敗 rc={info.rc}")
        return False
    return True


def maybe_ack_drd10(topic, hex_data):
    """收到 gateway 的 DRD_10 (0x80) 定時回報時，依目前 COMM_MODE 自動送 SRD_10 ACK 回去。
    server (這個 web subscriber) 收到後送對應 MAC 的 SRD_10 hex 作為「已收到」確認。"""
    if topic != TOPIC_RESP:
        return
    cmd_byte = hex_data[4:6].lower() if len(hex_data) >= 6 else ""
    if cmd_byte != "80":
        return
    mac = extract_mac(hex_data)
    if not mac or mac not in COMMANDS or "SRD_10" not in COMMANDS[mac]:
        return
    ack_hex = COMMANDS[mac]["SRD_10"].upper()
    ack_key = (mac, ack_hex)
    with _recent_events_lock:
        # both 模式下同一筆 DRD_10 會經 MQTT 與 /api/messages 各觸發一次此函式；若不在進入點
        # 就 dedup，下面 per-route 的「讀-檢查-送-標記」中間沒鎖，兩個 thread 會同時通過檢查
        # 並各自送出 ACK，造成 socket_server 收到重複 ROLE subscriber 訊息。
        if COMM_MODE == "both":
            trigger_key = (topic, hex_data)
            if not _remember_recent(_recent_drd10_triggers, trigger_key):
                print(f"[Subscriber] [BOTH] 略過重複 DRD_10 觸發 ACK: {hex_data}")
                return
        ack_routes = _recent_ack_routes(ack_key) if COMM_MODE == "both" else set()

    sent_ack = False
    if COMM_MODE in ("mqtt", "both"):
        if "mqtt" in ack_routes:
            print(f"[Subscriber] [BOTH] 略過重複 MQTT DRD_10 ACK -> MAC: {mac}")
        elif publish_mqtt_command(ack_hex, "DRD_10 ACK"):
            sent_ack = True
            with _recent_events_lock:
                _mark_ack_route(ack_key, "mqtt")
            print(f"[Subscriber] [PUB] 已回 DRD_10 ACK -> MAC: {mac}  Hex: {ack_hex}")

    if COMM_MODE == "socket":
        if not send_socket_command(ack_hex):
            print("[Subscriber] [SOCKET] 略過 DRD_10 ACK: socket 尚未連線")
            return
        print(f"[Subscriber] [SOCKET] 已回 DRD_10 ACK -> MAC: {mac}  Hex: {ack_hex}")
        _emit_mqtt_to_socketio(parse_payload(TOPIC_CMD, ack_hex))

    if COMM_MODE in ("api", "both"):
        if "socketserver" in ack_routes:
            print(f"[Subscriber] [BOTH] 略過重複 socketserver DRD_10 ACK -> MAC: {mac}")
        elif not send_socket_server_command(ack_hex):
            print("[Subscriber] [SOCKET_SERVER] 略過 DRD_10 ACK: socket server TCP 發送失敗")
            if COMM_MODE == "api":
                return
        else:
            sent_ack = True
            with _recent_events_lock:
                _mark_ack_route(ack_key, "socketserver")
            print(f"[Subscriber] [SOCKET_SERVER] 已回 DRD_10 ACK -> MAC: {mac}  Hex: {ack_hex}")

    if COMM_MODE == "both" and sent_ack:
        _emit_mqtt_to_socketio(parse_payload(TOPIC_CMD, ack_hex))


def api_authorized():
    if not API_TOKEN:
        return True
    return request.headers.get("Authorization", "") == f"Bearer {API_TOKEN}"


def setup_mqtt():
    """啟動兩個獨立的 MQTT client：
    - sub_client: BROKER_SUB_PORT（預設 11883）直連 broker，只訂閱、收即時訊息。
    - pub_client: BROKER_PUB_PORT（預設 1883）經 proxy，只發送；Web 按鈕與自訂 hex 皆走此 client。
    """
    global sub_client, pub_client

    # ---------- Subscribe client (port 11883) ----------
    def on_sub_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[Subscriber] [SUB] 已連線到 Broker {BROKER_HOST}:{BROKER_SUB_PORT}")
            client.subscribe(TOPIC_RESP)
            client.subscribe(TOPIC_CMD)
            print(f"[Subscriber] [SUB] 已訂閱 topics: {TOPIC_RESP}, {TOPIC_CMD}")

    def on_sub_message(client, userdata, msg):
        try:
            hex_data = msg.payload.decode().strip().upper()
            event = parse_payload(msg.topic, hex_data)
            print(f"[Subscriber] [SUB] 收到 [{msg.topic}]: {event['command']}  Hex: {hex_data}")
            if _SOCKETIO_ASYNC_MODE == "eventlet" and eventlet is not None:
                eventlet.spawn_n(_emit_mqtt_to_socketio, event)
            else:
                _emit_mqtt_to_socketio(event)
            maybe_ack_drd10(msg.topic, hex_data)
        except Exception as e:
            print(f"[Subscriber] [SUB] 解析訊息錯誤: {e}")

    sub_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="web-subscriber-sub")
    sub_client.on_connect = on_sub_connect
    sub_client.on_message = on_sub_message
    sub_client.reconnect_delay_set(min_delay=1, max_delay=120)

    def on_sub_disconnect(client, userdata, disconnect_flags, reason_code, properties=None):
        print(f"[Subscriber] [SUB] MQTT 斷線 reason_code={reason_code!r}")

    sub_client.on_disconnect = on_sub_disconnect

    def sub_loop():
        while True:
            try:
                sub_client.connect(BROKER_HOST, BROKER_SUB_PORT, MQTT_KEEPALIVE)
                sub_client.loop_forever()
            except Exception as e:
                print(f"[Subscriber] [SUB] 等待 Broker {BROKER_HOST}:{BROKER_SUB_PORT}... ({e})")
            finally:
                try:
                    sub_client.loop_stop()
                except Exception:
                    pass
                try:
                    sub_client.disconnect()
                except Exception:
                    pass
                time.sleep(3)

    threading.Thread(target=sub_loop, daemon=True).start()

    # ---------- Publish client (port 1883) ----------
    def on_pub_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[Subscriber] [PUB] 已連線到 Broker {BROKER_HOST}:{BROKER_PUB_PORT}")

    pub_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="web-subscriber-pub")
    pub_client.on_connect = on_pub_connect
    pub_client.reconnect_delay_set(min_delay=1, max_delay=120)

    def on_pub_disconnect(client, userdata, disconnect_flags, reason_code, properties=None):
        print(f"[Subscriber] [PUB] MQTT 斷線 reason_code={reason_code!r}")

    pub_client.on_disconnect = on_pub_disconnect

    def pub_loop():
        while True:
            try:
                pub_client.connect(BROKER_HOST, BROKER_PUB_PORT, MQTT_KEEPALIVE)
                pub_client.loop_forever()
            except Exception as e:
                print(f"[Subscriber] [PUB] 等待 Broker {BROKER_HOST}:{BROKER_PUB_PORT}... ({e})")
            finally:
                try:
                    pub_client.loop_stop()
                except Exception:
                    pass
                try:
                    pub_client.disconnect()
                except Exception:
                    pass
                time.sleep(3)

    threading.Thread(target=pub_loop, daemon=True).start()


def setup_socket():
    """啟動 TCP socket client：送出與接收都使用一行一筆純 hex 字串。"""
    global socket_client

    def socket_loop():
        global socket_client
        while True:
            sock = None
            try:
                print(f"[Subscriber] [SOCKET] 連線 Gateway {SOCKET_HOST}:{SOCKET_PORT}...")
                sock = socket.create_connection((SOCKET_HOST, SOCKET_PORT), timeout=10)
                sock.settimeout(None)
                _enable_tcp_keepalive(sock)
                with socket_client_lock:
                    socket_client = sock
                socket_ready.set()
                print(f"[Subscriber] [SOCKET] 已連線 Gateway {SOCKET_HOST}:{SOCKET_PORT}")

                file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
                for line in file_obj:
                    hex_data = line.strip().upper()
                    if not hex_data:
                        continue
                    event = parse_payload(TOPIC_RESP, hex_data)
                    print(f"[Subscriber] [SOCKET] 收到 Gateway 訊息: {event['command']}  Hex: {hex_data}")
                    _emit_mqtt_to_socketio(event)
                    maybe_ack_drd10(TOPIC_RESP, hex_data)
            except Exception as e:
                print(f"[Subscriber] [SOCKET] 等待 Gateway {SOCKET_HOST}:{SOCKET_PORT}... ({e})")
            finally:
                socket_ready.clear()
                with socket_client_lock:
                    if socket_client is sock:
                        socket_client = None
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                time.sleep(3)

    threading.Thread(target=socket_loop, daemon=True).start()


def send_socket_command(hex_data):
    payload = f"{hex_data}\n".encode()
    with socket_client_lock:
        sock = socket_client
        if not sock:
            return False
        try:
            sock.sendall(payload)
            return True
        except OSError as e:
            print(f"[Subscriber] [SOCKET] 發送失敗: {e}")
            return False


class _BridgeClient:
    """對 socket_server 的長連線 TCP bridge（取代舊的 HTTP /api/commands）。
    `ROLE bridge\\n` 握手後一行一筆 hex；server 回 `OK <count>` 或 `ERR <reason>`。
    send_lock 序列化 send + 等回覆，確保 reply 順序與 send 順序對齊。"""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._sock = None
        self._reader = None
        self._send_lock = threading.Lock()
        self._sock_lock = threading.Lock()
        self._connected = threading.Event()
        threading.Thread(target=self._maintain_loop, daemon=True).start()

    def _maintain_loop(self):
        while True:
            sock = None
            try:
                print(f"[Subscriber] [BRIDGE] 連線 {self.host}:{self.port}...")
                sock = socket.create_connection((self.host, self.port), timeout=10)
                sock.settimeout(None)
                _enable_tcp_keepalive(sock)
                sock.sendall(b"ROLE bridge\n")
                reader = sock.makefile("r", encoding="utf-8", newline="\n")
                with self._sock_lock:
                    self._sock = sock
                    self._reader = reader
                self._connected.set()
                print(f"[Subscriber] [BRIDGE] 已連線 {self.host}:{self.port}")
                # 監測 EOF / 對端斷線：用 SO_ERROR poll，避免跟 send_command 搶讀
                while True:
                    time.sleep(5)
                    with self._sock_lock:
                        cur = self._sock
                    if cur is None:
                        break
                    err = cur.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if err != 0:
                        print(f"[Subscriber] [BRIDGE] socket error={err}，重連")
                        break
            except OSError as e:
                print(f"[Subscriber] [BRIDGE] 等待 {self.host}:{self.port}... ({e})")
            finally:
                self._connected.clear()
                with self._sock_lock:
                    self._sock = None
                    self._reader = None
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                time.sleep(3)

    def is_connected(self):
        return self._connected.is_set()

    def _invalidate(self, sock):
        """I/O 失敗時呼叫：清掉 self._sock（若還是同一條），shutdown + close 該 socket，
        並 clear connected event。maintain_loop 下個 5s poll 看到 _sock is None 就會 break
        進入重連分支。

        為什麼必須這樣做：對端 graceful FIN（socket_server 重啟、proxy 重啟、雲端 LB 砍 idle）
        不會寫進 SO_ERROR，maintain_loop 永遠看不到。只有實際 I/O（send / read）才會撞到
        Broken pipe / EOF，所以 send 端必須在這時主動把 socket 標 None，否則就是無限 hang
        在那條死 socket 上每筆都 Broken pipe。"""
        self._connected.clear()
        with self._sock_lock:
            if self._sock is sock:
                self._sock = None
                self._reader = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def send(self, hex_data):
        if not self.is_connected():
            return False
        with self._send_lock:
            with self._sock_lock:
                sock = self._sock
                reader = self._reader
            if sock is None or reader is None:
                return False
            try:
                sock.sendall(f"{hex_data}\n".encode("utf-8"))
            except OSError as e:
                print(f"[Subscriber] [BRIDGE] 寫入失敗: {e}")
                self._invalidate(sock)  # ← 觸發重連
                return False
            sock.settimeout(SOCKET_SERVER_BRIDGE_REPLY_TIMEOUT)
            try:
                line = reader.readline()
            except (OSError, ValueError) as e:
                print(f"[Subscriber] [BRIDGE] 讀回覆失敗: {e}")
                self._invalidate(sock)  # ← 觸發重連
                return False
            finally:
                try:
                    sock.settimeout(None)
                except OSError:
                    pass
            line = (line or "").strip()
            if not line:
                # 對端 FIN 後 readline 會回空字串。視為連線壞了。
                print("[Subscriber] [BRIDGE] 對端無回覆 (EOF)，標為斷線")
                self._invalidate(sock)  # ← 觸發重連
                return False
            parts = line.split(" ", 1)
            if parts[0] == "OK":
                return True
            print(f"[Subscriber] [BRIDGE] 對端回 ERR: {line}")
            return False


_bridge_client = _BridgeClient(SOCKET_SERVER_HOST, SOCKET_SERVER_BRIDGE_PORT)


def send_socket_server_command(hex_data):
    """送指令到 socket_server 的 Bridge 長連線；server 寫 mongo + 沿下行通道下發給 gateway。"""
    return _bridge_client.send(hex_data)


# ---------- HONEYPOT: deliberate .env credential leak ----------
# 故意把 subscriber.env 暴露在常見的偵察路徑，誘餌 + 蒐集 IoC：
#   /.env              ← 攻擊者一定會試的第一個路徑
#   /env               ← 變形
#   /.env.bak          ← 備份猜測
#   /config.env        ← 變形
#   /admin/.env        ← 子目錄猜測
# 命中時記到 honeypot log（HONEYPOT_LOGS_DIR 由 docker-compose mount 出來給蒐集端用）。
import logging as _logging  # 避免跟其他 logger 衝突
_honeypot_log_dir = os.environ.get("HONEYPOT_LOGS_DIR", "/app/logs")
try:
    os.makedirs(_honeypot_log_dir, exist_ok=True)
except OSError:
    _honeypot_log_dir = "/tmp"
_honeypot_logger = _logging.getLogger("honeypot.envleak")
_honeypot_logger.setLevel(_logging.INFO)
_honeypot_handler = _logging.FileHandler(os.path.join(_honeypot_log_dir, "envleak.log"))
_honeypot_handler.setFormatter(_logging.Formatter("%(asctime)s %(message)s"))
_honeypot_logger.addHandler(_honeypot_handler)


def _serve_leaked_env():
    """讀並回傳 subscriber.env 原文。被當成「開發者疏忽暴露 .env」誘餌。
    在正式部署這條路徑會被 nuclei / nginx 預設 404 規則擋掉；honeypot 反而開放。"""
    src = os.environ.get("LEAKED_ENV_PATH", os.path.join(os.path.dirname(__file__), "subscriber.env"))
    peer = request.headers.get("X-Forwarded-For") or request.remote_addr or "?"
    ua = request.headers.get("User-Agent", "")
    _honeypot_logger.info(
        "ENV_LEAK path=%s peer=%s ua=%r",
        request.path, peer, ua[:200],
    )
    print(f"[Subscriber] [HONEYPOT] /.env 被存取 path={request.path} peer={peer} ua={ua[:100]!r}")
    try:
        with open(src, "r", encoding="utf-8") as f:
            body = f.read()
    except OSError:
        return jsonify({"error": "not found"}), 404
    return body, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/.env")
@app.route("/env")
@app.route("/.env.bak")
@app.route("/config.env")
@app.route("/admin/.env")
@app.route("/.env.production")
def _honeypot_env_leak():
    return _serve_leaked_env()


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USER and password == ADMIN_PASS:
            session["logged_in"] = True
            session["username"] = username
            print(f"[Subscriber] 登入成功: {username}")
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        error = "帳號或密碼錯誤"
        print(f"[Subscriber] 登入失敗: {username}")
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    map_payload = _map_payload()
    return render_template(
        "index.html",
        streetlights=STREETLIGHTS,
        commands=COMMANDS,
        map_payload=map_payload,
        username=session.get("username", ""),
        comm_mode=COMM_MODE,
    )


@app.route("/api/commands", methods=["POST"])
@login_required
def api_post_command():
    """前端 / 第三方 client 透過 HTTP POST 下指令的入口（取代 web_api 的同名端點）。
    流程：寫 mongo command_logs(stage=accepted) → 經 send_socket_server_command 走 HTTP
         POST 到 socket_server :19100 → socket_server 派送到 gateway 下行通道。"""
    payload = request.get_json(silent=True) or {}
    hex_data = (payload.get("data") or payload.get("hex_data") or "").strip().upper()
    if not is_hex_payload(hex_data):
        return jsonify({"error": "data must be a non-empty hex string"}), 400

    cmd_byte = hex_data[4:6].lower() if len(hex_data) >= 6 else ""
    mac = extract_mac(hex_data)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
    source = (payload.get("source") or "frontend").strip() or "frontend"

    db = _ensure_mongo()
    if db is not None:
        try:
            db["command_logs"].insert_one(
                {
                    "ts": now_iso,
                    "destination": "gateway",
                    "source": source,
                    "hex_data": hex_data,
                    "cmd_byte": cmd_byte,
                    "mac": mac,
                    "stage": "accepted",
                }
            )
        except PyMongoError as e:
            print(f"[Subscriber] [POST_CMD] mongo 寫入失敗: {e}")

    if not send_socket_server_command(hex_data):
        return jsonify({"error": "tcp_management unreachable"}), 502

    return jsonify({"ok": True, "source": source, "hex_data": hex_data, "mac": mac})


@app.route("/api/streetlights", methods=["GET"])
@login_required
def api_streetlights():
    """回傳智慧地圖匯出檔的路燈 marker 清單，供地圖 UI 使用。"""
    return jsonify(_map_payload())


@app.route("/api/runtime", methods=["GET"])
@login_required
def api_runtime():
    """讀 VM-B MongoDB 的 runtime collection（每 MAC 一筆 upsert，由 TCP Management 寫入）。"""
    db = _ensure_mongo()
    if db is None:
        return jsonify({"error": "mongo not connected", "items": [], "count": 0}), 503
    mac = (request.args.get("mac") or "").strip().upper()
    query = {"mac": mac} if mac else {}
    try:
        items = list(db["runtime"].find(query, {"_id": False}))
    except PyMongoError as e:
        return jsonify({"error": f"mongo: {e}", "items": [], "count": 0}), 503
    return jsonify({"items": items, "count": len(items)})


@app.route("/api/command_logs", methods=["GET"])
@login_required
def api_command_logs():
    """讀 VM-B MongoDB 的 command_logs（append-only）。預設拿最新 100 筆。"""
    db = _ensure_mongo()
    if db is None:
        return jsonify({"error": "mongo not connected", "items": [], "count": 0}), 503
    mac = (request.args.get("mac") or "").strip().upper()
    try:
        limit = max(1, min(int(request.args.get("limit", "100")), 1000))
    except ValueError:
        limit = 100
    query = {"mac": mac} if mac else {}
    try:
        cursor = (
            db["command_logs"]
            .find(query, {"_id": False})
            .sort("ts", DESCENDING)
            .limit(limit)
        )
        items = list(cursor)
    except PyMongoError as e:
        return jsonify({"error": f"mongo: {e}", "items": [], "count": 0}), 503
    return jsonify({"items": items, "count": len(items)})


@app.route("/api/messages", methods=["POST"])
def receive_api_message():
    """獨立 socket server 用這個 API 將 Gateway 資料推送到 Web subscriber。"""
    if not api_authorized():
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    hex_data = payload.get("data") or payload.get("hex_data")
    if not is_hex_payload(hex_data):
        return jsonify({"error": "data must be a non-empty hex string"}), 400

    topic = payload.get("topic")
    if topic is None:
        topic = TOPIC_CMD if payload.get("source") == "api" else TOPIC_RESP
    if topic not in (TOPIC_CMD, TOPIC_RESP):
        return jsonify({"error": "unsupported topic"}), 400

    hex_data = hex_data.strip().upper()
    event = parse_payload(topic, hex_data)
    if payload.get("timestamp"):
        event["timestamp"] = payload["timestamp"]
    print(f"[Subscriber] [API] 收到 [{topic}]: {event['command']}  Hex: {hex_data}")
    _emit_mqtt_to_socketio(event)
    maybe_ack_drd10(topic, hex_data)
    return jsonify({"ok": True})


@socketio.on("connect")
def handle_connect():
    """勿對未登入 return False：經反向代理／Docker 時，第一包 /socket.io 常讀不到 Flask session，
    會導致 Engine.IO 連不上、前端永遠「連線中」且收不到事件。已登入則登記 sid 供 send_command。"""
    sid = getattr(request, "sid", None)
    if sid and session.get("logged_in"):
        _socket_authorized_sids.add(sid)
    elif sid:
        print(f"[Subscriber] Socket.IO connect sid={sid!r}（此時無 session，按鈕發送需已登入或重整後再試）")


@socketio.on("disconnect")
def handle_disconnect():
    sid = getattr(request, "sid", None)
    if sid:
        _socket_authorized_sids.discard(sid)


@socketio.on("send_command")
@socket_auth_required
def handle_send_command(data):
    """從 Web UI 發送指令到 Gateway，payload 直接是 hex 字串"""
    if not isinstance(data, dict):
        print(f"[Subscriber] [PUB] 略過: payload 非 dict ({type(data).__name__})")
        return

    mac = data.get("mac")
    cmd_type = data.get("cmd_type")
    hex_data = data.get("hex_data")

    if not hex_data and mac in COMMANDS and cmd_type in COMMANDS[mac]:
        hex_data = COMMANDS[mac][cmd_type]

    if not hex_data:
        print(f"[Subscriber] [PUB] 略過: 無 hex_data (mac={mac!r}, cmd_type={cmd_type!r})")
        return

    hex_data = hex_data.upper()
    if COMM_MODE == "both":
        sent_mqtt = False
        sent_api = False

        if pub_client:
            pub_client.publish(TOPIC_CMD, hex_data)
            sent_mqtt = True
            print(f"[Subscriber] [PUB] 發送: {cmd_type} -> MAC: {mac}  Hex: {hex_data}")
        else:
            print("[Subscriber] [PUB] 略過: pub_client 尚未初始化")

        if send_socket_server_command(hex_data):
            sent_api = True
            print(f"[Subscriber] [SOCKET_SERVER] TCP 發送到 socket server: {cmd_type} -> MAC: {mac}  Hex: {hex_data}")
        else:
            print("[Subscriber] [SOCKET_SERVER] 略過: socket server TCP 發送失敗")

        if not sent_mqtt and not sent_api:
            print("[Subscriber] [BOTH] 略過: MQTT 與 API 都未送出")
        # both 模式不手動 emit；等待 MQTT/API 回流，並由 _emit_mqtt_to_socketio 去重。
        return

    if COMM_MODE == "api":
        if not send_socket_server_command(hex_data):
            print("[Subscriber] [SOCKET_SERVER] 略過: socket server TCP 發送失敗")
            return
        print(f"[Subscriber] [SOCKET_SERVER] TCP 發送到 socket server: {cmd_type} -> MAC: {mac}  Hex: {hex_data}")
        # API/socket_server 模式不手動 emit；socket server 會再呼叫 /api/messages 推送指令，避免 UI 重複顯示。
        return

    if COMM_MODE == "socket":
        if not send_socket_command(hex_data):
            print("[Subscriber] [SOCKET] 略過: socket 尚未連線")
            return
        print(f"[Subscriber] [SOCKET] 發送: {cmd_type} -> MAC: {mac}  Hex: {hex_data}")
        _emit_mqtt_to_socketio(parse_payload(TOPIC_CMD, hex_data))
        return

    if not pub_client:
        print("[Subscriber] [PUB] 略過: pub_client 尚未初始化")
        return

    pub_client.publish(TOPIC_CMD, hex_data)
    print(f"[Subscriber] [PUB] 發送: {cmd_type} -> MAC: {mac}  Hex: {hex_data}")
    # MQTT 模式不手動 emit：sub_client 已訂閱 TOPIC_CMD，
    # 會從 MQTT broker 收到這條訊息並透過 on_sub_message 推送到 UI。


if __name__ == "__main__":
    print(f"[Subscriber] Socket.IO async_mode={_SOCKETIO_ASYNC_MODE!r}（threading 較利於 Web 與 Paho 並存）")
    print(f"[Subscriber] 通訊模式={COMM_MODE!r}")
    if COMM_MODE == "socket":
        setup_socket()
    elif COMM_MODE in ("mqtt", "both"):
        setup_mqtt()
        if COMM_MODE == "both":
            print(f"[Subscriber] [BOTH] MQTT 已啟動，TCP 指令走 Bridge -> {SOCKET_SERVER_HOST}:{SOCKET_SERVER_BRIDGE_PORT}")
    else:
        print(f"[Subscriber] [API] 等待 socket server 推送 /api/messages，送指令走 Bridge -> {SOCKET_SERVER_HOST}:{SOCKET_SERVER_BRIDGE_PORT}")
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
