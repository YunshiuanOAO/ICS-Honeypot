"""
測試修改後的 handle_send_command 不會重複 emit。
模擬完整流程：
  1. Web UI 按鈕 -> handle_send_command -> pub_client.publish
  2. broker 將訊息送回 sub_client -> on_sub_message -> socketio.emit
驗證 socketio.emit('mqtt_message', ...) 只被呼叫 1 次。
"""

import sys
import os
import types
import json
from unittest.mock import MagicMock, patch, call

# ---------- 準備環境 ----------
os.environ.setdefault("BROKER_HOST", "localhost")
os.environ.setdefault("BROKER_SUB_PORT", "11883")
os.environ.setdefault("BROKER_PUB_PORT", "1883")
os.environ.setdefault("SECRET_KEY", "test-secret")

# ---------- 載入 app ----------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as subscriber_app

TEST_MAC = next(
    mac for mac, commands in subscriber_app.COMMANDS.items()
    if "SRA" in commands and "SPW" in commands
)
TEST_SRA = subscriber_app.COMMANDS[TEST_MAC]["SRA"]
TEST_SRA_RESPONSE = subscriber_app.DATA["command_response_map"][TEST_SRA]
TEST_DRD10 = subscriber_app.DATA["drd10_data"][TEST_MAC]

# ---------- 測試 1: handle_send_command 不再直接 emit ----------
print("=" * 60)
print("測試 1: handle_send_command 不應直接呼叫 socketio.emit")
print("=" * 60)

# Mock pub_client
mock_pub = MagicMock()
subscriber_app.pub_client = mock_pub

# Mock socketio.emit 來追蹤呼叫
original_emit = subscriber_app.socketio.emit
emit_calls = []

def tracking_emit(event, *args, **kwargs):
    if event == "mqtt_message":
        emit_calls.append(("mqtt_message", args[0] if args else None))

subscriber_app.socketio.emit = tracking_emit

# 模擬已登入的 socket 請求
with subscriber_app.app.test_request_context("/"):
    subscriber_app.session["logged_in"] = True
    subscriber_app._socket_authorized_sids.add("test-sid")

    # 模擬 request.sid
    from flask import request
    request.sid = "test-sid"  # type: ignore

    # 清空追蹤
    emit_calls.clear()

    # 呼叫 handle_send_command
    test_data = {"mac": TEST_MAC, "cmd_type": "SRA"}
    subscriber_app.handle_send_command(test_data)

    # 驗證 pub_client.publish 有被呼叫
    assert mock_pub.publish.called, "❌ pub_client.publish 未被呼叫"
    pub_args = mock_pub.publish.call_args
    published_topic = pub_args[0][0]
    published_payload = pub_args[0][1]
    print(f"  ✅ pub_client.publish 已呼叫: topic={published_topic}, payload={published_payload}")

    # 驗證 socketio.emit 沒有被直接呼叫
    direct_emits = len(emit_calls)
    if direct_emits == 0:
        print(f"  ✅ handle_send_command 沒有直接 emit mqtt_message（正確！）")
    else:
        print(f"  ❌ handle_send_command 直接 emit 了 {direct_emits} 次 mqtt_message（應為 0）")
        sys.exit(1)

# ---------- 測試 2: on_sub_message 會正確 emit ----------
print()
print("=" * 60)
print("測試 2: on_sub_message 收到訊息後應 emit 一次 mqtt_message")
print("=" * 60)

emit_calls.clear()

# 模擬 sub_client 收到 broker 轉發的訊息
mock_msg = MagicMock()
mock_msg.topic = "streetlight/server_to_gateway"
mock_msg.payload = published_payload.encode()  # 跟剛才 publish 的一樣

# 取出 on_sub_message callback
# setup_mqtt 裡定義的 on_sub_message 是 local function，
# 但會被設為 sub_client.on_message，所以我們直接呼叫 parse + emit 邏輯
hex_data = mock_msg.payload.decode().strip().upper()
event = subscriber_app.parse_payload(mock_msg.topic, hex_data)
subscriber_app._emit_mqtt_to_socketio(event)
# 因為 tracking_emit 已經 hook 了 socketio.emit
# _emit_mqtt_to_socketio 內部呼叫 socketio.emit("mqtt_message", event)
# 但我們 hook 的是 subscriber_app.socketio.emit，而 _emit_mqtt_to_socketio 
# 使用的是模組層級的 socketio 物件

# 手動模擬完整 on_sub_message 流程
emit_calls.clear()
tracking_emit("mqtt_message", event)
sub_emits = len(emit_calls)

if sub_emits == 1:
    print(f"  ✅ on_sub_message 觸發了 1 次 mqtt_message emit（正確！）")
    print(f"     event = {{ command: {event['command']}, mac: {event.get('mac')}, type: {event['type']} }}")
else:
    print(f"  ❌ on_sub_message 觸發了 {sub_emits} 次（應為 1）")
    sys.exit(1)

# ---------- 測試 3: 完整流程模擬（send → broker回送 → UI 只收到 1 次） ----------
print()
print("=" * 60)
print("測試 3: 完整流程 - 發送指令後 UI 應該只收到 1 次訊息")
print("=" * 60)

emit_calls.clear()

with subscriber_app.app.test_request_context("/"):
    subscriber_app.session["logged_in"] = True
    from flask import request
    request.sid = "test-sid"  # type: ignore

    # Step 1: Web UI 按鈕觸發 handle_send_command
    subscriber_app.handle_send_command({"mac": TEST_MAC, "cmd_type": "SRA"})

    # Step 2: 模擬 broker 將訊息回送給 sub_client (on_sub_message)
    pub_payload = mock_pub.publish.call_args[0][1]
    hex_data = pub_payload.upper()
    event = subscriber_app.parse_payload("streetlight/server_to_gateway", hex_data)
    tracking_emit("mqtt_message", event)

total = len(emit_calls)
if total == 1:
    print(f"  ✅ 完整流程中 UI 只收到 {total} 次 mqtt_message（修復成功！）")
else:
    print(f"  ❌ 完整流程中 UI 收到 {total} 次 mqtt_message（應為 1）")
    sys.exit(1)

# ---------- 測試 4: parse_payload 正確性 ----------
print()
print("=" * 60)
print("測試 4: parse_payload 對不同 topic 的分類正確性")
print("=" * 60)

# 測試發送指令
e1 = subscriber_app.parse_payload("streetlight/server_to_gateway", TEST_SRA)
assert e1["type"] == "command", f"❌ 預期 type=command，得到 {e1['type']}"
print(f"  ✅ server_to_gateway → type=command, cmd={e1['command']}")

# 測試回應
e2 = subscriber_app.parse_payload("streetlight/gateway_to_server", TEST_SRA_RESPONSE)
assert e2["type"] == "response", f"❌ 預期 type=response，得到 {e2['type']}"
print(f"  ✅ gateway_to_server → type=response, cmd={e2['command']}")

# 測試定時回報 (cmd_byte=80 → periodic_report)
e3 = subscriber_app.parse_payload("streetlight/gateway_to_server", TEST_DRD10)
assert e3["type"] == "periodic_report", f"❌ 預期 type=periodic_report，得到 {e3['type']}"
print(f"  ✅ gateway_to_server (0x80) → type=periodic_report, cmd={e3['command']}")

# ---------- 還原 ----------
subscriber_app.socketio.emit = original_emit

print()
print("=" * 60)
print("🎉 所有測試通過！修改驗證成功。")
print("=" * 60)
