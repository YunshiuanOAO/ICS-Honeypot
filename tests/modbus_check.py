from pymodbus.client import ModbusTcpClient


IP_ADDRESS = '127.0.0.1'  # 設備 IP
PORT = 5020

# 2. 建立連線
client = ModbusTcpClient(IP_ADDRESS, port=PORT)
client.connect()
print("[*] Connect to PLC Sucecss")
# 3. 讀取資料
# 參數: address (起始位址), count (讀取數量), slave (設備站號)
# 假設我們要讀取位址 0 開始的 10 個 Holding Registers (Function Code 03)
result = client.read_holding_registers(address=0, count=100,device_id=1)

if not result.isError():
    print("讀取成功:", result.registers)
    # 處理數據範例：假設暫存器 0 是溫度，且數值放大了 10 倍 (例如 255 代表 25.5度)
    temperature = result.registers[0] / 10.0
    print(f"溫度: {temperature} °C")
else:
    print("讀取失敗:", result)

# 4. 讀取設備識別 (Device Identification)
# Function Code 43 (0x2B), MEI Type 14 (0x0E)
# read_code=1 (Basic Device Identification)
print("\n--- 讀取設備識別 ---")
try:
    mei_result = client.read_device_information(read_code=1, device_id=1)
    
    if not mei_result.isError():
        print("識別資訊讀取成功:")
        # 結果在 mei_result.information 中，是一個字典 {ObjectId: bytes}
        # 0x00: VendorName, 0x01: ProductCode, 0x02: MajorMinorRevision
        for oid, value in mei_result.information.items():
            print(f"  Object {oid}: {value.decode('utf-8')}")
    else:
        print("識別資訊讀取失敗:", mei_result)
except Exception as e:
    print(f"發生錯誤: {e}")

# 5. 讀取 Server ID (Report Server ID, FC 17) - 使用 Raw Socket
print("\n--- 讀取 Server ID (FC 17) [Raw Socket] ---")
import socket
import struct

try:
    # 建立一個新的 Raw Socket 連線
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((IP_ADDRESS, PORT))
    
    # 建構 Modbus TCP Request
    # Transaction ID: 0x0001
    # Protocol ID: 0x0000
    # Length: 0x0002 (Unit ID + PDU)
    # Unit ID: 0x01 (對應 slave=1)
    # Function Code: 0x11 (Report Slave ID)
    req = struct.pack('>HHHBB', 1, 0, 2, 1, 0x11)
    
    print(f"發送 Raw Request: {req.hex()}")
    sock.send(req)
    
    # 接收 Header (7 bytes)
    header = sock.recv(7)
    if len(header) == 7:
        tid, pid, length, uid = struct.unpack('>HHHB', header)
        # 接收 PDU
        # Length 包含了 Unit ID (1 byte)，所以 PDU 長度 = length - 1
        pdu_len = length - 1
        pdu = sock.recv(pdu_len)
        
        print(f"接收 Raw Response: {(header + pdu).hex()}")
        
        if len(pdu) > 2 and pdu[0] == 0x11:
            byte_count = pdu[1]
            slave_id_data = pdu[2:]
            print("Server ID 讀取成功:")
            print(f"  Raw Data: {slave_id_data}")
            # 最後一個 byte 是 Run Indicator
            if len(slave_id_data) > 0:
                print(f"  Decoded: {slave_id_data[:-1].decode('utf-8', errors='ignore')}")
                print(f"  Run Indicator: {hex(slave_id_data[-1])}")
        else:
            print(f"Server ID 讀取失敗或錯誤回應: {pdu.hex()}")
    else:
        print("接收 Header 失敗")

    sock.close()

except Exception as e:
    print(f"Raw Socket 發生錯誤: {e}")
# 5. 寫入測試 (Function Code 05 & 06)
print("\n--- 寫入測試 ---")
try:
    # 寫入單一線圈 (Write Single Coil, FC 05)
    # address=0, value=True (ON)
    print("嘗試寫入線圈 (Coil) Address 0 -> True")
    write_coil_result = client.write_coil(address=0, value=True, device_id=1)
    if not write_coil_result.isError():
        print("寫入線圈成功")
    else:
        print("寫入線圈失敗:", write_coil_result)

    # 寫入單一暫存器 (Write Single Register, FC 06)
    # address=0, value=12345
    print("嘗試寫入暫存器 (Register) Address 0 -> 12345")
    write_reg_result = client.write_register(address=0, value=12345, device_id=1)
    if not write_reg_result.isError():
        print("寫入暫存器成功")
    else:
        print("寫入暫存器失敗:", write_reg_result)

except Exception as e:
    print(f"寫入發生錯誤: {e}")
# 6. 驗證寫入結果 (Read Back)
print("\n--- 驗證寫入結果 ---")
try:
    # 讀取剛剛寫入的 Coil 0
    read_coil = client.read_coils(address=0, count=1, device_id=1)
    if not read_coil.isError():
        print(f"讀取 Coil 0: {read_coil.bits[0]} (預期: True)")
    else:
        print("讀取 Coil 0 失敗:", read_coil)

    # 讀取剛剛寫入的 Register 0
    read_reg = client.read_holding_registers(address=0, count=1, device_id=1)
    if not read_reg.isError():
        print(f"讀取 Register 0: {read_reg.registers[0]} (預期: 12345)")
    else:
        print("讀取 Register 0 失敗:", read_reg)

except Exception as e:
    print(f"驗證發生錯誤: {e}")

# 7. 關閉連線
client.close()