import snap7
from snap7.util import get_int, get_real, get_bool

# 1. 設定連線參數
IP_ADDRESS = '127.0.0.1'
RACK = 0  # 機架號 (S7-1200/1500 通常是 0)
SLOT = 2  # 插槽號 (S7-1200/1500 通常是 1，S7-300 通常是 2)

client = snap7.client.Client()

try:
    # 2. 建立連線
    print(f"正在連線到 {IP_ADDRESS}...")
    client.connect(IP_ADDRESS, RACK, SLOT)
    print("連線成功！")

    # 3. 讀取資料 (Read Data Block)
    # 參數: db_number (DB編號), start (起始 Byte), size (要讀多少 Bytes)
    # 假設我們要讀取 DB1，從第 0 個 Byte 開始，讀取 10 個 Bytes
    db_number = 1
    start_offset = 0
    size = 10 
    
    # 讀回來的是 bytearray (原始二進位資料)
    data = client.db_read(db_number, start_offset, size)
    
    print(f"原始 Byte 資料: {data}")

    # 4. 解析資料 (S7 也是 Big-Endian)
    # 必須知道 PLC 裡的變數型態對應哪個 Byte 位置

    # 範例 A: 讀取整數 (Int is 2 bytes) -> 假設在 Offset 0
    val_int = get_int(data, 0) 
    print(f"Offset 0 (Int): {val_int}")

    # 範例 B: 讀取浮點數 (Real is 4 bytes) -> 假設在 Offset 2
    val_real = get_real(data, 2)
    print(f"Offset 2 (Real/Float): {val_real}")
    
    # 範例 C: 讀取布林值 (Bool) -> 假設在 Offset 6 的第 0 個 bit
    val_bool = get_bool(data, 6, 0)
    print(f"Offset 6.0 (Bool): {val_bool}")

except Exception as e:
    print(f"發生錯誤: {e}")
finally:
    # 5. 斷開連線
    if client.get_connected():
        client.disconnect()
        print("連線已關閉")