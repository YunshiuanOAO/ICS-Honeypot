import socket
import threading
import struct
import time
import sys
import os
from db.database import LogDB
from plc.simulation import SimulationEngine, ConfigDrivenSimulator

# 載入場景載入器
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'profiles'))
try:
    from profile_loader import get_s7_profile
    PROFILES_AVAILABLE = True
except ImportError:
    print("[S7PLC] Warning: profile_loader not found. Profile support disabled.")
    PROFILES_AVAILABLE = False
    get_s7_profile = None

class S7PLC:
    """
    S7 PLC 模擬器 (S7-300/1200/1500)
    
    支援三種模擬配置模式：
    1. 最簡配置（使用預設場景）：
       simulation_config = {"scenario": "water_treatment"}
       
    2. 部分覆蓋（基於場景 + 自定義）：
       simulation_config = {
           "scenario": "manufacturing",
           "db": {"1": {"0": {"wave": "sine", "min": 0, "max": 1000, "period": 60}}}
       }
       
    3. 完整自定義：
       simulation_config = {
           "db": {"1": {"0": {...}, "2": {...}}},
           "m": {"0": {...}},
           "q": {"0": {...}}
       }
    """
    
    PROFILES = {
        "S7-300": {
            "valid_slots": [2], # Rack 0, Slot 2
            "order_code": "6ES7 315-2AG10-0AB0",
            "module_name": "CPU 315-2 DP",
            "max_pdu": 240,
            "system_name": "S7-300 Station",
            "serial_number": "S C-C2UR28922013",
            "plant_id": "Factory_Main_Unit",
            "oem_id": "Siemens",
            "location": "Rack 0 Slot 2"
        },
        "S7-1200": {
            "valid_slots": [1], # Rack 0, Slot 1
            "order_code": "6ES7 214-1AG40-0XB0",
            "module_name": "CPU 1214C",
            "max_pdu": 480,
            "system_name": "S7-1200 Station",
            "serial_number": "S C-C2UR28922014",
            "plant_id": "Plant_Unit_1200",
            "oem_id": "Siemens",
            "location": "Rack 0 Slot 1"
        },
        "S7-1500": {
            "valid_slots": [1],
            "order_code": "6ES7 511-1AK01-0AB0",
            "module_name": "CPU 1511-1 PN",
            "max_pdu": 960,
            "system_name": "S7-1500 Station",
            "serial_number": "S C-C2UR28922015",
            "plant_id": "Plant_Unit_1500",
            "oem_id": "Siemens",
            "location": "Rack 0 Slot 1"
        }
    }

    def __init__(self, port=102, db: LogDB = None, model="S7-300", simulation_config=None):
        self.host = '0.0.0.0'
        self.port = port
        self.db = db
        self.model_name = model
        
        # Load profile
        # Default to S7-300 if unknown
        base_model = "S7-300"
        if "1200" in model: base_model = "S7-1200"
        elif "1500" in model: base_model = "S7-1500"
        
        self.profile = self.PROFILES.get(base_model, self.PROFILES["S7-300"])
        print(f"Loaded S7 Profile: {base_model} (Order: {self.profile['order_code']})")

        self.running = False
        self.sock = None
        self.thread = None
        
        # Memory Storage
        # Structure: {
        #   'DB': { db_num: bytearray },
        #   'M': bytearray(size),
        #   'I': bytearray(size),
        #   'Q': bytearray(size)
        # }
        self.storage = {
            'DB': {},
            'M': bytearray(65536), # 64KB Merkers
            'I': bytearray(65536), # 64KB Inputs
            'Q': bytearray(65536)  # 64KB Outputs
        }
        
        # 配置驅動的模擬器
        self.simulation_config = simulation_config or {}
        self.sim_engine = SimulationEngine()
        self.sim_thread = None
        
        # 解析 S7 專用的模擬配置
        self._s7_sim_config = self._parse_s7_simulation_config()

    def _ensure_db(self, db_num, min_size=1024):
        if db_num not in self.storage['DB']:
            self.storage['DB'][db_num] = bytearray(min_size)
        elif len(self.storage['DB'][db_num]) < min_size:
            # Resize if needed (naive approach)
            self.storage['DB'][db_num].extend(bytearray(min_size - len(self.storage['DB'][db_num])))
        return self.storage['DB'][db_num]

    def _read_data(self, area, db_num, start, length):
        # Area codes (approx):
        # 0x84: DB
        # 0x83: Merkers (M)
        # 0x81: Inputs (I)
        # 0x82: Outputs (Q)
        
        try:
            source = None
            if area == 0x84: # DB
                source = self._ensure_db(db_num, start + length)
            elif area == 0x83: # M
                source = self.storage['M']
            elif area == 0x81: # I
                source = self.storage['I']
            elif area == 0x82: # Q
                source = self.storage['Q']
            
            if source is not None:
                if start + length <= len(source):
                    return source[start : start + length]
                else:
                     # Auto-expand M/I/Q if needed or return zeros?
                     # Let's return zeros for OOB for robustness
                     return bytearray(length)
            return bytearray(length)
        except Exception:
            return bytearray(length)

    def _write_data(self, area, db_num, start, data):
        try:
            target = None
            length = len(data)
            if area == 0x84:
                target = self._ensure_db(db_num, start + length)
            elif area == 0x83:
                target = self.storage['M']
            elif area == 0x81:
                target = self.storage['I']
            elif area == 0x82:
                target = self.storage['Q']
                
            if target is not None:
                # Ensure size
                if start + length > len(target):
                    # Only for dictionaries (DB) we might care, for fixed we might truncate or ignore
                    # For simplicty in honeypot: expand global bytearrays if needed?
                    # Let's just limit to existing size for fixed types
                    pass
                
                # Write
                end = min(start + length, len(target))
                write_len = end - start
                if write_len > 0:
                    target[start:start+write_len] = data[:write_len]
        except Exception as e:
            print(f"Write Error: {e}")

    def _parse_s7_simulation_config(self):
        """
        解析 S7 專用的模擬配置
        
        配置格式：
        {
            "profile": "water_treatment",  # 可選，使用預設配置
            "db": {
                "1": {  # DB1
                    "0": {"type": "INT", "wave": "sine", "min": 200, "max": 800, "period": 300},
                    "2": {"type": "INT", "wave": "random_walk", "min": 50, "max": 200, "step": 5},
                    "4": {"type": "INT", "wave": "sawtooth", "min": 0, "max": 5000, "period": 600},
                    "6": {"type": "REAL", "wave": "noise", "base": 120.5, "amplitude": 2.0}
                }
            },
            "m": {
                "0": {"type": "BYTE", "wave": "status_flags"},
                "10": {"type": "BYTE", "wave": "counter"}
            }
        }
        """
        config = {
            "db": {},
            "m": {},
            "i": {},
            "q": {}
        }
        
        profile_name = self.simulation_config.get("profile")
        
        # 使用配置載入器（從 JSON 檔案）
        if profile_name and PROFILES_AVAILABLE:
            s7_profile = get_s7_profile(profile_name)
            if s7_profile:
                # 載入場景配置
                config["db"] = s7_profile.get("db", {})
                config["m"] = s7_profile.get("m", {})
                config["i"] = s7_profile.get("i", {})
                config["q"] = s7_profile.get("q", {})
                print(f"[S7 Simulator] Loaded profile from JSON: {profile_name}")
            else:
                print(f"[S7 Simulator] Warning: Profile '{profile_name}' not found")
        elif not self.simulation_config and PROFILES_AVAILABLE:
            # 沒有指定場景也沒有自定義配置，使用預設水處理廠
            s7_profile = get_s7_profile("water_treatment")
            if s7_profile:
                config["db"] = s7_profile.get("db", {})
                config["m"] = s7_profile.get("m", {})
                config["i"] = s7_profile.get("i", {})
                config["q"] = s7_profile.get("q", {})
                print("[S7 Simulator] No config provided, using default: water_treatment (from JSON)")
        
        # 覆蓋自定義配置
        custom_db = self.simulation_config.get("db", {})
        for db_num, offsets in custom_db.items():
            db_key = str(db_num)
            if db_key not in config["db"]:
                config["db"][db_key] = {}
            for offset, cfg in offsets.items():
                config["db"][db_key][int(offset)] = cfg
        
        custom_m = self.simulation_config.get("m", {})
        for offset, cfg in custom_m.items():
            config["m"][int(offset)] = cfg
        
        return config
    
    def _generate_s7_value(self, cfg: dict, key: str) -> bytes:
        """根據配置生成 S7 數據"""
        wave = cfg.get("wave", "fixed")
        data_type = cfg.get("type", "INT")
        
        if wave == "fixed":
            value = cfg.get("value", 0)
        elif wave == "sine":
            value = self.sim_engine.sine_wave(
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("period", 300)
            )
        elif wave == "sawtooth":
            value = self.sim_engine.sawtooth_wave(
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("period", 600)
            )
        elif wave == "triangle":
            value = self.sim_engine.triangle_wave(
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("period", 600)
            )
        elif wave == "random_walk":
            if not hasattr(self, '_random_walk_state'):
                self._random_walk_state = {}
            if key not in self._random_walk_state:
                self._random_walk_state[key] = cfg.get("initial", (cfg.get("min", 0) + cfg.get("max", 65535)) // 2)
            
            value = self.sim_engine.random_walk(
                self._random_walk_state[key],
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("step", 5)
            )
            self._random_walk_state[key] = value
        elif wave == "noise":
            value = self.sim_engine.process_noise_float(
                cfg.get("base", 0),
                cfg.get("amplitude", 1.0)
            )
        elif wave == "counter":
            value = int(self.sim_engine.get_time()) % cfg.get("max", 256)
        elif wave == "status_flags":
            # 特殊處理狀態標誌位元組
            value = 0
            if self.sim_engine.square_wave(10, 0): value |= 0x01  # Running
            if self.sim_engine.square_wave(5, 5): value |= 0x02   # Warning blink
            if self.sim_engine.random_int(0, 100) > 95: value |= 0x04  # Random error
            return bytes([value])
        else:
            value = 0
        
        # 根據數據類型打包
        if data_type == "INT" or data_type == "WORD":
            return struct.pack('>H', int(value) & 0xFFFF)
        elif data_type == "DINT" or data_type == "DWORD":
            return struct.pack('>I', int(value) & 0xFFFFFFFF)
        elif data_type == "REAL":
            return struct.pack('>f', float(value))
        elif data_type == "BYTE":
            return bytes([int(value) & 0xFF])
        else:
            return struct.pack('>H', int(value) & 0xFFFF)

    def _run_simulation(self):
        """
        背景執行緒：使用配置驅動的模擬器更新 S7 數據
        """
        print("S7 Simulation Thread Started (Config-Driven)")
        
        # 確保 DB1 存在
        self._ensure_db(1, 1024)
        
        # 顯示載入的配置摘要
        db_count = len(self._s7_sim_config.get("db", {}))
        m_count = len(self._s7_sim_config.get("m", {}))
        q_count = len(self._s7_sim_config.get("q", {}))
        print(f"[S7 Simulator] Active config: {db_count} DB(s), {m_count} Merker(s), {q_count} Output(s)")
        
        while self.running:
            try:
                # 1. 更新 Data Blocks
                for db_num_str, offsets in self._s7_sim_config.get("db", {}).items():
                    db_num = int(db_num_str)
                    self._ensure_db(db_num, 1024)
                    
                    for offset, cfg in offsets.items():
                        key = f"db{db_num}_{offset}"
                        data = self._generate_s7_value(cfg, key)
                        self._write_data(0x84, db_num, int(offset), data)
                
                # 2. 更新 Merkers (M)
                for offset, cfg in self._s7_sim_config.get("m", {}).items():
                    key = f"m_{offset}"
                    data = self._generate_s7_value(cfg, key)
                    self._write_data(0x83, 0, int(offset), data)
                
                # 3. 更新 Outputs (Q) - 如果有配置
                for offset, cfg in self._s7_sim_config.get("q", {}).items():
                    key = f"q_{offset}"
                    data = self._generate_s7_value(cfg, key)
                    self._write_data(0x82, 0, int(offset), data)

                time.sleep(1)
            except Exception as e:
                print(f"S7 Simulation Error: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(5)

    def reload_simulation_config(self, new_config: dict):
        """
        熱更新模擬配置（可從 server 動態下發）
        
        Args:
            new_config: 新的模擬配置字典
        """
        self.simulation_config = new_config or {}
        self._s7_sim_config = self._parse_s7_simulation_config()
        if hasattr(self, '_random_walk_state'):
            self._random_walk_state = {}
        print("[S7PLC] Simulation config reloaded")

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run_server)
        self.thread.daemon = True
        self.thread.start()
        
        # Start Simulation Thread
        self.sim_thread = threading.Thread(target=self._run_simulation)
        self.sim_thread.daemon = True
        self.sim_thread.start()
        
        print(f"S7 PLC started on port {self.port}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        print("S7 PLC stopped")

    def _run_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            
            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    client_handler = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr)
                    )
                    client_handler.start()
                except OSError:
                    break
        except Exception as e:
            print(f"S7 Server Error: {e}")

    def _handle_client(self, client_sock, addr):
        attacker_ip = addr[0]
        print(f"S7 connection from {attacker_ip}")
        
        # 設置接收超時，避免永久等待
        client_sock.settimeout(30.0)  # 30 秒超時
        
        try:
            while True:
                # TPKT Header (4 bytes)
                # Version (1), Reserved (1), Length (2)
                try:
                    tpkt_header = client_sock.recv(4)
                    if not tpkt_header or len(tpkt_header) < 4:
                        break
                except socket.timeout:
                    print(f"[S7] Connection timeout from {attacker_ip}")
                    break
                
                version, reserved, length = struct.unpack('>BBH', tpkt_header)
                
                # Read the rest of the packet (COTP + S7)
                # Length includes TPKT header
                remaining_length = length - 4
                if remaining_length <= 0:
                    continue
                    
                try:
                    data = client_sock.recv(remaining_length)
                    if not data:
                        break
                except socket.timeout:
                    print(f"[S7] Data receive timeout from {attacker_ip}")
                    break
                
                full_request = tpkt_header + data
                elk_meta = {"s7.tpkt_len": length}

                # Parse COTP
                # COTP Header Length (1 byte)
                cotp_len = data[0]
                cotp_pdu_type = data[1]
                
                response_data = b""

                # Handle COTP Connection Request (CR) -> 0xE0
                if cotp_pdu_type == 0xE0:
                    # Validate Destination Reference (Rack/Slot)
                    # CR Structure: Len(1), PDU(1), DstRef(2), SrcRef(2), Class(1), Params...
                    # TSAP is in parameters (Parameter Code 0xC1 for Src, 0xC2 for Dst)
                    
                    # Extract Source Reference (bytes 4-5 of data, i.e., indices 4 and 5)
                    # data includes COTP header length byte at 0
                    if len(data) >= 6:
                        src_ref = data[4:6]
                    else:
                        src_ref = b'\x00\x00'

                    # Let's parse parameters to find TSAP
                    # Param start at index 6 (if no optional fixed parts)
                    # Actually CR fixed part is 5 bytes: Dst(2), Src(2), Class(1)
                    # So params start at 1 + 1 + 5 = 7
                    
                    valid_connection = False
                    idx = 7
                    while idx < cotp_len + 1:
                        if idx + 1 >= len(data): break
                        
                        param_code = data[idx]
                        param_len = data[idx+1]
                        if idx + 2 + param_len > len(data): break
                        
                        param_val = data[idx+2 : idx+2+param_len]
                        
                        if param_code == 0xC1: # Calling TSAP (Client Source)
                            elk_meta['s7.cotp.src_tsap'] = param_val.hex()
                            pass
                        elif param_code == 0xC2: # Called TSAP (Server Destination)
                            elk_meta['s7.cotp.dst_tsap'] = param_val.hex()
                            if len(param_val) >= 2:
                                requested_slot = param_val[1] & 0x1F # Lower 5 bits
                                if requested_slot in self.profile['valid_slots']:
                                    valid_connection = True
                                else:
                                    print(f"S7 Reject: Invalid Slot {requested_slot} for {self.model_name}")
                        
                        idx += 2 + param_len

                    if not valid_connection:
                        # Reject connection (COTP DR)
                        resp_tpkt = b'\x03\x00\x00\x0B'
                        resp_cotp = b'\x06\x80' + b'\x00\x00' + src_ref + b'\x00' # Dst=0000?, Src=src_ref?
                        # DR Format: Len(6), PDU(80), Dst(2), Src(2), Reason(1)
                        # Dst should be the SrcRef from CR
                        resp_cotp = b'\x06\x80' + src_ref + b'\x00\x00' + b'\x01' # Reason 01
                        
                        response_data = resp_tpkt + resp_cotp
                        
                        if self.db:
                            elk_meta['s7.action'] = 'reject_connection'
                            self.db.log_interaction(attacker_ip, "s7comm", full_request, response_data, elk_meta)
                            
                        client_sock.send(response_data)
                        break

                    # Respond with Connection Confirm (CC) -> 0xD0
                    # TPKT
                    resp_tpkt = b'\x03\x00\x00\x16' # Length 22
                    # COTP CC
                    # Length (17), PDU Type (0xD0), Dest Ref (2), Src Ref (2), Class (1)
                    # Dest Ref must equal CR's Src Ref
                    resp_cotp = b'\x11\xD0' + src_ref + b'\x00\x02\x00' 
                    # Parameters (TPDU Size, etc.) - simplified
                    resp_cotp += b'\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02'
                    
                    response_data = resp_tpkt + resp_cotp
                    
                # Handle S7 Data (DT) -> 0xF0
                elif cotp_pdu_type == 0xF0:
                    # S7 PDU starts after COTP header
                    s7_data = data[cotp_len + 1:]
                    if len(s7_data) > 0:
                        # S7 Header
                        # Protocol ID (1) -> 0x32
                        # ROSCTR (1) -> 0x01 (Job), 0x03 (Ack Data)
                        proto_id = s7_data[0]
                        rosctr = s7_data[1]
                        
                        ROSCTR_MAP = {
                            1: "Job",
                            2: "Ack",
                            3: "Ack_Data",
                            7: "UserData"
                        }
                        
                        elk_meta['s7.proto_id'] = proto_id
                        elk_meta['s7.rosctr'] = rosctr
                        elk_meta['s7.pdu_type'] = ROSCTR_MAP.get(rosctr, "Unknown")
                        
                        if proto_id == 0x32:
                            if rosctr == 0x01 or rosctr == 0x07: # Job or UserData
                                # Setup Communication (0xF0) or Read SZL (0x04)
                                
                                param_len = struct.unpack('>H', s7_data[6:8])[0]
                                data_len = struct.unpack('>H', s7_data[8:10])[0]
                                param_data = s7_data[10 : 10 + param_len]
                                s7_data_payload = s7_data[10 + param_len : 10 + param_len + data_len]
                                
                                if len(param_data) > 0:
                                    func_code = param_data[0]
                                    elk_meta['s7.function_code'] = func_code
                                    
                                    if func_code == 0xF0: # Setup Communication
                                        # Construct a generic positive response (Ack Data)
                                        # TPKT + COTP DT + S7 Ack Data
                                        
                                        # S7 Ack Data Header
                                        # 0x32, 0x03 (Ack Data), Reserved (2), PDU Ref (2), Param Len (2), Data Len (2), Error (2)
                                        
                                        # Grab PDU Ref from request to echo it
                                        pdu_ref = s7_data[4:6]
                                        
                                        s7_resp_header = b'\x32\x03\x00\x00' + pdu_ref + b'\x00\x08\x00\x00\x00\x00'
                                        # Parameter: Setup Comm (0xF0) response
                                        # Function (1), Reserved (1), Max Amq Caller (2), Max Amq Callee (2), PDU Length (2)
                                        max_pdu = self.profile['max_pdu']
                                        s7_resp_param = b'\xF0\x00\x00\x01\x00\x01' + struct.pack('>H', max_pdu)
                                        
                                        s7_full_resp = s7_resp_header + s7_resp_param
                                        
                                        # Wrap in COTP DT
                                        # COTP Length (2), PDU Type (0xF0), EOT (0x80)
                                        cotp_resp = b'\x02\xF0\x80'
                                        
                                        # Wrap in TPKT
                                        total_len = 4 + len(cotp_resp) + len(s7_full_resp)
                                        tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                        
                                        
                                        response_data = tpkt_resp + cotp_resp + s7_full_resp
                                        
                                    elif func_code == 0x05: # Write Var
                                        # Write Request: [0x05] [ItemCount] [ItemHeader...] [DataHeader...] [Data...]
                                        # Note: Write is complex because Item Headers and Data are separated.
                                        # Item Headers come first, then Data for each item.
                                        
                                        if len(param_data) > 1:
                                            item_count = param_data[1]
                                            
                                            # We need to parse items to know where to write
                                            # Structure of Param: [Func][Count] [Item1] [Item2]...
                                            # Item Structure: 12 bytes
                                            
                                            # Structure of Data Payload (s7_data_payload):
                                            # [ReturnCode(1)][TransSize(1)][Len(2)][Data...]
                                            
                                            current_param_idx = 2
                                            current_data_idx = 0
                                            
                                            # Only support 1 item for simplicity in v1
                                            if item_count >= 1:
                                                # Parse Item Header
                                                # [12][0a][10][Trans][Len][DB][Area][Addr]
                                                item_bytes = param_data[current_param_idx : current_param_idx + 12]
                                                if len(item_bytes) == 12:
                                                    transport_type = item_bytes[3]
                                                    item_len = struct.unpack('>H', item_bytes[4:6])[0]
                                                    db_num = struct.unpack('>H', item_bytes[6:8])[0]
                                                    area = item_bytes[8]
                                                    address_raw = item_bytes[9:12] # 3 bytes
                                                    # Address is (ByteIndex * 8) + BitIndex
                                                    address_int = struct.unpack('>I', b'\x00' + address_raw)[0]
                                                    byte_index = address_int >> 3
                                                    bit_index = address_int & 0x07
                                                    
                                                    elk_meta['s7.area'] = area
                                                    elk_meta['s7.db_number'] = db_num
                                                    elk_meta['s7.address'] = f"{byte_index}.{bit_index}"
                                                    
                                                    # Parse Data Payload
                                                    # [ReturnCode(1)][TransSize(1)][Len(2)][Data...]
                                                    # Return Code is NOT in request data payload? 
                                                    # Actually Write Data structure: [ReturnCode(1)? No]
                                                    # Request Data: [ReturnCode(1)]?? No.
                                                    # Request Data Item: [Reserved(1)=0][TransSize(1)][Length(2)][Data]
                                                    
                                                    if current_data_idx + 4 <= len(s7_data_payload):
                                                        # rsv = s7_data_payload[current_data_idx]
                                                        # ts = s7_data_payload[current_data_idx+1]
                                                        payload_len_bits = struct.unpack('>H', s7_data_payload[current_data_idx+2:current_data_idx+4])[0]
                                                        
                                                        payload_len_bytes = (payload_len_bits + 7) // 8
                                                        # If TransSize is 3 (bit), 4 (word), 5 (int)...
                                                        # For TransSize 4 (Word), len is in bits.
                                                        
                                                        data_bytes = s7_data_payload[current_data_idx+4 : current_data_idx+4+payload_len_bytes]
                                                        
                                                        # Log Write Data (Hex)
                                                        elk_meta['s7.write_data'] = data_bytes.hex()

                                                        # Perform Write
                                                        self._write_data(area, db_num, byte_index, data_bytes)
                                                        
                                                        # Construct Response (Ack)
                                                        # Data: [ReturnCode(1)] for each item
                                                        resp_data = b'\xFF' # Success
                                                        
                                                        pdu_ref = s7_data[4:6]
                                                        
                                                        # Param: Func(0x05), Count(1)
                                                        resp_param = b'\x05\x01'
                                                        
                                                        s7_resp_header = b'\x32\x03\x00\x00' + pdu_ref + \
                                                                         struct.pack('>H', len(resp_param)) + \
                                                                         struct.pack('>H', len(resp_data)) + \
                                                                         b'\x00\x00'
                                                        
                                                        s7_full_resp = s7_resp_header + resp_param + resp_data
                                                        
                                                        cotp_resp = b'\x02\xF0\x80'
                                                        total_len = 4 + len(cotp_resp) + len(s7_full_resp)
                                                        tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                                        
                                                        response_data = tpkt_resp + cotp_resp + s7_full_resp
                                        
                                    elif func_code == 0x04: # Read Var or Read SZL
                                        # Check if it's a standard Read Var request
                                        # Structure: [0x04] [ItemCount] [Item1: 0x12 ...]
                                        if len(param_data) > 2 and param_data[2] == 0x12:
                                            # Handle Read Var (e.g., DB Read)
                                            item_count = param_data[1]
                                            
                                            # We only support 1 item for now to keep it simple
                                            if item_count >= 1:
                                                # Parse Item 1
                                                # Param Data Indices:
                                                # 0: Func (0x04)
                                                # 1: Count
                                                # 2: Var Spec (0x12)
                                                # 3: Length of remaining item bytes (usually 0x0a)
                                                # 4: Syntax ID (0x10)
                                                # 5: Transport Type
                                                # 6-7: Length (count of elements)
                                                # 8-9: DB Number
                                                # 10: Area
                                                # 11-13: Address
                                                
                                                if len(param_data) >= 14:
                                                    transport_type = param_data[5]
                                                    read_len = struct.unpack('>H', param_data[6:8])[0]
                                                    db_num = struct.unpack('>H', param_data[8:10])[0]
                                                    area = param_data[10]
                                                    address_raw = param_data[11:14]
                                                    address_int = struct.unpack('>I', b'\x00' + address_raw)[0]
                                                    byte_index = address_int >> 3
                                                    
                                                    elk_meta['s7.area'] = area
                                                    elk_meta['s7.db_number'] = db_num
                                                    elk_meta['s7.address'] = f"{byte_index}.0"

                                                    # Calculate bytes to return
                                                    data_len_bytes = 0
                                                    if transport_type == 0x01: # Bit
                                                        data_len_bytes = (read_len + 7) // 8
                                                    elif transport_type == 0x02: # Byte
                                                        data_len_bytes = read_len
                                                    elif transport_type == 0x04: # Word
                                                        data_len_bytes = read_len * 2
                                                    else:
                                                        data_len_bytes = read_len # Fallback
                                                    
                                                    # Fetch data from storage
                                                    resp_data_content = self._read_data(area, db_num, byte_index, data_len_bytes)
                                                    
                                                    # Construct Response
                                                    
                                                    # S7 Header (Ack Data)
                                                    # 0x32, 0x03 (Ack Data), Reserved (2), PDU Ref (2), Param Len (2), Data Len (2), Error (2)
                                                    
                                                    pdu_ref = s7_data[4:6]
                                                    
                                                    # Param: Func(0x04), Count(1)
                                                    resp_param = b'\x04\x01'
                                                    
                                                    # Data: Return Code(1), Transport Size(1), Length(2), Data(n)
                                                    # Return Code: 0xFF (Success)
                                                    # Transport Size: 0x04 (Byte/Word/DWord) -> Size in bits
                                                    # If original was Bit (0x01), return in bits? Usually S7 returns 0x03 (Bit), 0x04 (Byte/Word)
                                                    # Let's use 0x04 (Byte/Word) for simplicity unless it's strictly bit
                                                    
                                                    resp_trans_size = 0x04 # Byte/Word
                                                    if transport_type == 0x01:
                                                        resp_trans_size = 0x03 # Bit access
                                                    
                                                    resp_data_item_header = b'\xFF' + struct.pack('B', resp_trans_size) + struct.pack('>H', data_len_bytes * 8)
                                                    
                                                    resp_data = resp_data_item_header + resp_data_content
                                                    
                                                    s7_resp_header = b'\x32\x03\x00\x00' + pdu_ref + \
                                                                     struct.pack('>H', len(resp_param)) + \
                                                                     struct.pack('>H', len(resp_data)) + \
                                                                     b'\x00\x00'
                                                    
                                                    s7_full_resp = s7_resp_header + resp_param + resp_data
                                                    
                                                    cotp_resp = b'\x02\xF0\x80'
                                                    total_len = 4 + len(cotp_resp) + len(s7_full_resp)
                                                    tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                                    
                                                    response_data = tpkt_resp + cotp_resp + s7_full_resp

                                    elif func_code == 0x00: # UserData (e.g. Read SZL)
                                        # UserData: Param[0]=0x00, Param[1]=0x01 (Read SZL)
                                        # Data: [RetCode][TransSize][Len][ID][Index]
                                        if len(param_data) >= 2 and param_data[1] == 0x01:
                                            szl_id = 0
                                            szl_index = 0
                                            if len(s7_data_payload) >= 8:
                                                szl_id = struct.unpack('>H', s7_data_payload[4:6])[0]
                                                szl_index = struct.unpack('>H', s7_data_payload[6:8])[0]
                                            
                                            elk_meta['s7.szl_id'] = f"0x{szl_id:04X}"
                                            elk_meta['s7.szl_index'] = szl_index
                                            
                                            if szl_id == 0x0011: # Module Identification
                                                # Construct SZL Response
                                                # S7 Header (UserData 0x07) + Param (Mirror) + Data (SZL List)
                                                
                                                pdu_ref = s7_data[4:6]
                                                
                                                article_no = self.profile['order_code'].ljust(20, '\x00').encode('utf-8')[:20]
                                                module_name = self.profile['module_name'].encode('utf-8').ljust(16, b'\x00')[:16]
                                                
                                                # SZL Entry (28 bytes)
                                                # Index(2), ArticleNo(20), ModuleType(2), Firmware(2), Padding(2)
                                                szl_entry = struct.pack('>H', szl_index) + article_no + b'\x00\x00' + b'\x00\x01' + b'\x00\x00'
                                                
                                                # SZL List Header (4 bytes)
                                                # LENTHDR(2) = 28, N_DR(2) = 1
                                                szl_list_header = struct.pack('>HH', 28, 1)
                                                
                                                # S7 Data Item Header (4 bytes)
                                                # Return Code(1)=0xFF, TransSize(1)=0x09 (Octet String), Length(2)
                                                total_data_len = len(szl_list_header) + len(szl_entry)
                                                szl_data_item_header = b'\xFF\x09' + struct.pack('>H', total_data_len)
                                                
                                                szl_data = szl_data_item_header + szl_list_header + szl_entry
                                                
                                                # UserData Response Param: Mirror request
                                                szl_param = param_data 
                                                
                                                # S7 Header
                                                # ROSCTR 0x07 (UserData)
                                                s7_resp_header = b'\x32\x07\x00\x00' + pdu_ref + \
                                                                 struct.pack('>H', len(szl_param)) + \
                                                                 struct.pack('>H', len(szl_data)) + \
                                                                 b'\x00\x00'
                                                
                                                s7_full_resp = s7_resp_header + szl_param + szl_data
                                                
                                                cotp_resp = b'\x02\xF0\x80'
                                                total_len = 4 + len(cotp_resp) + len(s7_full_resp)
                                                tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                                
                                                response_data = tpkt_resp + cotp_resp + s7_full_resp
                                            
                                            elif szl_id == 0x001C: # Component Identification
                                                # Return expanded component info (System Name, Component Name, Plant ID, etc.)
                                                pdu_ref = s7_data[4:6]
                                                
                                                # Helper to create SZL entry
                                                def make_szl_entry(idx, data):
                                                    # Index(2) + Data + Padding to align?
                                                    # For 0x001C, entries vary in size but usually 34 bytes in total structure (Index(2) + 32 bytes Data)
                                                    # Conpot uses 34 bytes total length for most entries (2 bytes index + 32 bytes data)
                                                    # Exception: Index 0x04 (Copyright) is 26+6 bytes.
                                                    
                                                    # Standard entry: Index (2) + String (32)
                                                    entry_data = data.encode('latin-1').ljust(32, b'\x00')[:32]
                                                    return struct.pack('>H', idx) + entry_data

                                                # 1. Automation System Name
                                                e1 = make_szl_entry(1, self.profile.get('system_name', 'S7-300 Station'))
                                                # 2. Component Name
                                                e2 = make_szl_entry(2, self.profile.get('module_name', 'CPU 315-2 PN/DP'))
                                                # 3. Plant Identification
                                                e3 = make_szl_entry(3, self.profile.get('plant_id', 'Factory_Main_Unit'))
                                                # 4. Copyright
                                                e4 = struct.pack('>H', 4) + b'Original MC 575'.ljust(26, b'\x00') + b'\x00'*6
                                                # 5. Serial Number
                                                e5 = make_szl_entry(5, self.profile.get('serial_number', 'S C-C2UR28922013'))
                                                # 7. Module Type Name
                                                e7 = make_szl_entry(7, self.profile.get('module_name', 'CPU 315-2 PN/DP'))
                                                # A. OEM ID
                                                oem = self.profile.get('oem_id', 'Siemens')
                                                eA = struct.pack('>H', 0x0A) + oem.encode('latin-1').ljust(20, b'\x00') + b'\x00'*6 + b'\x00\x00' + b'\x00'*4
                                                # B. Location Designation
                                                eB = make_szl_entry(0x0B, self.profile.get('location', 'Rack 0 Slot 2'))

                                                # Concatenate all entries
                                                szl_entries_data = e1 + e2 + e3 + e4 + e5 + e7 + eA + eB
                                                num_entries = 8
                                                entry_len = 34 # Most are 34 bytes. Note: standard S7 SZL list usually has uniform length entries?
                                                               # Wait, Conpot constructs them individually. But in the S7 header, LENTHDR is defined.
                                                               # If entries have variable length, LENTHDR might not apply easily or we define it as largest?
                                                               # Conpot uses LENTHDR=34 for 0x001C. Let's stick to 34 bytes per entry.
                                                               # Entry 4 (Copyright) in Conpot: 2 + 26 + 6 = 34. Correct.
                                                               # Entry A (OEM): 2 + 20 + 6 + 2 + 4 = 34. Correct.
                                                
                                                # SZL List Header
                                                # LENTHDR(2)=34, N_DR(2)=num_entries
                                                szl_list_header = struct.pack('>HH', 34, num_entries)
                                                
                                                total_data_len = len(szl_list_header) + len(szl_entries_data)
                                                szl_data_item_header = b'\xFF\x09' + struct.pack('>H', total_data_len)
                                                
                                                szl_data = szl_data_item_header + szl_list_header + szl_entries_data
                                                szl_param = param_data
                                                
                                                s7_resp_header = b'\x32\x07\x00\x00' + pdu_ref + \
                                                                 struct.pack('>H', len(szl_param)) + \
                                                                 struct.pack('>H', len(szl_data)) + \
                                                                 b'\x00\x00'
                                                
                                                s7_full_resp = s7_resp_header + szl_param + szl_data
                                                cotp_resp = b'\x02\xF0\x80'
                                                total_len = 4 + len(cotp_resp) + len(s7_full_resp)
                                                tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                                response_data = tpkt_resp + cotp_resp + s7_full_resp
                                            
                                            elif szl_id == 0x0131: # Communication Capability
                                                # Return comm parameters
                                                pdu_ref = s7_data[4:6]
                                                
                                                # Simplified SZL 0x0131 Entry (22 bytes)
                                                # MaxPDU(2), MaxConnections(2), MaxMPI(2), MaxBlocks(2), etc.
                                                szl_entry = struct.pack('>H', szl_index) + \
                                                           struct.pack('>H', self.profile['max_pdu']) + \
                                                           struct.pack('>H', 32) + \
                                                           b'\x00' * 16
                                                
                                                szl_list_header = struct.pack('>HH', 22, 1)
                                                total_data_len = len(szl_list_header) + len(szl_entry)
                                                szl_data_item_header = b'\xFF\x09' + struct.pack('>H', total_data_len)
                                                szl_data = szl_data_item_header + szl_list_header + szl_entry
                                                szl_param = param_data
                                                
                                                s7_resp_header = b'\x32\x07\x00\x00' + pdu_ref + \
                                                                 struct.pack('>H', len(szl_param)) + \
                                                                 struct.pack('>H', len(szl_data)) + \
                                                                 b'\x00\x00'
                                                
                                                s7_full_resp = s7_resp_header + szl_param + szl_data
                                                cotp_resp = b'\x02\xF0\x80'
                                                total_len = 4 + len(cotp_resp) + len(s7_full_resp)
                                                tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                                response_data = tpkt_resp + cotp_resp + s7_full_resp
                                            
                                            else:
                                                # Unsupported SZL ID - Return Strict S7 Error PDU
                                                # Use ROSCTR 0x03 (Error PDU)
                                                print(f"[S7] Unsupported SZL ID: 0x{szl_id:04X}, Index: {szl_index}")
                                                
                                                pdu_ref = s7_data[4:6]
                                                
                                                # S7 Error PDU Header (10 bytes or 12 bytes? Usually 10+2 error)
                                                # [32][03][00 00][Ref][00 00][00 00][ErrCls][ErrCode]
                                                # Header Length is 10 bytes + 2 bytes error = 12 bytes total payload?
                                                # Standard Error PDU:
                                                # 0: Protocol ID (0x32)
                                                # 1: ROSCTR (0x03 - Error)
                                                # 2-3: Reserved (0x0000)
                                                # 4-5: PDU Reference (Mirror)
                                                # 6-7: Param Len (0x0000)
                                                # 8-9: Data Len (0x0000)
                                                # 10: Error Class (0x81 - App Rel Error, or 0x85 - Function not supported)
                                                # 11: Error Code (0x04 - Context not supported, or 0x00)
                                                
                                                s7_resp_header = b'\x32\x03\x00\x00' + pdu_ref + \
                                                                 b'\x00\x00' + \
                                                                 b'\x00\x00' + \
                                                                 b'\x81\x04' # Error Class/Code
                                                
                                                cotp_resp = b'\x02\xF0\x80'
                                                total_len = 4 + len(cotp_resp) + len(s7_resp_header)
                                                tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                                
                                                response_data = tpkt_resp + cotp_resp + s7_resp_header

                                    # Existing SZL Check (Legacy/Job)
                                    elif len(param_data) >= 8:
                                            szl_id = 0
                                            szl_index = 0
                                            is_userdata = (rosctr == 0x07)
                                            
                                            if is_userdata:
                                                # UserData: Param[0]=0x00, Param[1]=0x01 (Read SZL)
                                                # Data: [RetCode][TransSize][Len][ID][Index]
                                                if len(param_data) >= 2 and param_data[0] == 0x00 and param_data[1] == 0x01:
                                                    if len(s7_data_payload) >= 8:
                                                        szl_id = struct.unpack('>H', s7_data_payload[4:6])[0]
                                                        szl_index = struct.unpack('>H', s7_data_payload[6:8])[0]
                                            else:
                                                # Job: Param contains ID and Index directly
                                                szl_id = struct.unpack('>H', param_data[4:6])[0]
                                                szl_index = struct.unpack('>H', param_data[6:8])[0]
                                            
                                            print(f"DEBUG: Read SZL ID: 0x{szl_id:04X}, Index: 0x{szl_index:04X}")
                                            elk_meta['s7.szl_id'] = f"0x{szl_id:04X}"

                                            if szl_id == 0x0011: # Module Identification
                                                # Construct SZL Response
                                                # S7 Header (Ack Data) + Param (Read SZL Resp) + Data (SZL List)
                                                
                                                pdu_ref = s7_data[4:6]
                                                
                                                # Data: Return Code(1), Transport Size(1), Len(2), Count(2), Entry(n)
                                                # Entry for 0x0011: Index(2), Article No(20), Module Name(16), ...
                                                # Simplified: Just Article No and Module Name
                                                
                                                article_no = self.profile['order_code'].ljust(20, '\x00').encode('utf-8')[:20]
                                                module_name = self.profile['module_name'].encode('utf-8').ljust(16, b'\x00')[:16]
                                                
                                                # SZL Entry Structure (28 bytes for 0x0011)
                                                # Index(2), ArticleNo(20), ModuleType(2), Firmware(2), ... 
                                                # Actually 0x0011 structure is complex. Let's use a standard 28-byte record.
                                                # Index(2), MFLB(20), BG_TYP(2), Ausbg(2)
                                                
                                                szl_entry = struct.pack('>H', szl_index) + article_no + b'\x00\x00' + b'\x00\x01'
                                                
                                                szl_data_header = b'\xFF\x04' + struct.pack('>H', len(szl_entry)*8) + b'\x00\x01' # *8 is wrong, len is bytes
                                                szl_data_header = b'\xFF\x04' + struct.pack('>H', len(szl_entry)) + b'\x00\x01'
                                                
                                                szl_data = szl_data_header + szl_entry
                                                
                                                # Param: Func(1), Method(1), Subfunc(1), Seq(1), DataRef(1), Last(1), Err(2)
                                                # Method 0x12 (Response)
                                                szl_param = b'\x04\x12\x00\x00\x00\x00\x00\x00'
                                                
                                                if is_userdata:
                                                    # UserData Response Param: [00][01][Seq][Len][Ref][Last][ErrH][ErrL]
                                                    # Request Param: [00][01][Seq][Len][Ref][Last]...
                                                    # We need to preserve Seq, Len, Ref. Set Last=0.
                                                    
                                                    # param_data[2] = Seq
                                                    # param_data[3] = Len
                                                    # param_data[4] = Ref
                                                    
                                                    if len(param_data) >= 5:
                                                        szl_param = b'\x00\x01' + param_data[2:5] + b'\x00\x00\x00'
                                                    else:
                                                        # Fallback if short
                                                        szl_param = b'\x00\x01\x00\x00\x00\x00\x00\x00'
                                                
                                                # S7 Header
                                                resp_rosctr = 0x07 if is_userdata else 0x03
                                                s7_resp_header = b'\x32' + struct.pack('B', resp_rosctr) + b'\x00\x00' + pdu_ref + \
                                                                 struct.pack('>H', len(szl_param)) + \
                                                                 struct.pack('>H', len(szl_data)) + \
                                                                 b'\x00\x00'
                                                
                                                s7_full_resp = s7_resp_header + szl_param + szl_data
                                                
                                                cotp_resp = b'\x02\xF0\x80'
                                                total_len = 4 + len(cotp_resp) + len(s7_full_resp)
                                                tpkt_resp = struct.pack('>BBH', 3, 0, total_len)
                                                
                                                response_data = tpkt_resp + cotp_resp + s7_full_resp
                
                if response_data:
                    if self.db:
                        self.db.log_interaction(attacker_ip, "s7comm", full_request, response_data, elk_meta)
                    client_sock.send(response_data)
                else:
                    # Unknown packet, maybe close or ignore
                    pass
                    
        except Exception as e:
            print(f"Error handling S7 client {addr}: {e}")
        finally:
            client_sock.close()
