"""
工業 PLC 模擬引擎
生成真實的工業控制系統數據模式
"""
import time
import math
import random
import struct


class SimulationEngine:
    """
    模擬引擎 - 產生各種真實工業數據波形
    
    支援的波形類型:
    - 正弦波 (sine_wave): 溫度、壓力等週期性變化
    - 鋸齒波 (sawtooth_wave): 液位填充/排放
    - 方波 (square_wave): 開關狀態
    - 隨機漫步 (random_walk): 帶雜訊的穩定值
    - 過程雜訊 (process_noise): 帶雜訊的浮點數
    """
    
    def __init__(self):
        self.start_time = time.time()
        # 用於隨機漫步的狀態存儲
        self._random_walk_state = {}
    
    def get_time(self) -> float:
        """取得運行時間（秒）"""
        return time.time() - self.start_time
    
    def sine_wave(self, min_val: int, max_val: int, period_seconds: int) -> int:
        """
        正弦波模擬 - 適合溫度、壓力等週期性變化
        
        Args:
            min_val: 最小值
            max_val: 最大值
            period_seconds: 週期（秒）
            
        Returns:
            當前時間點的整數值
            
        Example:
            # 溫度 20-80°C，5分鐘週期
            temp = engine.sine_wave(20, 80, 300)
        """
        elapsed = self.get_time()
        # 正弦波範圍 [-1, 1] 轉換到 [0, 1]
        normalized = (math.sin(2 * math.pi * elapsed / period_seconds) + 1) / 2
        # 映射到目標範圍
        value = min_val + normalized * (max_val - min_val)
        return value
    
    def sawtooth_wave(self, min_val: int, max_val: int, period_seconds: int) -> int:
        """
        鋸齒波模擬 - 適合液位、計數器等線性增長後重置
        
        Args:
            min_val: 最小值（重置點）
            max_val: 最大值（峰值）
            period_seconds: 週期（秒）
            
        Returns:
            當前時間點的整數值
            
        Example:
            # 水槽液位 0-1000L，10分鐘填滿後排空
            level = engine.sawtooth_wave(0, 1000, 600)
        """
        elapsed = self.get_time()
        # 計算在週期內的位置 [0, 1)
        position = (elapsed % period_seconds) / period_seconds
        # 線性映射到目標範圍
        value = min_val + position * (max_val - min_val)
        return value
    
    def triangle_wave(self, min_val: int, max_val: int, period_seconds: int) -> int:
        """
        三角波模擬 - 適合往返運動、雙向流動
        
        Args:
            min_val: 最小值
            max_val: 最大值
            period_seconds: 完整週期（秒）
            
        Returns:
            當前時間點的整數值
        """
        elapsed = self.get_time()
        position = (elapsed % period_seconds) / period_seconds
        # 三角波：前半週期上升，後半週期下降
        if position < 0.5:
            normalized = position * 2
        else:
            normalized = 2 - position * 2
        value = min_val + normalized * (max_val - min_val)
        return value
    
    def square_wave(self, on_seconds: int, off_seconds: int) -> bool:
        """
        方波模擬 - 適合開關狀態、警示燈閃爍
        
        Args:
            on_seconds: ON 持續時間（秒）
            off_seconds: OFF 持續時間（秒）
            
        Returns:
            當前時間點的布林值
            
        Example:
            # 警示燈 5秒亮 / 5秒滅
            warning = engine.square_wave(5, 5)
        """
        elapsed = self.get_time()
        period = on_seconds + off_seconds
        position = elapsed % period
        return position < on_seconds
    
    def random_walk(self, current_value: int, min_val: int, max_val: int, max_step: int) -> int:
        """
        隨機漫步模擬 - 適合流量、風速等帶雜訊的穩定值
        
        Args:
            current_value: 當前值
            min_val: 最小邊界
            max_val: 最大邊界
            max_step: 每次最大變化量
            
        Returns:
            新的整數值（在邊界內）
            
        Example:
            # 流量約 500，±5 波動，範圍 450-550
            flow = engine.random_walk(flow, 450, 550, 5)
        """

        if isinstance(max_step, float) or isinstance(current_value, float):
            step = random.uniform(-max_step, max_step)
        else:
            step = random.randint(-max_step, max_step)
            
        new_value = current_value + step
        # 確保在邊界內
        new_value = max(min_val, min(max_val, new_value))
        return new_value
    
    def process_noise_float(self, base_value: float, noise_amplitude: float) -> float:
        """
        帶雜訊的浮點數模擬 - 適合精確感測器讀數
        
        Args:
            base_value: 基準值
            noise_amplitude: 雜訊振幅
            
        Returns:
            帶雜訊的浮點數值
            
        Example:
            # 流量約 120.5，±2.0 雜訊
            flow = engine.process_noise_float(120.5, 2.0)
        """
        noise = random.uniform(-noise_amplitude, noise_amplitude)
        return base_value + noise
    
    def random_int(self, min_val: int, max_val: int) -> int:
        """
        隨機整數 - 適合隨機事件觸發
        
        Args:
            min_val: 最小值
            max_val: 最大值
            
        Returns:
            隨機整數
        """
        return random.randint(min_val, max_val)
    
    def exponential_decay(self, initial_val: int, target_val: int, 
                          time_constant: float, start_offset: float = 0) -> int:
        """
        指數衰減模擬 - 適合溫度冷卻、壓力洩漏
        
        Args:
            initial_val: 初始值
            target_val: 目標值（穩態）
            time_constant: 時間常數（秒）
            start_offset: 開始偏移時間
            
        Returns:
            當前時間點的整數值
        """
        elapsed = self.get_time() - start_offset
        if elapsed < 0:
            return initial_val
        
        decay = math.exp(-elapsed / time_constant)
        value = target_val + (initial_val - target_val) * decay
        return value
    
    def step_sequence(self, values: list, durations: list) -> int:
        """
        步進序列模擬 - 適合批次製程、多段控制
        
        Args:
            values: 各階段的值列表
            durations: 各階段的持續時間列表（秒）
            
        Returns:
            當前階段的值
            
        Example:
            # 三段溫度控制：預熱 200°C(60s) -> 加熱 350°C(120s) -> 保溫 300°C(180s)
            temp = engine.step_sequence([200, 350, 300], [60, 120, 180])
        """
        if len(values) != len(durations):
            return values[0] if values else 0
        
        total_cycle = sum(durations)
        elapsed = self.get_time() % total_cycle
        
        cumulative = 0
        for i, duration in enumerate(durations):
            cumulative += duration
            if elapsed < cumulative:
                return values[i]
        
        return values[-1]


# ============================================
# 配置載入器 (從 JSON 檔案載入配置)
# ============================================

import sys
import os
# 將 profiles 目錄加入 Python 路徑
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'profiles'))

try:
    from profile_loader import get_modbus_profile, get_s7_profile, get_profile_loader
    PROFILES_AVAILABLE = True
except ImportError:
    print("[Simulation] Warning: profile_loader not found. Profile support disabled.")
    PROFILES_AVAILABLE = False
    get_modbus_profile = None
    get_s7_profile = None





class ConfigDrivenSimulator:
    """
    根據配置動態生成模擬數據
    
    支援三種配置模式：
    1. 最簡配置（使用預設配置）：
       {"profile": "water_treatment"}
       
    2. 部分覆蓋（基於配置 + 自定義）：
       {"profile": "water_treatment", "holding_registers": [...]}
       
    3. 完整自定義：
       {"holding_registers": [...], "coils": [...], ...}
    
    波形類型 (wave):
    - "fixed": 固定值 (需要 value)
    - "sine": 正弦波 (需要 min, max, period)
    - "sawtooth": 鋸齒波 (需要 min, max, period)
    - "triangle": 三角波 (需要 min, max, period)
    - "random_walk": 隨機漫步 (需要 min, max, step, 可選 initial)
    - "square": 方波 (需要 on, off)
    - "random": 隨機觸發 (需要 probability)
    - "counter": 計數器 (可選 max)
    """
    
    # 配置載入器（從 JSON 檔案載入）
    _profile_loader = None
    
    def __init__(self, config: dict = None):
        """
        初始化配置驅動模擬器
        
        Args:
            config: 模擬配置字典，可以是：
                - None 或 {}: 使用預設水處理廠配置
                - {"profile": "xxx"}: 使用指定預設配置
                - {"profile": "xxx", "holding_registers": [...]}: 配置 + 自定義覆蓋
                - {"holding_registers": [...], ...}: 完整自定義
        """
        self.engine = SimulationEngine()
        self.config = config or {}
        self._random_walk_state = {}  # 用於記錄 random_walk 的當前值
        
        # 解析後的配置
        self.holding_registers = []
        self.coils = []
        self.input_registers = []
        self.discrete_inputs = []
        
        # 載入配置
        self._load_config()
    
    def _load_config(self):
        """載入並解析模擬配置"""
        profile_name = self.config.get("profile")
        
        # 1. 載入基礎配置（如果指定）
        base_registers = {}
        base_coils = {}
        base_input_regs = {}
        base_discrete = {}
        
        # 使用配置載入器（從 JSON 檔案）
        if profile_name and PROFILES_AVAILABLE:
            modbus_profile = get_modbus_profile(profile_name)
            if modbus_profile:
                # JSON 格式已經是 list of dicts，直接轉為 dict by addr
                base_registers = {item["addr"]: item for item in modbus_profile.get("registers", [])}
                base_coils = {item["addr"]: item for item in modbus_profile.get("coils", [])}
                base_input_regs = {item["addr"]: item for item in modbus_profile.get("input_registers", [])}
                base_discrete = {item["addr"]: item for item in modbus_profile.get("discrete_inputs", [])}
                print(f"[Simulator] Loaded profile from JSON: {profile_name}")
            else:
                print(f"[Simulator] Warning: Profile '{profile_name}' not found, using custom config only")
        elif not self.config.get("holding_registers") and not self.config.get("coils") and PROFILES_AVAILABLE:
            # 沒有指定配置也沒有自定義配置，使用預設水處理廠
            modbus_profile = get_modbus_profile("water_treatment")
            if modbus_profile:
                base_registers = {item["addr"]: item for item in modbus_profile.get("registers", [])}
                base_coils = {item["addr"]: item for item in modbus_profile.get("coils", [])}
                base_input_regs = {item["addr"]: item for item in modbus_profile.get("input_registers", [])}
                base_discrete = {item["addr"]: item for item in modbus_profile.get("discrete_inputs", [])}
                print("[Simulator] No config provided, using default: water_treatment (from JSON)")
        
        # 2. 應用自定義覆蓋
        custom_hr = {item["addr"]: item for item in self.config.get("holding_registers", [])}
        custom_coils = {item["addr"]: item for item in self.config.get("coils", [])}
        custom_ir = {item["addr"]: item for item in self.config.get("input_registers", [])}
        custom_di = {item["addr"]: item for item in self.config.get("discrete_inputs", [])}
        
        # 3. 合併：自定義優先
        base_registers.update(custom_hr)
        base_coils.update(custom_coils)
        base_input_regs.update(custom_ir)
        base_discrete.update(custom_di)
        
        # 4. 轉換為列表格式
        self.holding_registers = list(base_registers.values())
        self.coils = list(base_coils.values())
        self.input_registers = list(base_input_regs.values())
        self.discrete_inputs = list(base_discrete.values())
        
        print(f"[Simulator] Loaded {len(self.holding_registers)} holding registers, "
              f"{len(self.coils)} coils, {len(self.input_registers)} input registers, "
              f"{len(self.discrete_inputs)} discrete inputs")
    
    def _convert_profile_registers(self, registers: dict) -> dict:
        """將配置格式轉換為模擬器格式"""
        result = {}
        for addr, cfg in registers.items():
            item = {"addr": addr}
            if "value" in cfg:
                item["wave"] = "fixed"
                item["value"] = cfg["value"]
            else:
                item["wave"] = cfg.get("wave", "random_walk")
                item["min"] = cfg.get("min", 0)
                item["max"] = cfg.get("max", 65535)
                if item["wave"] == "random_walk":
                    item["step"] = cfg.get("step", 5)
                    item["initial"] = cfg.get("initial", (item["min"] + item["max"]) // 2)
                else:
                    item["period"] = cfg.get("period", 300)
            result[addr] = item
        return result
    
    def _convert_profile_coils(self, coils: dict) -> dict:
        """將配置格式轉換為模擬器格式"""
        result = {}
        for addr, cfg in coils.items():
            on_time = cfg.get("on", 0)
            off_time = cfg.get("off", 0)
            
            item = {"addr": addr}
            
            if on_time > 0 and off_time == 0:
                # 永遠 ON
                item["wave"] = "fixed"
                item["value"] = True
            elif on_time == 0 and off_time > 0:
                # 永遠 OFF
                item["wave"] = "fixed"
                item["value"] = False
            elif on_time == 0 and off_time == 0:
                # 預設為 OFF
                item["wave"] = "fixed"
                item["value"] = False
            else:
                # 方波
                item["wave"] = "square"
                item["on"] = on_time
                item["off"] = off_time
            
            result[addr] = item
        return result
    
    def _generate_value(self, cfg: dict, key: str) -> int:
        """根據配置生成數值"""
        wave = cfg.get("wave", "fixed")
        
        if wave == "fixed":
            return cfg.get("value", 0)
        
        elif wave == "static":
            # 靜態值，不自動更新 (用於讓攻擊者寫入或保持狀態)
            # 如果是第一次初始化，返回 min_val (預設值)
            # 如果已經有值，則應該由 update_storage 保留原值 (這裡只負責生成新值)
            # 但 _generate_value 是無狀態的，所以我們回傳 None 表示 "不更新"
            return None
        
        elif wave == "sine":
            return self.engine.sine_wave(
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("period", 300)
            )
        
        elif wave == "sawtooth":
            return self.engine.sawtooth_wave(
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("period", 600)
            )
        
        elif wave == "triangle":
            return self.engine.triangle_wave(
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("period", 600)
            )
        
        elif wave == "random_walk":
            # 取得或初始化當前值
            if key not in self._random_walk_state:
                self._random_walk_state[key] = cfg.get("initial", (cfg.get("min", 0) + cfg.get("max", 65535)) // 2)
            
            new_val = self.engine.random_walk(
                self._random_walk_state[key],
                cfg.get("min", 0),
                cfg.get("max", 65535),
                cfg.get("step", 5)
            )
            self._random_walk_state[key] = new_val
            return new_val
        
        elif wave == "counter":
            return int(self.engine.get_time()) % cfg.get("max", 65536)
        
        elif wave == "noise":
            base = cfg.get("base", 0)
            amplitude = cfg.get("amplitude", 10)
            return int(self.engine.process_noise_float(base, amplitude))
        
        return 0
    
    def _generate_bool_value(self, cfg: dict) -> bool:
        """根據配置生成布林值"""
        wave = cfg.get("wave", "fixed")
        
        if wave == "fixed":
            return cfg.get("value", False)
        
        elif wave == "static":
            return None
        
        elif wave == "square":
            return self.engine.square_wave(
                cfg.get("on", 5),
                cfg.get("off", 5)
            )
        
        elif wave == "random":
            probability = cfg.get("probability", 0.5)
            return self.engine.random_int(0, 100) < (probability * 100)
        
        return False
    
    def _encode_float32(self, value: float) -> list:
        """
        將 float32 編碼為兩個 16-bit 整數 (Big Endian)
        Modbus 通常使用兩個暫存器來存儲一個 32 位元浮點數
        """
        # Pack float to 4 bytes (Big Endian)
        packed = struct.pack('>f', value)
        # Unpack to two 16-bit integers
        ints = struct.unpack('>HH', packed)
        return list(ints)

    def _encode_string(self, text: str, length: int) -> list:
        """
        將字串編碼為 Modbus 暫存器列表 (每個暫存器存 2 bytes)
        """
        # Truncate or pad with null bytes
        data = text.encode('ascii', errors='ignore')
        if len(data) > length * 2:
            data = data[:length*2]
        else:
            data = data.ljust(length*2, b'\0')
            
        regs = []
        for i in range(0, len(data), 2):
            chunk = data[i:i+2]
            val = struct.unpack('>H', chunk)[0]
            regs.append(val)
        return regs

    def _handle_pm5300_command(self, storage: dict, unit_id: int):
        """
        處理 Schneider PM5300 的特殊命令邏輯 (High Interaction)
        1. Command Interface (Energy Reset)
        2. DO Control (Voltage Cutoff)
        3. CT Ratio Scaling
        """
        regs = storage[unit_id]['holding_registers']
        coils = storage[unit_id]['coils']
        
        # --- 1. Command Interface ---
        cmd_code = regs.get(5000, 0)
        semaphore = regs.get(5001, 0)
        
        # Command 2020: Reset All Energies
        if cmd_code == 2020:
            if 3200 in regs:
                print(f"[PM5300] Executing Command 2020: Reset All Energies")
                regs[3200] = 0
                regs[3201] = 0
            regs[5002] = 0 # Success
            regs[5000] = 0 # Clear Command
            
        # --- 2. DO Control (DoS Simulation) ---
        # 假設 Coil 0 是 "Main Breaker Trip Coil"
        # 如果 Set 為 True，則強制切斷電壓 (Voltage = 0)
        breaker_trip = coils.get(0, False)
        # print(f"DEBUG: Breaker Trip Status: {breaker_trip}")
        if breaker_trip:
            print("DEBUG: Breaker TRIPPED! Zeroing voltages.")
            # Force Voltage A/B/C to 0
            # Voltage A-N (3020), B-N (3022), C-N (3024)
            for addr in [3020, 3021, 3022, 3023, 3024, 3025]:
                if addr in regs:
                    regs[addr] = 0
                    print(f"DEBUG: Zeroed Reg {addr}")
                    
        # --- 3. CT Ratio Scaling ---
        # 假設 Reg 2012 是 CT Primary (Float32)，預設 100
        # 如果被修改，Current A/B/C (3000-3005) 應該要依比例變化
        # 這裡簡化邏輯：我們已經生成的 Current 是基於 Default Ratio (100:5)
        # 如果現在的 CT Ratio 不是 100，我們就縮放 Current
        # 注意：這應該在 update_storage 生成完數值後「修正」
        
        # 讀取目前 CT Ratio
        ct_primary = 100.0 # Default
        if 2012 in regs and 2013 in regs:
            # Decode float
            ints = [regs[2012], regs[2013]]
            packed = struct.pack('>HH', ints[0], ints[1])
            ct_primary = struct.unpack('>f', packed)[0]
            
            # 防呆：避免除以零或負數
            if ct_primary <= 0: ct_primary = 100.0

        # 如果 CT Ratio 被改成非預設值 (例如 200)，則電流讀數應該放大 2 倍 (因為負載不變，變的是量程定義... 等等)
        # 不對，如果是 CT Ratio 改變 (例如變壓器換了)，同樣的實際電流 (Primary) 經過不同的 CT，Secondary 會變。
        # 但 Modbus 讀到的是 "Primary Current" (實際一次側電流)。
        # 所以如果攻擊者把 CT Ratio 改大 (例如從 100 改成 1000)，
        # 表示他告訴儀表：「原本 5A 的訊號現在代表 1000A 了！」
        # 所以同樣的負載訊號，儀表顯示的數值應該會 **變大**。
        
        if abs(ct_primary - 100.0) > 0.1:
            scale_factor = ct_primary / 100.0
            # 修正 Current A (3000)
            for start_addr in [3000, 3002, 3004]: # A, B, C
                if start_addr in regs and (start_addr+1) in regs:
                    # 先解碼
                    c_ints = [regs[start_addr], regs[start_addr+1]]
                    c_packed = struct.pack('>HH', c_ints[0], c_ints[1])
                    c_val = struct.unpack('>f', c_packed)[0]
                    
                    # 應用縮放
                    new_val = c_val * scale_factor
                    
                    # 寫回
                    new_regs = self._encode_float32(new_val)
                    regs[start_addr] = new_regs[0]
                    regs[start_addr+1] = new_regs[1]

    def update_storage(self, storage: dict, unit_id: int):
        """
        批量更新 storage 中的所有模擬值
        
        Args:
            storage: Modbus storage 字典
            unit_id: 設備 Unit ID
        """
        # 確保 storage 結構存在
        if unit_id not in storage:
            storage[unit_id] = {'coils': {}, 'holding_registers': {}, 'input_registers': {}, 'discrete_inputs': {}}
        
        # 更新 Holding Registers
        for cfg in self.holding_registers:
            addr = cfg["addr"]
            val = self._generate_value(cfg, f"hr_{unit_id}_{addr}")
            
            # 如果是 static 類型且 val 為 None，則跳過更新 (保留原值)
            if val is None:
                # 確保至少有初始值
                if addr not in storage[unit_id]['holding_registers']:
                    # 使用 min 作為預設初始值
                    storage[unit_id]['holding_registers'][addr] = int(cfg.get("min", 0))
                continue

            # 檢查是否為 float32
            if cfg.get("type") == "float32":
                # 浮點數需要佔用兩個暫存器
                regs = self._encode_float32(float(val))
                storage[unit_id]['holding_registers'][addr] = regs[0]
                storage[unit_id]['holding_registers'][addr + 1] = regs[1]
            
            elif cfg.get("type") == "string":
                # String 類型需要多個 Registers
                length = cfg.get("length", 10) # 預設 10 registers (20 chars)
                val_str = str(val)
                regs = self._encode_string(val_str, length)
                for i, r_val in enumerate(regs):
                    storage[unit_id]['holding_registers'][addr + i] = r_val
            
            else:
                # 預設為 int16
                storage[unit_id]['holding_registers'][addr] = int(val)
        

        
        # 更新 Input Registers
        for cfg in self.input_registers:
            addr = cfg["addr"]
            storage[unit_id]['input_registers'][addr] = self._generate_value(cfg, f"ir_{unit_id}_{addr}")
        
        # 更新 Discrete Inputs
        for cfg in self.discrete_inputs:
            addr = cfg["addr"]
            val = self._generate_bool_value(cfg)
            if val is not None:
                storage[unit_id]['discrete_inputs'][addr] = bool(val)

        # 更新 Coils
        for cfg in self.coils:
            addr = cfg["addr"]
            val = self._generate_bool_value(cfg)
            if val is not None:
                storage[unit_id]['coils'][addr] = bool(val)
            elif addr not in storage[unit_id]['coils']:
                 # Default for static if not set
                 storage[unit_id]['coils'][addr] = bool(cfg.get("value", False))

        # 執行特定設備的邏輯
        # 這裡簡單判斷：如果存在 PM5300 特有的 Register (例如 5000+3200)，就執行邏輯
        # 或者未來可以在 json 中加標記
        if any(r['addr'] == 5000 for r in self.holding_registers):
            self._handle_pm5300_command(storage, unit_id)
    
    def reload_config(self, new_config: dict):
        """
        熱更新配置
        
        Args:
            new_config: 新的模擬配置
        """
        self.config = new_config or {}
        self._random_walk_state = {}  # 重置狀態
        self._load_config()
        print("[Simulator] Configuration reloaded")

