"""
工業 PLC 模擬引擎
生成真實的工業控制系統數據模式
"""
import time
import math
import random


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
        return int(value)
    
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
        return int(value)
    
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
        return int(value)
    
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
        return int(value)
    
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
# 場景載入器 (從 JSON 檔案載入場景配置)
# ============================================

import sys
import os
# 將 scenarios 目錄加入 Python 路徑
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scenarios'))

try:
    from scenario_loader import get_modbus_scenario, get_s7_scenario, get_scenario_loader
    SCENARIOS_AVAILABLE = True
except ImportError:
    print("[Simulation] Warning: scenario_loader not found. Scenario support disabled.")
    SCENARIOS_AVAILABLE = False
    get_modbus_scenario = None
    get_s7_scenario = None





class ConfigDrivenSimulator:
    """
    根據配置動態生成模擬數據
    
    支援三種配置模式：
    1. 最簡配置（使用預設場景）：
       {"scenario": "water_treatment"}
       
    2. 部分覆蓋（基於場景 + 自定義）：
       {"scenario": "water_treatment", "holding_registers": [...]}
       
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
    
    # 場景載入器（從 JSON 檔案載入）
    _scenario_loader = None
    
    def __init__(self, config: dict = None):
        """
        初始化配置驅動模擬器
        
        Args:
            config: 模擬配置字典，可以是：
                - None 或 {}: 使用預設水處理廠場景
                - {"scenario": "xxx"}: 使用指定預設場景
                - {"scenario": "xxx", "holding_registers": [...]}: 場景 + 自定義覆蓋
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
        scenario_name = self.config.get("scenario")
        
        # 1. 載入基礎場景（如果指定）
        base_registers = {}
        base_coils = {}
        base_input_regs = {}
        base_discrete = {}
        
        # 使用場景載入器（從 JSON 檔案）
        if scenario_name and SCENARIOS_AVAILABLE:
            modbus_scenario = get_modbus_scenario(scenario_name)
            if modbus_scenario:
                # JSON 格式已經是 list of dicts，直接轉為 dict by addr
                base_registers = {item["addr"]: item for item in modbus_scenario.get("registers", [])}
                base_coils = {item["addr"]: item for item in modbus_scenario.get("coils", [])}
                base_input_regs = {item["addr"]: item for item in modbus_scenario.get("input_registers", [])}
                base_discrete = {item["addr"]: item for item in modbus_scenario.get("discrete_inputs", [])}
                print(f"[Simulator] Loaded scenario from JSON: {scenario_name}")
            else:
                print(f"[Simulator] Warning: Scenario '{scenario_name}' not found, using custom config only")
        elif not self.config.get("holding_registers") and not self.config.get("coils") and SCENARIOS_AVAILABLE:
            # 沒有指定場景也沒有自定義配置，使用預設水處理廠
            modbus_scenario = get_modbus_scenario("water_treatment")
            if modbus_scenario:
                base_registers = {item["addr"]: item for item in modbus_scenario.get("registers", [])}
                base_coils = {item["addr"]: item for item in modbus_scenario.get("coils", [])}
                base_input_regs = {item["addr"]: item for item in modbus_scenario.get("input_registers", [])}
                base_discrete = {item["addr"]: item for item in modbus_scenario.get("discrete_inputs", [])}
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
    
    def _convert_scenario_registers(self, registers: dict) -> dict:
        """將場景格式轉換為配置格式"""
        result = {}
        for addr, cfg in registers.items():
            item = {"addr": addr, "name": cfg.get("name", f"reg_{addr}")}
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
    
    def _convert_scenario_coils(self, coils: dict) -> dict:
        """將場景格式轉換為配置格式"""
        result = {}
        for addr, cfg in coils.items():
            on_time = cfg.get("on", 0)
            off_time = cfg.get("off", 0)
            
            item = {"addr": addr, "name": cfg.get("name", f"coil_{addr}")}
            
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
        
        elif wave == "square":
            return self.engine.square_wave(
                cfg.get("on", 5),
                cfg.get("off", 5)
            )
        
        elif wave == "random":
            probability = cfg.get("probability", 0.5)
            return self.engine.random_int(0, 100) < (probability * 100)
        
        return False
    
    def update_storage(self, storage: dict, unit_id: int):
        """
        批量更新 storage 中的所有模擬值
        
        Args:
            storage: Modbus storage 字典
            unit_id: 設備 Unit ID
        """
        # 確保 storage 結構存在
        if unit_id not in storage:
            storage[unit_id] = {}
        for key in ['holding_registers', 'coils', 'input_registers', 'discrete_inputs']:
            if key not in storage[unit_id]:
                storage[unit_id][key] = {}
        
        # 更新 Holding Registers
        for cfg in self.holding_registers:
            addr = cfg["addr"]
            storage[unit_id]['holding_registers'][addr] = self._generate_value(cfg, f"hr_{unit_id}_{addr}")
        
        # 更新 Coils
        for cfg in self.coils:
            addr = cfg["addr"]
            storage[unit_id]['coils'][addr] = self._generate_bool_value(cfg)
        
        # 更新 Input Registers
        for cfg in self.input_registers:
            addr = cfg["addr"]
            storage[unit_id]['input_registers'][addr] = self._generate_value(cfg, f"ir_{unit_id}_{addr}")
        
        # 更新 Discrete Inputs
        for cfg in self.discrete_inputs:
            addr = cfg["addr"]
            storage[unit_id]['discrete_inputs'][addr] = self._generate_bool_value(cfg)
    
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

