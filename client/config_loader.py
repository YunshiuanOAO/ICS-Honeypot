import json
import os
from copy import deepcopy

class ConfigLoader:
    """
    配置載入器 - 負責載入、清理和驗證配置
    
    功能：
    1. 清理配置：移除無效欄位並標準化格式
    2. 驗證配置：確保必要欄位存在且格式正確
    3. 標準化配置：統一配置格式和數據類型
    """
    
    def __init__(self, config_path=None):
        if config_path is None:
            # Resolve relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.config_path = os.path.join(base_dir, "client_config.json")
        else:
            self.config_path = config_path
        
        self.config = self._load_default_config()

    def _load_default_config(self):
        import uuid
        # Generate a semi-persistent random ID for new agents
        random_suffix = uuid.uuid4().hex[:8]
        return {
            "server_url": "http://localhost:8000",
            "node_id": f"pending_{random_suffix}",
            "plcs": [] # No PLCs by default for pending agents
        }

    def clean_config(self, config):
        """
        清理配置：移除無效欄位並標準化格式
        
        會自動移除：
        - 以 '_' 開頭的內部欄位（用於臨時標記）
        - 無效的嵌套結構
        
        Args:
            config: 原始配置字典
            
        Returns:
            清理後的配置字典
        """
        if not isinstance(config, dict):
            return config
        
        cleaned = {}
        for key, value in config.items():
            # 移除內部標記欄位（以 '_' 開頭）
            if key.startswith('_'):
                continue
            
            # 遞迴清理嵌套的字典
            if isinstance(value, dict):
                cleaned[key] = self.clean_config(value)
            elif isinstance(value, list):
                # 清理列表中的字典元素
                cleaned[key] = [
                    self.clean_config(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                cleaned[key] = value
        
        return cleaned

    def validate_config(self, config):
        """
        驗證配置結構
        
        Args:
            config: 配置字典
            
        Returns:
            (is_valid, error_message)
        """
        if not isinstance(config, dict):
            return False, "Config must be a dictionary"
        
        # 驗證必要欄位
        if "plcs" not in config:
            return False, "Missing 'plcs' field"
        
        if not isinstance(config["plcs"], list):
            return False, "'plcs' must be a list"
        
        # 驗證每個 PLC 配置
        for i, plc_conf in enumerate(config["plcs"]):
            if not isinstance(plc_conf, dict):
                return False, f"PLC config at index {i} must be a dictionary"
            
            # 必要欄位
            required_fields = ["type", "enabled", "port", "model"]
            for field in required_fields:
                if field not in plc_conf:
                    return False, f"PLC config at index {i} missing required field: {field}"
            
            # 驗證類型
            if plc_conf["type"] not in ["modbus", "s7comm"]:
                return False, f"PLC config at index {i} has invalid type: {plc_conf['type']}"
            
            # 驗證 port
            if not isinstance(plc_conf["port"], int) or plc_conf["port"] < 1 or plc_conf["port"] > 65535:
                return False, f"PLC config at index {i} has invalid port: {plc_conf['port']}"
            
            # 驗證 simulation 配置（如果存在）
            if "simulation" in plc_conf:
                sim_config = plc_conf["simulation"]
                if not isinstance(sim_config, dict):
                    return False, f"PLC config at index {i} has invalid simulation config"
                
                # 驗證 simulation 中的陣列結構
                for sim_key in ["holding_registers", "coils", "input_registers", "discrete_inputs"]:
                    if sim_key in sim_config:
                        if not isinstance(sim_config[sim_key], list):
                            return False, f"PLC config at index {i} simulation.{sim_key} must be a list"
                        
                        # 驗證陣列中的每個元素
                        for j, item in enumerate(sim_config[sim_key]):
                            if not isinstance(item, dict):
                                return False, f"PLC config at index {i} simulation.{sim_key}[{j}] must be a dictionary"
                            if "addr" not in item:
                                return False, f"PLC config at index {i} simulation.{sim_key}[{j}] missing 'addr' field"
        
        return True, None

    def normalize_config(self, config):
        """
        標準化配置：確保所有欄位格式一致
        
        Args:
            config: 配置字典
            
        Returns:
            標準化後的配置字典
        """
        normalized = deepcopy(config)
        
        # 確保 plcs 是列表
        if "plcs" not in normalized:
            normalized["plcs"] = []
        
        # 標準化每個 PLC 配置
        for plc_conf in normalized["plcs"]:
            # 確保 enabled 是布林值
            if "enabled" in plc_conf:
                plc_conf["enabled"] = bool(plc_conf["enabled"])
            
            # 確保 port 是整數
            if "port" in plc_conf:
                plc_conf["port"] = int(plc_conf["port"])
            
            # 標準化 simulation 配置
            if "simulation" in plc_conf:
                sim = plc_conf["simulation"]
                
                # 確保陣列中的 addr 是整數
                for sim_key in ["holding_registers", "coils", "input_registers", "discrete_inputs"]:
                    if sim_key in sim and isinstance(sim[sim_key], list):
                        for item in sim[sim_key]:
                            if "addr" in item:
                                item["addr"] = int(item["addr"])
        
        return normalized

    def load_config(self):
        """
        載入配置檔案（本地）
        
        Returns:
            清理和驗證後的配置
        """
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    raw_config = json.load(f)
                
                # 清理、驗證、標準化
                cleaned = self.clean_config(raw_config)
                is_valid, error = self.validate_config(cleaned)
                
                if is_valid:
                    self.config = self.normalize_config(cleaned)
                else:
                    print(f"Config validation failed: {error}, using default.")
                    self.config = self._load_default_config()
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}, using default.")
                self.config = self._load_default_config()
            except Exception as e:
                print(f"Error loading config: {e}, using default.")
                self.config = self._load_default_config()
        return self.config

    def parse_server_config(self, raw_config):
        """
        解析從 server 接收的配置
        
        這個方法會：
        1. 清理無效欄位
        2. 驗證配置結構
        3. 標準化配置格式
        
        Args:
            raw_config: 從 server 接收的原始配置字典
            
        Returns:
            (success, cleaned_config, error_message)
        """
        try:
            # 1. 清理註釋欄位
            cleaned = self.clean_config(raw_config)
            
            # 2. 驗證配置
            is_valid, error = self.validate_config(cleaned)
            if not is_valid:
                return False, None, error
            
            # 3. 標準化配置
            normalized = self.normalize_config(cleaned)
            
            return True, normalized, None
            
        except Exception as e:
            return False, None, f"Config parsing error: {str(e)}"

    def save_config(self, config):
        """
        儲存配置到檔案
        
        Args:
            config: 配置字典（會自動清理無效欄位）
        """
        # 清理後再儲存
        cleaned = self.clean_config(config)
        self.config = cleaned
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(cleaned, f, indent=4, ensure_ascii=False)
