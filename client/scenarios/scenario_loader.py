"""
場景配置載入器
從 JSON 檔案中載入預定義的工業場景配置
"""

import json
import os
from typing import Dict, Optional, List


class ScenarioLoader:
    """載入和管理場景配置檔案"""
    
    def __init__(self, scenarios_dir: str = None):
        """
        初始化場景載入器
        
        Args:
            scenarios_dir: 場景檔案目錄，預設為本檔案所在目錄
        """
        if scenarios_dir is None:
            scenarios_dir = os.path.dirname(os.path.abspath(__file__))
        
        self.scenarios_dir = scenarios_dir
        self._scenarios_cache = {}
        self._scan_scenarios()
    
    def _scan_scenarios(self):
        """掃描場景目錄，建立場景列表"""
        if not os.path.exists(self.scenarios_dir):
            print(f"[ScenarioLoader] Warning: Scenarios directory not found: {self.scenarios_dir}")
            return
        
        for filename in os.listdir(self.scenarios_dir):
            if filename.endswith('.json'):
                scenario_name = filename[:-5]  # 移除 .json 副檔名
                self._scenarios_cache[scenario_name] = None  # 延遲載入
        
        print(f"[ScenarioLoader] Found {len(self._scenarios_cache)} scenario(s): {', '.join(self._scenarios_cache.keys())}")
    
    def load_scenario(self, scenario_name: str) -> Optional[Dict]:
        """
        載入指定的場景配置
        
        Args:
            scenario_name: 場景名稱（不含 .json）
        
        Returns:
            場景配置字典，如果載入失敗則返回 None
        """
        # 檢查快取
        if scenario_name in self._scenarios_cache and self._scenarios_cache[scenario_name] is not None:
            return self._scenarios_cache[scenario_name]
        
        # 載入檔案
        scenario_path = os.path.join(self.scenarios_dir, f"{scenario_name}.json")
        
        if not os.path.exists(scenario_path):
            print(f"[ScenarioLoader] Error: Scenario file not found: {scenario_path}")
            return None
        
        try:
            with open(scenario_path, 'r', encoding='utf-8') as f:
                scenario_data = json.load(f)
            
            # 快取配置
            self._scenarios_cache[scenario_name] = scenario_data
            
            print(f"[ScenarioLoader] Loaded scenario: {scenario_data.get('name', scenario_name)} (v{scenario_data.get('version', '?')})")
            return scenario_data
        
        except json.JSONDecodeError as e:
            print(f"[ScenarioLoader] JSON decode error in {scenario_name}.json: {e}")
            return None
        except Exception as e:
            print(f"[ScenarioLoader] Error loading scenario {scenario_name}: {e}")
            return None
    
    def get_modbus_config(self, scenario_name: str) -> Optional[Dict]:
        """
        獲取場景的 Modbus 配置
        
        Args:
            scenario_name: 場景名稱
        
        Returns:
            Modbus 配置字典 (registers, coils, input_registers, discrete_inputs)
        """
        scenario = self.load_scenario(scenario_name)
        if scenario is None:
            return None
        
        return scenario.get('modbus', {})
    
    def get_s7_config(self, scenario_name: str) -> Optional[Dict]:
        """
        獲取場景的 S7 配置
        
        Args:
            scenario_name: 場景名稱
        
        Returns:
            S7 配置字典 (db, m, i, q)
        """
        scenario = self.load_scenario(scenario_name)
        if scenario is None:
            return None
        
        return scenario.get('s7', {})
    
    def list_scenarios(self) -> List[str]:
        """
        列出所有可用的場景名稱
        
        Returns:
            場景名稱列表
        """
        return list(self._scenarios_cache.keys())
    
    def get_scenario_info(self, scenario_name: str) -> Optional[Dict]:
        """
        獲取場景的基本資訊（不載入完整配置）
        
        Args:
            scenario_name: 場景名稱
        
        Returns:
            包含 name, description, author, version 的字典
        """
        scenario = self.load_scenario(scenario_name)
        if scenario is None:
            return None
        
        return {
            'name': scenario.get('name', scenario_name),
            'description': scenario.get('description', ''),
            'author': scenario.get('author', 'Unknown'),
            'version': scenario.get('version', '1.0')
        }
    
    def reload(self):
        """重新掃描場景目錄並清除快取"""
        self._scenarios_cache = {}
        self._scan_scenarios()


# 全域場景載入器實例
_global_loader = None


def get_scenario_loader(scenarios_dir: str = None) -> ScenarioLoader:
    """
    獲取全域場景載入器實例（單例模式）
    
    Args:
        scenarios_dir: 場景檔案目錄，僅在首次呼叫時有效
    
    Returns:
        ScenarioLoader 實例
    """
    global _global_loader
    
    if _global_loader is None:
        _global_loader = ScenarioLoader(scenarios_dir)
    
    return _global_loader


def load_scenario(scenario_name: str) -> Optional[Dict]:
    """
    便捷函數：載入指定場景
    
    Args:
        scenario_name: 場景名稱
    
    Returns:
        場景配置字典
    """
    loader = get_scenario_loader()
    return loader.load_scenario(scenario_name)


def get_modbus_scenario(scenario_name: str) -> Optional[Dict]:
    """
    便捷函數：獲取 Modbus 場景配置
    
    Args:
        scenario_name: 場景名稱
    
    Returns:
        Modbus 配置字典
    """
    loader = get_scenario_loader()
    return loader.get_modbus_config(scenario_name)


def get_s7_scenario(scenario_name: str) -> Optional[Dict]:
    """
    便捷函數：獲取 S7 場景配置
    
    Args:
        scenario_name: 場景名稱
    
    Returns:
        S7 配置字典
    """
    loader = get_scenario_loader()
    return loader.get_s7_config(scenario_name)


if __name__ == "__main__":
    # 測試載入器
    loader = get_scenario_loader()
    
    print("\n=== Available Scenarios ===")
    for scenario in loader.list_scenarios():
        info = loader.get_scenario_info(scenario)
        if info:
            print(f"- {scenario}: {info['name']} - {info['description']}")
    
    print("\n=== Test Loading water_treatment ===")
    modbus_cfg = get_modbus_scenario("water_treatment")
    if modbus_cfg:
        print(f"Modbus Registers: {len(modbus_cfg.get('registers', []))}")
        print(f"Modbus Coils: {len(modbus_cfg.get('coils', []))}")
    
    s7_cfg = get_s7_scenario("water_treatment")
    if s7_cfg:
        print(f"S7 DBs: {len(s7_cfg.get('db', {}))}")
        print(f"S7 Merkers: {len(s7_cfg.get('m', {}))}")

