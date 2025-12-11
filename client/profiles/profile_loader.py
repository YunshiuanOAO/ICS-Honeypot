"""
配置文件載入器
從 JSON 檔案中載入預定義的工業配置 (Profiles)
"""

import json
import os
from typing import Dict, Optional, List


class ProfileLoader:
    """載入和管理配置文件"""
    
    def __init__(self, profiles_dir: str = None):
        """
        初始化配置載入器
        
        Args:
            profiles_dir: 配置檔案目錄，預設為本檔案所在目錄
        """
        if profiles_dir is None:
            profiles_dir = os.path.dirname(os.path.abspath(__file__))
        
        self.profiles_dir = profiles_dir
        self._profiles_cache = {}
        self._scan_profiles()
    
    def _scan_profiles(self):
        """掃描配置目錄，建立配置列表"""
        if not os.path.exists(self.profiles_dir):
            print(f"[ProfileLoader] Warning: Profiles directory not found: {self.profiles_dir}")
            return
        
        for filename in os.listdir(self.profiles_dir):
            if filename.endswith('.json'):
                profile_name = filename[:-5]  # 移除 .json 副檔名
                self._profiles_cache[profile_name] = None  # 延遲載入
        
        print(f"[ProfileLoader] Found {len(self._profiles_cache)} profile(s): {', '.join(self._profiles_cache.keys())}")
    
    def load_profile(self, profile_name: str) -> Optional[Dict]:
        """
        載入指定的配置
        
        Args:
            profile_name: 配置名稱（不含 .json）
        
        Returns:
            配置字典，如果載入失敗則返回 None
        """
        # 檢查快取
        if profile_name in self._profiles_cache and self._profiles_cache[profile_name] is not None:
            return self._profiles_cache[profile_name]
        
        # 載入檔案
        profile_path = os.path.join(self.profiles_dir, f"{profile_name}.json")
        
        if not os.path.exists(profile_path):
            print(f"[ProfileLoader] Error: Profile file not found: {profile_path}")
            return None
        
        try:
            with open(profile_path, 'r', encoding='utf-8') as f:
                profile_data = json.load(f)
            
            # 快取配置
            self._profiles_cache[profile_name] = profile_data
            
            print(f"[ProfileLoader] Loaded profile: {profile_data.get('name', profile_name)} (v{profile_data.get('version', '?')})")
            return profile_data
        
        except json.JSONDecodeError as e:
            print(f"[ProfileLoader] JSON decode error in {profile_name}.json: {e}")
            return None
        except Exception as e:
            print(f"[ProfileLoader] Error loading profile {profile_name}: {e}")
            return None
    
    def get_modbus_config(self, profile_name: str) -> Optional[Dict]:
        """
        獲取配置的 Modbus 設定
        
        Args:
            profile_name: 配置名稱
        
        Returns:
            Modbus 配置字典 (registers, coils, input_registers, discrete_inputs)
        """
        profile = self.load_profile(profile_name)
        if profile is None:
            return None
        
        return profile.get('modbus', {})
    
    def get_s7_config(self, profile_name: str) -> Optional[Dict]:
        """
        獲取配置的 S7 設定
        
        Args:
            profile_name: 配置名稱
        
        Returns:
            S7 配置字典 (db, m, i, q)
        """
        profile = self.load_profile(profile_name)
        if profile is None:
            return None
        
        return profile.get('s7', {})
    
    def list_profiles(self) -> List[str]:
        """
        列出所有可用的配置名稱
        
        Returns:
            配置名稱列表
        """
        return list(self._profiles_cache.keys())
    
    def get_profile_info(self, profile_name: str) -> Optional[Dict]:
        """
        獲取配置的基本資訊（不載入完整配置）
        
        Args:
            profile_name: 配置名稱
        
        Returns:
            包含 name, description, author, version 的字典
        """
        profile = self.load_profile(profile_name)
        if profile is None:
            return None
        
        return {
            'name': profile.get('name', profile_name),
            'description': profile.get('description', ''),
            'author': profile.get('author', 'Unknown'),
            'version': profile.get('version', '1.0')
        }
    
    def reload(self):
        """重新掃描配置目錄並清除快取"""
        self._profiles_cache = {}
        self._scan_profiles()


# 全域配置載入器實例
_global_loader = None


def get_profile_loader(profiles_dir: str = None) -> ProfileLoader:
    """
    獲取全域配置載入器實例（單例模式）
    
    Args:
        profiles_dir: 配置檔案目錄，僅在首次呼叫時有效
    
    Returns:
        ProfileLoader 實例
    """
    global _global_loader
    
    if _global_loader is None:
        _global_loader = ProfileLoader(profiles_dir)
    
    return _global_loader


def load_profile(profile_name: str) -> Optional[Dict]:
    """
    便捷函數：載入指定配置
    
    Args:
        profile_name: 配置名稱
    
    Returns:
        配置字典
    """
    loader = get_profile_loader()
    return loader.load_profile(profile_name)


def get_modbus_profile(profile_name: str) -> Optional[Dict]:
    """
    便捷函數：獲取 Modbus 配置設定
    
    Args:
        profile_name: 配置名稱
    
    Returns:
        Modbus 配置字典
    """
    loader = get_profile_loader()
    return loader.get_modbus_config(profile_name)


def get_s7_profile(profile_name: str) -> Optional[Dict]:
    """
    便捷函數：獲取 S7 配置設定
    
    Args:
        profile_name: 配置名稱
    
    Returns:
        S7 配置字典
    """
    loader = get_profile_loader()
    return loader.get_s7_config(profile_name)


if __name__ == "__main__":
    # 測試載入器
    loader = get_profile_loader()
    
    print("\n=== Available Profiles ===")
    for profile in loader.list_profiles():
        info = loader.get_profile_info(profile)
        if info:
            print(f"- {profile}: {info['name']} - {info['description']}")
    
    print("\n=== Test Loading water_treatment ===")
    modbus_cfg = get_modbus_profile("water_treatment")
    if modbus_cfg:
        print(f"Modbus Registers: {len(modbus_cfg.get('registers', []))}")
        print(f"Modbus Coils: {len(modbus_cfg.get('coils', []))}")
    
    s7_cfg = get_s7_profile("water_treatment")
    if s7_cfg:
        print(f"S7 DBs: {len(s7_cfg.get('db', {}))}")
        print(f"S7 Merkers: {len(s7_cfg.get('m', {}))}")

