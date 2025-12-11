"""
Profiles Package - PLC Simulation Profiles

此套件包含預定義的工業配置檔案 (Profiles) 和載入器。
"""

from .profile_loader import (
    ProfileLoader,
    get_profile_loader,
    load_profile,
    get_modbus_profile,
    get_s7_profile
)

__all__ = [
    'ProfileLoader',
    'get_profile_loader',
    'load_profile',
    'get_modbus_profile',
    'get_s7_profile'
]

__version__ = '1.0.0'
