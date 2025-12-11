"""
Scenarios Package - PLC Simulation Scenarios

此套件包含預定義的工業場景配置檔案和載入器。
"""

from .scenario_loader import (
    ScenarioLoader,
    get_scenario_loader,
    load_scenario,
    get_modbus_scenario,
    get_s7_scenario
)

__all__ = [
    'ScenarioLoader',
    'get_scenario_loader',
    'load_scenario',
    'get_modbus_scenario',
    'get_s7_scenario'
]

__version__ = '1.0.0'

