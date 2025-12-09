import json
import os

class ConfigLoader:
    def __init__(self, config_path=None):
        if config_path is None:
            # Resolve relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.config_path = os.path.join(base_dir, "client_config.json")
        else:
            self.config_path = config_path
        
        self.config = self._load_default_config()

    def _load_default_config(self):
        return {
            "server_url": "http://localhost:8000",
            "node_id": "node_01",
            "plcs": [
                {
                    "type": "modbus",
                    "enabled": True,
                    "port": 5020, # Default to 5020 to avoid root requirement on dev machine
                    "model": "Simulated Modbus Device"
                },
                {
                    "type": "s7comm",
                    "enabled": True,
                    "port": 1020, # Default to 1020
                    "model": "S7-300"
                }
            ]
        }

    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}, using default.")
        return self.config

    def save_config(self, config):
        self.config = config
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=4)
