# app/config_manager.py

import os
import yaml
import logging
from typing import Dict, Any, Optional

class ConfigManager:
    """
    Manager for configuration settings.
    """
    
    DEFAULT_CONFIG_PATH = os.path.join("configs", "default_config.yml")
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to custom configuration file (optional)
        """
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f) or {}
            else:
                logging.warning(f"Config file not found: {self.config_path}, using defaults")
                return self._get_default_config()
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get default configuration values.
        
        Returns:
            Default configuration dictionary
        """
        return {
            "network": {
                "default_protocol": "SCTP",
                "default_port": 2905,
                "timeout": 10,
                "buffer_size": 4096
            },
            "logging": {
                "level": "INFO",
                "format": "[%(asctime)s] %(levelname)s: %(message)s",
                "date_format": "%Y-%m-%d %H:%M:%S",
                "file": "logs/ss7_tool.log"
            },
            "defaults": {
                "ssn": "6",
                "country_code": "91"
            }
        }
    
    def get(self, key: str, default=None) -> Any:
        """
        Get configuration value by key.
        
        Args:
            key: Configuration key (use dot notation for nested keys)
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        try:
            keys = key.split('.')
            value = self.config
            for k in keys:
                value = value.get(k)
                if value is None:
                    return default
            return value
        except Exception:
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value.
        
        Args:
            key: Configuration key (use dot notation for nested keys)
            value: Configuration value
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to the deepest dict
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
            
        # Set the value
        config[keys[-1]] = value
    
    def save(self, config_path: Optional[str] = None) -> bool:
        """
        Save configuration to file.
        
        Args:
            config_path: Path to save configuration (optional)
            
        Returns:
            True if successful, False otherwise
        """
        path = config_path or self.config_path
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            return True
        except Exception as e:
            logging.error(f"Error saving config: {e}")
            return False