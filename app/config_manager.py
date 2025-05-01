#app/config_manger.py
import yaml
import logging
import os
from cryptography.fernet import Fernet
from typing import Dict, Any

class ConfigManager:
    """
    Manager for loading, saving, and encrypting configuration.
    """
    SENSITIVE_KEYS = ["default_imsi", "default_msisdn", "default_gt"]
    ENCRYPTION_KEY_FILE = "config_key.key"

    def __init__(self, config_file: str = "configs/default_config.yml"):
        """
        Initialize config manager.

        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.cipher = None
        self._load_key()
        self.load()

    def _load_key(self) -> None:
        """
        Load or generate encryption key for sensitive fields.
        """
        try:
            if os.path.exists(self.ENCRYPTION_KEY_FILE):
                with open(self.ENCRYPTION_KEY_FILE, "rb") as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(self.ENCRYPTION_KEY_FILE, "wb") as f:
                    f.write(key)
            self.cipher = Fernet(key)
            logging.debug("Encryption key loaded")
        except Exception as e:
            logging.error(f"Failed to load encryption key: {e}")
            raise RuntimeError("Encryption setup failed")

    def _encrypt_sensitive(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt sensitive configuration fields.

        Args:
            config: Configuration dictionary

        Returns:
            Config with encrypted sensitive fields
        """
        result = config.copy()
        try:
            if "ss7" in result:
                for key in self.SENSITIVE_KEYS:
                    if key in result["ss7"]:
                        value = result["ss7"][key]
                        if value and isinstance(value, str) and not value.startswith("gAAAAAB"):
                            result["ss7"][key] = self.cipher.encrypt(value.encode()).decode()
            return result
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise RuntimeError("Failed to encrypt configuration")

    def _decrypt_sensitive(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt sensitive configuration fields.

        Args:
            config: Configuration dictionary

        Returns:
            Config with decrypted sensitive fields
        """
        result = config.copy()
        try:
            if "ss7" in result:
                for key in self.SENSITIVE_KEYS:
                    if key in result["ss7"]:
                        value = result["ss7"][key]
                        if value and isinstance(value, str):
                            try:
                                result["ss7"][key] = self.cipher.decrypt(value.encode()).decode()
                            except Exception:
                                logging.debug(f"Field {key} not encrypted, using as-is")
                                result["ss7"][key] = value
            return result
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise RuntimeError("Failed to decrypt configuration")

    def load(self) -> None:
        """
        Load configuration from file.
        """
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
                self.config = self._decrypt_sensitive(self.config)
                logging.info(f"Configuration loaded from {self.config_file}")
            else:
                logging.warning(f"Config file {self.config_file} not found, using defaults")
                self.config = {
                    "network": {"default_ip": "127.0.0.1", "default_port": 2905, "protocol": "SCTP"},
                    "logging": {"log_file": "logs/ss7_tool.log", "log_level": "INFO"},
                    "ss7": {"ssn": 6, "country_code": 91, "default_imsi": "123456789012345",
                            "default_msisdn": "9876543210", "default_gt": "1234567890"}
                }
                self.save(self.config_file)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            raise RuntimeError(f"Failed to load config: {e}")

    def save(self, config_file: str) -> None:
        """
        Save configuration to file.

        Args:
            config_file: Path to save configuration
        """
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            encrypted_config = self._encrypt_sensitive(self.config)
            with open(config_file, 'w') as f:
                yaml.safe_dump(encrypted_config, f, default_flow_style=False)
            logging.info(f"Configuration saved to {config_file}")
        except Exception as e:
            logging.error(f"Error saving config: {e}")
            raise RuntimeError(f"Failed to save config: {e}")