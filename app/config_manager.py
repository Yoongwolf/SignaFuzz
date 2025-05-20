#app/config_manger.py
import os
import logging
import yaml
from typing import Optional

class ConfigManager:
    def __init__(self, config_file: str = "configs/default_config.yml"):
        self.logger = logging.getLogger(__name__)
        self.config_file = config_file
        self.api_key: Optional[str] = None
        self.target_ip: str = "127.0.0.1"
        self.target_port: int = 2905
        self.protocol: str = "SCTP"
        self.ssn: int = 6
        self.country_code: int = 91
        self.default_imsi: str = "123456789012345"
        self.default_msisdn: str = "9876543210"
        self.default_gt: str = "1234567890"
        self.config = {}
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from YAML file or environment variables."""
        try:
            # Check environment variables first
            self.api_key = os.getenv("SS7_API_KEY")
            self.target_ip = os.getenv("SS7_TARGET_IP", self.target_ip)
            self.target_port = int(os.getenv("SS7_TARGET_PORT", str(self.target_port)))
            self.protocol = os.getenv("SS7_PROTOCOL", self.protocol)
            self.ssn = int(os.getenv("SS7_SSN", str(self.ssn)))
            self.country_code = int(os.getenv("SS7_COUNTRY_CODE", str(self.country_code)))
            self.default_imsi = os.getenv("SS7_DEFAULT_IMSI", self.default_imsi)
            self.default_msisdn = os.getenv("SS7_DEFAULT_MSISDN", self.default_msisdn)
            self.default_gt = os.getenv("SS7_DEFAULT_GT", self.default_gt)

            # Load from YAML config file if it exists
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
                    if self.config:
                        network = self.config.get("network", {})
                        ss7 = self.config.get("ss7", {})
                        self.api_key = ss7.get("api_key", self.api_key)
                        self.target_ip = network.get("default_ip", self.target_ip)
                        self.target_port = network.get("default_port", self.target_port)
                        self.protocol = network.get("protocol", self.protocol)
                        self.ssn = ss7.get("ssn", self.ssn)
                        self.country_code = ss7.get("country_code", self.country_code)
                        self.default_imsi = ss7.get("default_imsi", self.default_imsi)
                        self.default_msisdn = ss7.get("default_msisdn", self.default_msisdn)
                        self.default_gt = ss7.get("default_gt", self.default_gt)

            if not self.api_key:
                self.logger.info("No API key found, using default 'test_key_123'")
                self.api_key = "test_key_123"

            self.logger.info("Configuration loaded successfully")
        except Exception as e:
            self.logger.error(f"Configuration loading error: {e}")
            raise

    def get_config(self, key: str, default=None):
        return self.config.get(key, default)

    def set_config(self, key: str, value) -> None:
        self.config[key] = value
        try:
            with open(self.config_file, 'w') as f:
                yaml.safe_dump(self.config, f)
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
