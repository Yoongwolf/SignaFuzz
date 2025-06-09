import logging
import hashlib
from utils.network.sctp_client import SCTPClient
from utils.network.tcp_client import TCPClient
from app.message_factory import MessageFactory
from app.response_parser import ResponseParser
from app.config_manager import ConfigManager
from utils.validators import validate_imsi, validate_msisdn, validate_gt, validate_ssn, validate_ip, validate_port, validate_protocol

class SS7Core:
    def __init__(self, api_key: str = None):
        self.logger = logging.getLogger(__name__)
        self.config = ConfigManager()
        self.api_key = api_key or self.config.api_key
        self.message_factory = MessageFactory()
        self.response_parser = ResponseParser()
        self._validate_api_key()

    def _validate_api_key(self):
        """Validate API key (P2: Security)."""
        if not self.api_key:
            self.logger.error("No API key provided")
            raise ValueError("Invalid API key")
        # Allow 'test_key_123' for testing
        if self.api_key == "test_key_123":
            return
        expected_hash = "cc5c1e78a0438ac4a4d55d4ac6ac66c0"  # MD5 hash of "test_key_123"
        if hashlib.md5(self.api_key.encode()).hexdigest() != expected_hash:
            self.logger.error("Invalid API key")
            raise ValueError("Invalid API key")

    def send_sri(self, imsi: str, msisdn: str, target_ip: str, target_port: int, ssn: int, gt: str, protocol: str) -> dict:
        if not all([validate_imsi(imsi), validate_msisdn(msisdn), validate_ip(target_ip), validate_port(target_port), validate_ssn(ssn), validate_gt(gt), validate_protocol(protocol)]):
            self.logger.error("Invalid input parameters for SRI")
            return {"status": "error", "message": "Invalid input parameters"}
        
        packet = self.message_factory.create_sri_message(imsi, msisdn, gt, ssn)
        return self._send_packet(packet, "SRI", target_ip, target_port, {"imsi": imsi, "msisdn": msisdn, "gt": gt, "ssn": ssn, "target_ip": target_ip, "target_port": target_port, "protocol": protocol})

    def send_ati(self, imsi: str, target_ip: str, target_port: int, ssn: int, gt: str, protocol: str) -> dict:
        if not all([validate_imsi(imsi), validate_ip(target_ip), validate_port(target_port), validate_ssn(ssn), validate_gt(gt), validate_protocol(protocol)]):
            self.logger.error("Invalid input parameters for ATI")
            return {"status": "error", "message": "Invalid input parameters"}
        
        packet = self.message_factory.create_ati_message(imsi, gt, ssn)
        return self._send_packet(packet, "ATI", target_ip, target_port, {"imsi": imsi, "gt": gt, "ssn": ssn, "target_ip": target_ip, "target_port": target_port, "protocol": protocol})

    def send_ul(self, imsi: str, vlr_gt: str, target_ip: str, target_port: int, ssn: int, gt: str, protocol: str) -> dict:
        if not all([validate_imsi(imsi), validate_gt(vlr_gt), validate_ip(target_ip), validate_port(target_port), validate_ssn(ssn), validate_gt(gt), validate_protocol(protocol)]):
            self.logger.error("Invalid input parameters for UL")
            return {"status": "error", "message": "Invalid input parameters"}
        
        packet = self.message_factory.create_ul_message(imsi, vlr_gt, gt, ssn)
        return self._send_packet(packet, "UL", target_ip, target_port, {"imsi": imsi, "vlr_gt": vlr_gt, "gt": gt, "ssn": ssn, "target_ip": target_ip, "target_port": target_port, "protocol": protocol})

    def send_psi(self, imsi: str, target_ip: str, target_port: int, ssn: int, gt: str, protocol: str) -> dict:
        if not all([validate_imsi(imsi), validate_ip(target_ip), validate_port(target_port), validate_ssn(ssn), validate_gt(gt), validate_protocol(protocol)]):
            self.logger.error("Invalid input parameters for PSI")
            return {"status": "error", "message": "Invalid input parameters"}
        
        packet = self.message_factory.create_psi_message(imsi, gt, ssn)
        return self._send_packet(packet, "PSI", target_ip, target_port, {"imsi": imsi, "gt": gt, "ssn": ssn, "target_ip": target_ip, "target_port": target_port, "protocol": protocol})

    

    def get_history(self, limit: int = 10) -> list:
        return self.response_parser.get_history(limit=limit)

    def get_filtered_history(self, operation: str = None, start_date: str = None, end_date: str = None, limit: int = 10) -> list:
        return self.response_parser.get_filtered_history(operation, start_date, end_date, limit)
    
    def _send_packet(self, packet, operation, target_ip, target_port, params):
        try:
            client = SCTPClient(target_ip, target_port) if params["protocol"] == "SCTP" else TCPClient(target_ip, target_port)
            self.logger.info(f"Sending {operation} packet to {target_ip}:{target_port} with protocol {params['protocol']}")
            response = client.send_packet(packet)
            result = self.response_parser.parse_response(response)
        except Exception as e:
            self.logger.error(f"Failed to send {operation} packet: {str(e)}")
            result = {
                "status": "error",
                "message": str(e),
                "operation": operation,
                "params": params,  # Include params for storage
                "raw_response": ""
            }
        self.response_parser._store_response(result)
        return result