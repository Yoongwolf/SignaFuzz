#app/core.py
import logging
import socket
import sctp
from typing import Dict, Any, Optional
from app.message_factory import MessageFactory, MAPMessage
from utils.validators import validate_ip, validate_port, validate_protocol, validate_imsi, validate_msisdn, validate_gt, validate_ssn
from utils.network.tcp_client import TCPClient

class Ss7Tool:
    """
    Core SS7 tool for sending and receiving MAP messages.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SS7 tool with configuration.
        
        Args:
            config: Configuration dictionary with target_ip, target_port, protocol, etc.
        """
        self.target_ip = config["target_ip"]
        self.target_port = int(config["target_port"])
        self.protocol = config.get("protocol", "SCTP").upper()
        self.imsi = config.get("imsi")
        self.msisdn = config.get("msisdn")
        self.vlr = config.get("vlr")
        self.ssn = int(config["ssn"])
        self.gt = config.get("gt")
        self.response = None
        self.packet = None
        
        self._validate_inputs()
    
    def _validate_inputs(self):
        if not validate_ip(self.target_ip):
            raise ValueError("Invalid target IP address")
        if not validate_port(self.target_port):
            raise ValueError("Invalid target port")
        if not validate_protocol(self.protocol):
            raise ValueError("Invalid protocol: must be SCTP or TCP")
        if self.imsi and not validate_imsi(self.imsi):
            raise ValueError("Invalid IMSI: must be 15 digits")
        if self.msisdn and not validate_msisdn(self.msisdn):
            raise ValueError("Invalid MSISDN: must be 10–15 digits")
        if self.gt and not validate_gt(self.gt):
            raise ValueError("Invalid Global Title (GT): must be 10–15 digits")
        if self.ssn is not None and not validate_ssn(self.ssn):
            raise ValueError("Invalid SSN: must be integer 0–254")
    
    def send_message(self, operation: str, vlr_number: Optional[str] = None) -> None:
        """
        Send an SS7 MAP message.
        
        Args:
            operation: MAP operation (sri, ati, ul, psi)
            vlr_number: VLR number for UpdateLocation (optional)
        """
        try:
            # Create MAP message
            if operation == "sri":
                if not self.imsi or not self.msisdn:
                    raise ValueError("IMSI and MSISDN required for SendRoutingInfo")
                self.packet = MessageFactory.create_send_routing_info(self.imsi, self.msisdn)
            elif operation == "ati":
                if not self.imsi:
                    raise ValueError("IMSI required for AnyTimeInterrogation")
                self.packet = MessageFactory.create_any_time_interrogation(self.imsi)
            elif operation == "ul":
                if not self.imsi or not vlr_number:
                    raise ValueError("IMSI and VLR number required for UpdateLocation")
                self.packet = MessageFactory.create_update_location(self.imsi, vlr_number)
            elif operation == "psi":
                if not self.imsi:
                    raise ValueError("IMSI required for ProvideSubscriberInfo")
                self.packet = MessageFactory.create_provide_subscriber_info(self.imsi)
            else:
                raise ValueError(f"Unsupported operation: {operation}")
            
            # Construct TCAP/MAP packet
            packet_bytes = (
                bytes([0x02, 0x01, self.packet.invoke_id, 0x02, 0x01, self.packet.opcode]) +
                bytes([0x30, len(self.packet.params) + 2, 0x80, len(self.packet.params)]) +
                self.packet.params
            )
            logging.info(f"[MAP] Packet (hex): {packet_bytes.hex().upper()}")
            
            # Send packet
            if self.protocol == "SCTP":
                sock = sctp.sctpsocket_tcp(socket.AF_INET)
                try:
                    sock.settimeout(10.0)
                    sock.connect((self.target_ip, self.target_port))
                    logging.info(f"Successfully connected to {self.target_ip}:{self.target_port}")
                    sock.send(packet_bytes)
                    self.response = sock.recv(4096)
                    logging.info(f"[MAP] Response (hex): {self.response.hex().upper()}")
                finally:
                    sock.close()
                    logging.info(f"SCTP connection to {self.target_ip}:{self.target_port} closed")
            elif self.protocol == "TCP":
                client = TCPClient(self.target_ip, self.target_port, timeout=10.0)
                try:
                    self.response = client.send(packet_bytes)
                    logging.info(f"[MAP] Response (hex): {self.response.hex().upper()}")
                finally:
                    client.close()
            else:
                raise ValueError(f"Unsupported protocol: {self.protocol}")
            
            print("✅ Packet sent successfully.")
        
        except (socket.timeout, socket.gaierror, Exception) as e:
            logging.error(f"Error during operation: {e}")
            print(f"❌ Error: {e}")
            raise
    
    def handle_response(self):
        if self.response:
            print(f"📨 Response received (hex): {self.response.hex().upper()}")
        else:
            print("⚠️ No response received.")