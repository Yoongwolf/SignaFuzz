# app/core.py

import logging
from scapy.all import raw
from app.map_builder import build_map_send_routing_info
from utils.encoding.bcd import encode_bcd
from utils.network.sctp_client import SCTPClient
from utils.validators import (
    validate_imsi, validate_msisdn, validate_gt, validate_ssn
)

class Ss7Tool:
    def __init__(self, config: dict):
        self.imsi = config.get("imsi")
        self.msisdn = config.get("msisdn")
        self.target_ip = config.get("target_ip")
        self.target_port = int(config.get("target_port", 0))
        self.protocol = config.get("protocol", "SCTP").upper()
        self.ssn = config.get("ssn")
        self.gt = config.get("gt")

        self.client = None
        self.packet = None
        self.response = None

        self._validate_inputs()

    def _validate_inputs(self):
        if not validate_imsi(self.imsi):
            raise ValueError("Invalid IMSI: must be 15 digits")
        if not validate_msisdn(self.msisdn):
            raise ValueError("Invalid MSISDN: must be 10–15 digits")
        if not validate_gt(self.gt):
            raise ValueError("Invalid Global Title (GT): must be 10–15 digits")
        if not validate_ssn(self.ssn):
            raise ValueError("Invalid SSN: must be integer 0–254")
        if self.protocol not in ["SCTP"]:
            raise ValueError("Invalid Protocol: only SCTP supported for now")

    def send_message(self):
        try:
            self.packet = build_map_send_routing_info(self.imsi)
            packet_bytes = raw(self.packet)

            logging.info(f"[MAP] Packet (hex): {packet_bytes.hex().upper()}")

            self.client = SCTPClient(self.target_ip, self.target_port)
            self.client.connect()
            self.response = self.client.send(packet_bytes)
            self.client.close()

            logging.info(f"[MAP] Response (hex): {self.response.hex().upper()}")
            print("✅ Packet sent successfully.")
        except Exception as e:
            logging.error(f"[SEND] Error during sending: {e}")
            raise

    def handle_response(self):
        if self.response:
            print(f"📨 Response received (hex): {self.response.hex().upper()}")
        else:
            print("⚠️ No response received.")
