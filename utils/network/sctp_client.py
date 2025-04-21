# utils/network/sctp_client.py

import socket
import logging


class SCTPClient:
    def __init__(self, target_ip: str, target_port: int, buffer_size: int = 4096):
        self.target_ip = target_ip
        self.target_port = target_port
        self.buffer_size = buffer_size
        self.sock = None

    def connect(self):
        try:
            # Create SCTP socket (SOCK_STREAM for 1-to-1 style)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
            self.sock.connect((self.target_ip, self.target_port))
            logging.info(f"[SCTP] Connected to {self.target_ip}:{self.target_port}")
        except Exception as e:
            logging.error(f"[SCTP] Connection failed: {e}")
            raise

    def send(self, payload: bytes) -> bytes:
        try:
            if self.sock is None:
                self.connect()

            self.sock.send(payload)
            logging.info(f"[SCTP] Sent {len(payload)} bytes")

            response = self.sock.recv(self.buffer_size)
            logging.info(f"[SCTP] Received {len(response)} bytes")

            return response

        except Exception as e:
            logging.error(f"[SCTP] Send/Receive error: {e}")
            raise

    def close(self):
        if self.sock:
            self.sock.close()
            logging.info("[SCTP] Connection closed")
