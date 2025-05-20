# utils/network/sctp_client.py
import socket
import logging
import time
from scapy.all import raw

class SCTPClient:
    def __init__(self, target_ip: str, target_port: int, timeout: float = 2.0, retries: int = 3):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.retries = retries
        self.sock = None
        self.logger = logging.getLogger(__name__)

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target_ip, self.target_port))
            self.logger.info(f"Connected to {self.target_ip}:{self.target_port}")
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            raise

    def send(self, packet: bytes):
        if not self.sock:
            self.connect()
        try:
            self.sock.sendall(packet)
            self.logger.debug(f"Sent packet: {packet.hex()}")
        except Exception as e:
            self.logger.error(f"Send error: {e}")
            raise

    def receive(self, buffer_size: int = 1024) -> bytes:
        if not self.sock:
            self.logger.error("No active connection")
            return b""
        for attempt in range(self.retries):
            try:
                data = self.sock.recv(buffer_size)
                if data:
                    self.logger.debug(f"Received packet: {data.hex()}")
                    return data
                self.logger.warning(f"Empty response on attempt {attempt + 1}")
                time.sleep(0.1)
            except socket.timeout:
                self.logger.warning(f"Receive timeout on attempt {attempt + 1}")
            except Exception as e:
                self.logger.error(f"Receive error: {e}")
                break
        return b""

    def send_packet(self, packet: bytes) -> bytes:
        try:
            self.connect()
            self.send(packet)
            response = self.receive()
            return response
        except Exception as e:
            self.logger.error(f"Send/receive error: {e}")
            raise
        finally:
            self.close()

    def close(self):
        if self.sock:
            try:
                self.sock.close()
                self.logger.info("Connection closed")
            except Exception as e:
                self.logger.error(f"Close error: {e}")
            finally:
                self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()