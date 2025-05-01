# utils/network/tcp_client.py
import logging
import socket
from typing import Optional

class TCPClient:
    """
    TCP client for SS7 communication (fallback for testing).
    """
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        """
        Initialize TCP client.

        Args:
            host: Target host IP
            port: Target port
            timeout: Socket timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        """
        Connect to the target host.

        Raises:
            socket.timeout: If connection times out
            socket.gaierror: If host resolution fails
            Exception: For other connection errors
        """
        try:
            logging.debug(f"Attempting TCP connection to {self.host}:{self.port}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            logging.info(f"Successfully connected to {self.host}:{self.port}")
        except socket.timeout:
            logging.error(f"Connection to {self.host}:{self.port} timed out after {self.timeout}s")
            raise
        except socket.gaierror as e:
            logging.error(f"Failed to resolve host {self.host}: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error connecting to {self.host}:{self.port}: {e}")
            raise

    def send(self, data: bytes) -> bytes:
        """
        Send data and receive response.

        Args:
            data: Data to send

        Returns:
            Response data

        Raises:
            socket.timeout: If send/receive times out
            Exception: For other send/receive errors
        """
        try:
            if not self.sock:
                self.connect()
            logging.debug(f"Sending data: {data.hex().upper()}")
            self.sock.sendall(data)
            response = self.sock.recv(4096)
            logging.debug(f"Received response: {response.hex().upper()}")
            return response
        except socket.timeout:
            logging.error(f"Send/receive timeout for {self.host}:{self.port} after {self.timeout}s")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during send/receive: {e}")
            raise

    def close(self) -> None:
        """
        Close the TCP connection.
        """
        if self.sock:
            try:
                self.sock.close()
                logging.info(f"TCP connection to {self.host}:{self.port} closed")
            except Exception as e:
                logging.error(f"Error closing connection: {e}")
            finally:
                self.sock = None