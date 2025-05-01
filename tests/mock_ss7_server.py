import sctp
import socket
import logging
from utils.encoding.bcd import encode_bcd

def run_mock_server(host: str = "127.0.0.1", port: int = 2905):
    """
    Run a mock SS7 SCTP server that returns a valid MAP response.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s:%(message)s")
    sock = None
    try:
        sock = sctp.sctpsocket_tcp(socket.AF_INET)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)
        logging.info(f"Mock SS7 server listening on {host}:{port}")

        while True:
            client_sock, addr = sock.accept()
            try:
                logging.info(f"Connection from {addr}")
                data = client_sock.recv(4096)
                if data:
                    logging.info(f"Received: {data.hex().upper()}")
                    # Generate response with corrected BCD
                    imsi = "123456789012345"
                    msisdn = "9876543210"
                    encoded_imsi = encode_bcd(imsi)  # 8 bytes
                    encoded_msisdn = encode_bcd(msisdn)  # 5 bytes
                    response = (
                        bytes([0x02, 0x02, 0x02, 0x02, 0x01, 0x04]) +  # Header
                        bytes([0x30, 0x11, 0x80, 0x08]) + encoded_imsi +  # IMSI
                        bytes([0x81, 0x05]) + encoded_msisdn  # MSISDN
                    )
                    client_sock.send(response)
                    logging.info(f"Sent response: {response.hex().upper()}")
                else:
                    logging.warning("Empty data received")
            except Exception as e:
                logging.error(f"Client error: {e}")
            finally:
                client_sock.close()
                logging.info(f"Connection to {addr} closed")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        if sock:
            sock.close()
            logging.info("Mock server socket closed")

if __name__ == "__main__":
    run_mock_server()