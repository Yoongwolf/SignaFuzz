#mock_tcp_server.py
import socket
import logging

def run_mock_server(host: str = "127.0.0.1", port: int = 2906):
    """
    Run a mock SS7 TCP server that returns a valid MAP response.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)
        logging.info(f"Mock TCP server listening on {host}:{port}")

        while True:
            client_sock, addr = sock.accept()
            try:
                logging.info(f"Connection from {addr}")
                data = client_sock.recv(4096)
                if data:
                    logging.info(f"Received: {data.hex().upper()}")
                    # Valid MAP response for SRI
                    response = bytes.fromhex("0202020201043011800821436587092143f581058967452301")
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