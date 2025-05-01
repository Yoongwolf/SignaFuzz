#test/test_connectivity.py
import pytest
import sctp
import socket

@pytest.mark.parametrize("host,port,protocol", [
    ("127.0.0.1", 2905, "SCTP"),
    ("127.0.0.1", 2906, "TCP")
])
def test_connectivity(host: str, port: int, protocol: str):
    """Test connectivity to mock servers."""
    if protocol == "SCTP":
        sock = sctp.sctpsocket_tcp(socket.AF_INET)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
    finally:
        sock.close()