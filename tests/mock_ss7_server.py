#mock_ss7_server.py
import logging
import socket
from scapy.all import raw
from utils.protocols.ss7_layers import SCCP_UDT, TCAP_Invoke, TCAP_ReturnResultLast, MAP_SRI, MAP_ATI, MAP_UL, MAP_PSI
from utils.encoding.bcd import encode_bcd

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")

def create_response(request_packet: SCCP_UDT) -> bytes:
    try:
        logging.debug(f"Received packet hex: {raw(request_packet).hex()}")
        if not request_packet.haslayer(TCAP_Invoke):
            logging.error("No TCAP_Invoke layer in request")
            return b""
        
        tcap_req = request_packet[TCAP_Invoke]
        response = SCCP_UDT(
            msg_type=0x09,
            protocol_class=0x00,
            pointer1=0x03,
            pointer2=0x00,
            pointer3=0x00,
            called_party=encode_bcd("1234567890"),
            calling_party=encode_bcd("1234567890"),
            called_len=5,
            calling_len=5
        )
        
        map_resp = None
        if request_packet.haslayer(MAP_SRI):
            map_sri = request_packet[MAP_SRI]
            map_resp = MAP_SRI(
                tag=0x04,
                imsi=map_sri.imsi,  # Full IMSI
                msisdn=map_sri.msisdn  # Full MSISDN
            )
        elif request_packet.haslayer(MAP_ATI):
            map_ati = request_packet[MAP_ATI]
            map_resp = MAP_ATI(
                tag=0x47,
                imsi=map_ati.imsi
            )
        elif request_packet.haslayer(MAP_UL):
            map_ul = request_packet[MAP_UL]
            map_resp = MAP_UL(
                tag=0x02,
                imsi=map_ul.imsi,
                vlr_gt=map_ul.vlr_gt
            )
        elif request_packet.haslayer(MAP_PSI):
            map_psi = request_packet[MAP_PSI]
            map_resp = MAP_PSI(
                tag=0x46,
                imsi=map_psi.imsi
            )
        else:
            logging.error("Unknown MAP layer")
            return b""
        
        # Build TCAP_ReturnResultLast with MAP payload
        tcap_resp = TCAP_ReturnResultLast(
            tag=0x04,
            invoke_id_tag=0x02,
            invoke_id_len=0x01,
            invoke_id=tcap_req.invoke_id,
            sequence_tag=0x30,
            opcode_tag=0x02,
            opcode_len=0x01,
            opcode=tcap_req.opcode
        ) / map_resp
        
        tcap_raw = raw(tcap_resp)
        response = response / tcap_resp
        response.data_len = len(tcap_raw)
        logging.debug(f"Sending response hex: {raw(response).hex()}")
        return raw(response)
    except Exception as e:
        logging.error(f"Response creation error: {e}")
        return b""

def run_server(host: str = "127.0.0.1", port: int = 2905):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    logging.info(f"Mock SS7 server listening on {host}:{port}")
    
    try:
        while True:
            conn, addr = sock.accept()
            logging.info(f"Connection from {addr}")
            try:
                data = conn.recv(1024)
                if not data:
                    continue
                logging.debug(f"Received: {data.hex()}")
                
                request_packet = SCCP_UDT(data)
                response = create_response(request_packet)
                if response:
                    conn.send(response)
                else:
                    logging.error("No response generated")
            except Exception as e:
                logging.error(f"Client error: {e}")
            finally:
                logging.info(f"Connection to {addr} closed")
                conn.close()
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        sock.close()

if __name__ == "__main__":
    run_server()