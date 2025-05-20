#mock_ss7_server.py
import logging
import socket
from scapy.all import raw, hexdump
from utils.protocols.ss7_layers import SCCP_UDT, TCAP_Invoke, TCAP_ReturnResultLast, MAP_SRI, MAP_ATI, MAP_UL, MAP_PSI
from utils.encoding.bcd import encode_bcd

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")

def create_response(request_packet: SCCP_UDT) -> bytes:
    try:
        logging.debug(f"Received packet hex: {raw(request_packet).hex()}")
        if not request_packet.haslayer(TCAP_Invoke):
            logging.error("No TCAP_Invoke layer in request")
            hexdump(raw(request_packet))
            return b""
        
        tcap_req = request_packet[TCAP_Invoke]
        response = SCCP_UDT(
            msg_type=0x09,
            protocol_class=0x00,
            called_party=encode_bcd("2143658709"),
            calling_party=encode_bcd("2143658709"),
            called_len=5,
            calling_len=5
        )
        
        tcap_resp = TCAP_ReturnResultLast(
            invoke_id=tcap_req.invoke_id,
            opcode=tcap_req.opcode
        )
        
        if request_packet.haslayer(MAP_SRI):
            map_sri = request_packet[MAP_SRI]
            map_resp = MAP_SRI(
                imsi=map_sri.imsi,
                msisdn=map_sri.msisdn,
                imsi_len=len(map_sri.imsi),
                msisdn_len=len(map_sri.msisdn)
            )
        elif request_packet.haslayer(MAP_ATI):
            map_ati = request_packet[MAP_ATI]
            map_resp = MAP_ATI(
                imsi=map_ati.imsi,
                imsi_len=len(map_ati.imsi)
            )
        elif request_packet.haslayer(MAP_UL):
            map_ul = request_packet[MAP_UL]
            map_resp = MAP_UL(
                imsi=map_ul.imsi,
                vlr_gt=map_ul.vlr_gt,
                imsi_len=len(map_ul.imsi),
                vlr_gt_len=len(map_ul.vlr_gt)
            )
        elif request_packet.haslayer(MAP_PSI):
            map_psi = request_packet[MAP_PSI]
            map_resp = MAP_PSI(
                imsi=map_psi.imsi,
                imsi_len=len(map_psi.imsi)
            )
        else:
            logging.error("Unknown MAP layer")
            return b""
        
        response /= tcap_resp / map_resp
        response.data_len = len(raw(tcap_resp / map_resp))
        logging.debug(f"Sending response hex: {raw(response).hex()}")
        return raw(response)
    except Exception as e:
        logging.error(f"Response creation error: {e}")
        return b""

def run_server(host: str = "127.0.0.1", port: int = 2905):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
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