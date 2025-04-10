# app/core.py

from utils.protocols.ss7_layers import MTP3, SCCP, TCAP, MAP
from scapy.all import IP, send
from scapy.contrib.sctp import SCTP, SCTPChunkData


class Ss7Tool:
    def __init__(self, config):
        self.config = config

    def send_message(self):
        print("[+] Sending MAP message with following config:")
        for k, v in self.config.items():
            print(f"{k}: {v}")

        imsi = self.config["imsi"]
        padded_imsi = imsi.ljust(8, '\x00')[:8]  # MAP expects 8 bytes

        # Construct MAP layer
        map_layer = MAP(imsi=padded_imsi.encode())

        # Wrap it with TCAP
        tcap_layer = TCAP(data=bytes(map_layer))

        # SCCP wrapping
        sccp_layer = SCCP(user_data=bytes(tcap_layer))

        # MTP3 layer
        mtp3_layer = MTP3(DPC_SPC=0x123456, SIO=0x83, Service_Indicator=3)

        # SCTP chunk
        sctp_chunk = SCTPChunkData(data=bytes(mtp3_layer / sccp_layer))

        # IP + SCTP + Chunk (correct stacking)
        ip = IP(dst=self.config["target_ip"])
        sctp = SCTP(dport=int(self.config["target_port"]))

        full_packet = ip / sctp / sctp_chunk

        print("[*] Final Packet Constructed:")
        full_packet.show()

        print("[+] Sending packet (simulation)...")
        send(full_packet)
        print("[+] Packet sent!")

    def handle_response(self):
        print("[*] Awaiting response... (Simulation)")
        print("[+] Response handled.")
