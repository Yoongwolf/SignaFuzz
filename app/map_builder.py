from scapy.packet import Packet
from utils.encoding.bcd import encode_bcd
from utils.protocols.ss7_layers import MAP


def build_map_send_routing_info(imsi: str) -> Packet:
    bcd_imsi = encode_bcd(imsi)

    map_layer = MAP(
        invoke_id=0x02,
        opcode_tag=0x02,
        opcode_length=1,
        opcode=0x04,  # SendRoutingInfo
        param_tag=0x30,
        param_length=2 + 2 + len(bcd_imsi),  # imsi_tag + length + bcd_imsi
        imsi_tag=0x80,
        imsi_length=len(bcd_imsi),
        imsi=bcd_imsi
    )

    return map_layer
