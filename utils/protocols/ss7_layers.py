# utils/protocols/ss7_layers.py

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteField,
    IntField,
    StrLenField,
    StrFixedLenField,
    FieldLenField
)
from scapy.layers.inet import IP
from scapy.all import load_contrib
load_contrib("sctp")

from scapy.contrib.sctp import SCTP, SCTPChunkData


# Custom 3-byte field for DPC/OPC in MTP3
class ThreeBytesField(IntField):
    def __init__(self, name, default):
        super().__init__(name, default)

    def i2m(self, pkt, val):
        return val & 0xFFFFFF  # Keep only 3 bytes

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val).to_bytes(3, "big")

    def getfield(self, pkt, s):
        return s[3:], int.from_bytes(s[:3], "big")

    def i2repr(self, pkt, x):
        return hex(x)


class MTP3(Packet):
    name = "MTP3"
    fields_desc = [
        ByteField("SIO", 0x83),  # Network Indicator, Service Indicator, Priority
        ThreeBytesField("DPC_SPC", 0),  # Destination Point Code + Originating Point Code
        ByteField("Service_Indicator", 3)  # E.g., 3 = SCCP
    ]


class SCCP(Packet):
    name = "SCCP"
    fields_desc = [
        ByteField("message_type", 0x11),
        ByteField("pointer", 0x0A),
        FieldLenField("called_length", None, length_of="called_data", fmt="B"),
        StrLenField("called_data", "", length_from=lambda pkt: pkt.called_length),
        FieldLenField("calling_length", None, length_of="calling_data", fmt="B"),
        StrLenField("calling_data", "", length_from=lambda pkt: pkt.calling_length),
        ByteField("protocol_class", 0x11),
        ByteField("message_handling", 0x00),
        FieldLenField("data_length", None, length_of="user_data", fmt="H"),
        StrLenField("user_data", "", length_from=lambda pkt: pkt.data_length)
    ]


class TCAP(Packet):
    name = "TCAP"
    fields_desc = [
        ByteField("tag", 0x62),  # Begin dialogue tag
        FieldLenField("length", None, length_of="data", fmt="B"),
        StrLenField("data", "", length_from=lambda pkt: pkt.length)
    ]


class MAP(Packet):
    name = "MAP"
    fields_desc = [
        ByteField("invoke_id", 0x02),
        ByteField("opcode_tag", 0x02),
        ByteField("opcode_length", 1),
        ByteField("opcode", 0x04),  # 0x04 = SendRoutingInfo
        ByteField("param_tag", 0x30),
        ByteField("param_length", 0x0A),
        ByteField("imsi_tag", 0x80),
        ByteField("imsi_length", 0x08),
        StrFixedLenField("imsi", b"", length=8)  # RAW bytes, not string
    ]



# Layer bindings
bind_layers(SCTPChunkData, MTP3)
bind_layers(MTP3, SCCP)
bind_layers(SCCP, TCAP)
bind_layers(TCAP, MAP)
