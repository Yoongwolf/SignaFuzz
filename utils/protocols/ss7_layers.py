from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, FieldLenField, FieldListField, StrLenField

class ThreeBytesField(StrLenField):
    """
    Custom Scapy field for 3-byte values (e.g., OPC, DPC).
    """
    def __init__(self, name, default):
        if len(default) != 3:
            raise ValueError(f"{name} must be exactly 3 bytes, got {len(default)} bytes")
        StrLenField.__init__(self, name, default)

class MTP3(Packet):
    """
    MTP3 layer for SS7 protocol.
    """
    name = "MTP3"
    fields_desc = [
        XByteField("sio", 0x00),  # Service Information Octet
        ThreeBytesField("opc", b"\x00\x00\x00"),  # Originating Point Code
        ThreeBytesField("dpc", b"\x00\x00\x00"),  # Destination Point Code
        XByteField("sls", 0x00),  # Signalling Link Selection
    ]

class SCCP(Packet):
    """
    SCCP layer for SS7 protocol (UDT message).
    """
    name = "SCCP"
    fields_desc = [
        XByteField("message_type", 0x09),  # UDT
        XByteField("protocol_class", 0x00),
        XByteField("pointer_called", 0x03),
        XByteField("pointer_calling", 0x00),
        XByteField("pointer_data", 0x00),
        FieldLenField("called_party_len", None, length_of="called_party", fmt="B"),
        StrLenField("called_party", b"", length_from=lambda pkt: pkt.called_party_len),
        FieldLenField("calling_party_len", None, length_of="calling_party", fmt="B"),
        StrLenField("calling_party", b"", length_from=lambda pkt: pkt.calling_party_len),
        FieldLenField("data_len", None, length_of="data", fmt="B"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.data_len),
    ]

    def post_build(self, pkt, pay):
        """
        Adjust SCCP pointers after packet construction.
        """
        if self.pointer_calling == 0:
            self.pointer_calling = 3 + self.called_party_len
        if self.pointer_data == 0:
            self.pointer_data = 3 + self.called_party_len + self.calling_party_len
        return Packet.post_build(self, pkt, pay)

class MAP(Packet):
    """
    MAP layer for SS7 protocol per 3GPP TS 29.002.
    """
    name = "MAP"
    fields_desc = [
        XByteField("invoke_id_tag", 0x02),  # Invoke ID tag
        XByteField("invoke_id_length", 0x01),
        XByteField("invoke_id", 0x02),
        XByteField("opcode_tag", 0x02),  # Operation code tag
        XByteField("opcode_length", 0x01),
        XByteField("opcode", 0x00),  # Operation code (e.g., 0x04 for SendRoutingInfo)
        XByteField("param_tag", 0x30),  # Parameters sequence tag
        FieldLenField("param_length", None, length_of="params", fmt="B"),
        FieldListField(
            "params",
            [],
            StrLenField("", b"", length_from=lambda pkt: pkt.param_length),
            length_from=lambda pkt: pkt.param_length
        ),
    ]

# Bind layers for SS7 stack
bind_layers(SCCP, MAP, data_len=lambda x: x > 0)
bind_layers(MTP3, SCCP)
# Note: SCTP binding requires custom handling in sctp_client.py due to Scapy limitations