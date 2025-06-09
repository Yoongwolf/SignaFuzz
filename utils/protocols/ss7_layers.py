# utils/protocols/ss7_layers.py
from scapy.all import Packet, ByteField, ShortField, StrLenField
from scapy.packet import bind_layers

class SCCP_UDT(Packet):
    name = "SCCP_UDT"
    fields_desc = [
        ByteField("msg_type", 0x09),
        ByteField("protocol_class", 0x00),
        ByteField("pointer1", 0x03),
        ByteField("pointer2", 0x00),
        ByteField("pointer3", 0x00),
        ShortField("called_len", 0),
        ShortField("calling_len", 0),
        ShortField("data_len", 0),
        StrLenField("called_party", b"", length_from=lambda pkt: pkt.called_len),
        StrLenField("calling_party", b"", length_from=lambda pkt: pkt.calling_len),
        StrLenField("data", b"", length_from=lambda pkt: pkt.data_len)
    ]

    def extract_padding(self, s):
        return self.data, s

class TCAP_Invoke(Packet):
    name = "TCAP_Invoke"
    fields_desc = [
        ByteField("tag", 0x02),
        ByteField("component_len", None),
        ByteField("invoke_tag", 0x0C),
        ByteField("invoke_len", None),
        ByteField("invoke_id", 0x02),
        ByteField("opcode_tag", 0x02),
        ByteField("opcode_len", 0x01),
        ByteField("opcode", 0x04)
    ]

    def post_build(self, pkt, pay):
        if self.component_len is None:
            invoke_len = 4 + len(pay)  # invoke_id (1) + opcode_tag (1) + opcode_len (1) + opcode (1)
            component_len = invoke_len  # Exclude tag
            pkt = pkt[:1] + bytes([component_len]) + pkt[2:3] + bytes([invoke_len]) + pkt[4:] + pay
        return pkt

class TCAP_ReturnResultLast(Packet):
    name = "TCAP_ReturnResultLast"
    fields_desc = [
        ByteField("tag", 0x04),
        ByteField("component_len", None),
        ByteField("invoke_id_tag", 0x02),
        ByteField("invoke_id_len", 0x01),
        ByteField("invoke_id", 0x02),
        ByteField("sequence_tag", 0x30),
        ByteField("sequence_len", None),
        ByteField("opcode_tag", 0x02),
        ByteField("opcode_len", 0x01),
        ByteField("opcode", 0x04)
    ]

    def post_build(self, pkt, pay):
        if self.sequence_len is None:
            sequence_len = 3 + len(pay)  # opcode_tag (1) + opcode_len (1) + opcode (1) + payload
            component_len = 5 + sequence_len  # invoke_id_tag (1) + invoke_id_len (1) + invoke_id (1) + sequence_tag (1) + sequence_len (1)
            pkt = pkt[:1] + bytes([component_len]) + pkt[2:6] + bytes([sequence_len]) + pkt[7:] + pay
        return pkt

class MAP_SRI(Packet):
    name = "MAP_SRI"
    fields_desc = [
        ByteField("tag", 0x04),
        ByteField("len", None),
        StrLenField("imsi", b"", length_from=lambda pkt: 15),  # 15 bytes
        StrLenField("msisdn", b"", length_from=lambda pkt: 10)  # 10 bytes
    ]

    def post_build(self, pkt, pay):
        if self.len is None:
            total_len = len(pkt[2:]) + len(pay)
            pkt = pkt[:1] + bytes([total_len]) + pkt[2:] + pay
        return pkt

class MAP_ATI(Packet):
    name = "MAP_ATI"
    fields_desc = [
        ByteField("tag", 0x47),
        ByteField("len", None),
        StrLenField("imsi", b"", length_from=lambda pkt: 15)
    ]

    def post_build(self, pkt, pay):
        if self.len is None:
            total_len = len(pkt[2:]) + len(pay)
            pkt = pkt[:1] + bytes([total_len]) + pkt[2:] + pay
        return pkt

class MAP_UL(Packet):
    name = "MAP_UL"
    fields_desc = [
        ByteField("tag", 0x02),
        ByteField("len", None),
        StrLenField("imsi", b"", length_from=lambda pkt: 15),
        StrLenField("vlr_gt", b"", length_from=lambda pkt: 10)
    ]

    def post_build(self, pkt, pay):
        if self.len is None:
            total_len = len(pkt[2:]) + len(pay)
            pkt = pkt[:1] + bytes([total_len]) + pkt[2:] + pay
        return pkt

class MAP_PSI(Packet):
    name = "MAP_PSI"
    fields_desc = [
        ByteField("tag", 0x46),
        ByteField("len", None),
        StrLenField("imsi", b"", length_from=lambda pkt: 15)
    ]

    def post_build(self, pkt, pay):
        if self.len is None:
            total_len = len(pkt[2:]) + len(pay)
            pkt = pkt[:1] + bytes([total_len]) + pkt[2:] + pay
        return pkt

def set_map_fields(map_packet, **kwargs):
    for field, value in kwargs.items():
        if hasattr(map_packet, field):
            encoded_value = value.encode('utf-8') if isinstance(value, str) else value
            setattr(map_packet, field, encoded_value)
    total_len = sum(len(getattr(map_packet, f.name)) for f in map_packet.fields_desc if f.name not in ["tag", "len"])
    map_packet.len = total_len
    return map_packet

# Bind layers based on opcode
bind_layers(SCCP_UDT, TCAP_Invoke)
bind_layers(TCAP_Invoke, MAP_SRI, opcode=4)
bind_layers(TCAP_Invoke, MAP_ATI, opcode=71)
bind_layers(TCAP_Invoke, MAP_UL, opcode=2)
bind_layers(TCAP_Invoke, MAP_PSI, opcode=59)
bind_layers(TCAP_ReturnResultLast, MAP_SRI, opcode=4)
bind_layers(TCAP_ReturnResultLast, MAP_ATI, opcode=71)
bind_layers(TCAP_ReturnResultLast, MAP_UL, opcode=2)
bind_layers(TCAP_ReturnResultLast, MAP_PSI, opcode=59)