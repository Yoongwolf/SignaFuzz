#app/message_factory.py
from scapy.all import raw
from utils.protocols.ss7_layers import SCCP_UDT, TCAP_Invoke, MAP_SRI, MAP_ATI, MAP_UL, MAP_PSI, set_map_fields
from utils.encoding.bcd import encode_bcd

class MessageFactory:
    @staticmethod
    def create_sri_message(imsi: str, msisdn: str, gt: str, ssn: int) -> bytes:
        map_sri = set_map_fields(MAP_SRI(), imsi=imsi, msisdn=msisdn)
        tcap = TCAP_Invoke(invoke_id=2, opcode=4)
        tcap_data = raw(tcap / map_sri)
        called_party = encode_bcd(gt)
        calling_party = encode_bcd("2143658709")
        sccp = SCCP_UDT(
            msg_type=0x09,
            protocol_class=0x00,
            pointer1=3,
            pointer2=5 + len(called_party),
            pointer3=7 + len(called_party) + len(calling_party),
            called_len=len(called_party),
            calling_len=len(calling_party),
            data_len=len(tcap_data),
            called_party=called_party,
            calling_party=calling_party,
            data=tcap_data
        )
        return raw(sccp)

    @staticmethod
    def create_ati_message(imsi: str, gt: str, ssn: int) -> bytes:
        map_ati = set_map_fields(MAP_ATI(), imsi=imsi)
        tcap = TCAP_Invoke(invoke_id=2, opcode=71)
        tcap_data = raw(tcap / map_ati)
        called_party = encode_bcd(gt)
        calling_party = encode_bcd("2143658709")
        sccp = SCCP_UDT(
            msg_type=0x09,
            protocol_class=0x00,
            pointer1=3,
            pointer2=5 + len(called_party),
            pointer3=7 + len(called_party) + len(calling_party),
            called_len=len(called_party),
            calling_len=len(calling_party),
            data_len=len(tcap_data),
            called_party=called_party,
            calling_party=calling_party,
            data=tcap_data
        )
        return raw(sccp)

    @staticmethod
    def create_ul_message(imsi: str, vlr_gt: str, gt: str, ssn: int) -> bytes:
        map_ul = set_map_fields(MAP_UL(), imsi=imsi, vlr_gt=vlr_gt)
        tcap = TCAP_Invoke(invoke_id=2, opcode=2)
        tcap_data = raw(tcap / map_ul)
        called_party = encode_bcd(gt)
        calling_party = encode_bcd("2143658709")
        sccp = SCCP_UDT(
            msg_type=0x09,
            protocol_class=0x00,
            pointer1=3,
            pointer2=5 + len(called_party),
            pointer3=7 + len(called_party) + len(calling_party),
            called_len=len(called_party),
            calling_len=len(calling_party),
            data_len=len(tcap_data),
            called_party=called_party,
            calling_party=calling_party,
            data=tcap_data
        )
        return raw(sccp)

    @staticmethod
    def create_psi_message(imsi: str, gt: str, ssn: int) -> bytes:
        map_psi = set_map_fields(MAP_PSI(), imsi=imsi)
        tcap = TCAP_Invoke(invoke_id=2, opcode=59)
        tcap_data = raw(tcap / map_psi)
        called_party = encode_bcd(gt)
        calling_party = encode_bcd("2143658709")
        sccp = SCCP_UDT(
            msg_type=0x09,
            protocol_class=0x00,
            pointer1=3,
            pointer2=5 + len(called_party),
            pointer3=7 + len(called_party) + len(calling_party),
            called_len=len(called_party),
            calling_len=len(calling_party),
            data_len=len(tcap_data),
            called_party=called_party,
            calling_party=calling_party,
            data=tcap_data
        )
        return raw(sccp)