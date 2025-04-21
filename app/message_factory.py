# app/message_factory.py

import logging
from scapy.packet import Packet
from utils.encoding.bcd import encode_bcd
from utils.protocols.ss7_layers import MAP

class MessageFactory:
    """
    Factory for creating different types of MAP messages.
    """
    
    @staticmethod
    def create_send_routing_info(imsi: str, msisdn: str = None) -> Packet:
        """
        Create a SendRoutingInfo (SRI) MAP message.
        
        Args:
            imsi: International Mobile Subscriber Identity
            msisdn: Mobile Station ISDN number (optional)
            
        Returns:
            Scapy packet with MAP layer
        """
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
        
        logging.debug(f"Created SendRoutingInfo message for IMSI: {imsi}")
        return map_layer
    
    @staticmethod
    def create_any_time_interrogation(imsi: str) -> Packet:
        """
        Create an AnyTimeInterrogation (ATI) MAP message.
        
        Args:
            imsi: International Mobile Subscriber Identity
            
        Returns:
            Scapy packet with MAP layer
        """
        bcd_imsi = encode_bcd(imsi)
        
        map_layer = MAP(
            invoke_id=0x02,
            opcode_tag=0x02,
            opcode_length=1,
            opcode=0x71,  # AnyTimeInterrogation
            param_tag=0x30,
            param_length=2 + 2 + len(bcd_imsi),  # imsi_tag + length + bcd_imsi
            imsi_tag=0x80,
            imsi_length=len(bcd_imsi),
            imsi=bcd_imsi
        )
        
        logging.debug(f"Created AnyTimeInterrogation message for IMSI: {imsi}")
        return map_layer
    
    @staticmethod
    def create_update_location(imsi: str, vlr_number: str) -> Packet:
        """
        Create an UpdateLocation MAP message.
        
        Args:
            imsi: International Mobile Subscriber Identity
            vlr_number: VLR number
            
        Returns:
            Scapy packet with MAP layer
        """
        bcd_imsi = encode_bcd(imsi)
        bcd_vlr = encode_bcd(vlr_number)
        
        # UpdateLocation has different parameters
        map_layer = MAP(
            invoke_id=0x02,
            opcode_tag=0x02,
            opcode_length=1,
            opcode=0x02,  # UpdateLocation
            param_tag=0x30,
            param_length=2 + 2 + len(bcd_imsi) + 2 + 2 + len(bcd_vlr),
            imsi_tag=0x80,
            imsi_length=len(bcd_imsi),
            imsi=bcd_imsi,
            # Additional fields for UpdateLocation
            vlr_tag=0x81,
            vlr_length=len(bcd_vlr),
            vlr_number=bcd_vlr
        )
        
        logging.debug(f"Created UpdateLocation message for IMSI: {imsi}, VLR: {vlr_number}")
        return map_layer