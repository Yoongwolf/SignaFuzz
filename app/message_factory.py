from dataclasses import dataclass
from typing import Optional
from utils.encoding.bcd import encode_bcd
from utils.validators import validate_imsi, validate_msisdn

@dataclass
class MAPMessage:
    invoke_id: int
    opcode: int
    params: bytes

class MessageFactory:
    @staticmethod
    def create_send_routing_info(imsi: str, msisdn: Optional[str] = None) -> MAPMessage:
        """
        Create a SendRoutingInfo MAP message.

        Args:
            imsi: International Mobile Subscriber Identity
            msisdn: Mobile Station International Subscriber Directory Number (optional)

        Returns:
            MAPMessage object

        Raises:
            ValueError: If IMSI or MSISDN is invalid
        """
        if not validate_imsi(imsi):
            raise ValueError("Invalid IMSI: must be 15 digits")
        if msisdn and not validate_msisdn(msisdn):
            raise ValueError("Invalid MSISDN: must be 10-15 digits")

        imsi_bytes = encode_bcd(imsi)
        params = bytes([0x80, len(imsi_bytes)]) + imsi_bytes
        if msisdn:
            msisdn_bytes = encode_bcd(msisdn)
            params += bytes([0x81, len(msisdn_bytes)]) + msisdn_bytes

        return MAPMessage(
            invoke_id=0x02,
            opcode=0x04,  # SRI opcode
            params=params
        )

    @staticmethod
    def create_any_time_interrogation(imsi: str) -> MAPMessage:
        """
        Create an AnyTimeInterrogation MAP message.

        Args:
            imsi: International Mobile Subscriber Identity

        Returns:
            MAPMessage object

        Raises:
            ValueError: If IMSI is invalid
        """
        if not validate_imsi(imsi):
            raise ValueError("Invalid IMSI: must be 15 digits")

        imsi_bytes = encode_bcd(imsi)
        params = bytes([0x80, len(imsi_bytes)]) + imsi_bytes

        return MAPMessage(
            invoke_id=0x02,
            opcode=0x71,  # ATI opcode
            params=params
        )

    @staticmethod
    def create_update_location(imsi: str, vlr_number: str) -> MAPMessage:
        """
        Create an UpdateLocation MAP message.

        Args:
            imsi: International Mobile Subscriber Identity
            vlr_number: Visitor Location Register number

        Returns:
            MAPMessage object

        Raises:
            ValueError: If IMSI or VLR number is invalid
        """
        if not validate_imsi(imsi):
            raise ValueError("Invalid IMSI: must be 15 digits")
        if not validate_msisdn(vlr_number):  # Using MSISDN validator for VLR
            raise ValueError("Invalid VLR number: must be 10-15 digits")

        imsi_bytes = encode_bcd(imsi)
        vlr_bytes = encode_bcd(vlr_number)
        params = (
            bytes([0x80, len(imsi_bytes)]) + imsi_bytes +
            bytes([0x81, len(vlr_bytes)]) + vlr_bytes
        )

        return MAPMessage(
            invoke_id=0x02,
            opcode=0x02,  # UL opcode
            params=params
        )

    @staticmethod
    def create_provide_subscriber_info(imsi: str) -> MAPMessage:
        """
        Create a ProvideSubscriberInfo MAP message.

        Args:
            imsi: International Mobile Subscriber Identity

        Returns:
            MAPMessage object

        Raises:
            ValueError: If IMSI is invalid
        """
        if not validate_imsi(imsi):
            raise ValueError("Invalid IMSI: must be 15 digits")

        imsi_bytes = encode_bcd(imsi)
        params = bytes([0x80, len(imsi_bytes)]) + imsi_bytes

        return MAPMessage(
            invoke_id=0x02,
            opcode=0x70,  # PSI opcode
            params=params
        )