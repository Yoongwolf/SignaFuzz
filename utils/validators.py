# utils/validators.py
import ipaddress
import re

def validate_imsi(imsi: str) -> bool:
    """
    Validate IMSI: must be 15 digits.
    """
    return bool(imsi and re.match(r'^\d{15}$', imsi))

def validate_msisdn(msisdn: str) -> bool:
    """
    Validate MSISDN: must be 10–15 digits, optional + prefix.
    """
    return bool(msisdn and re.match(r'^\+?\d{10,15}$', msisdn))

def validate_gt(gt: str) -> bool:
    """
    Validate Global Title: must be 10–15 digits.
    """
    return bool(gt and re.match(r'^\d{10,15}$', gt))

def validate_ssn(ssn: int) -> bool:
    """
    Validate SSN: must be integer 0–254.
    """
    try:
        return 0 <= int(ssn) <= 254
    except (ValueError, TypeError):
        return False

def validate_ip(ip: str) -> bool:
    """
    Validate IP: must be a valid IPv4 address.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: int) -> bool:
    """
    Validate port: must be integer 1–65535.
    """
    try:
        return 1 <= int(port) <= 65535
    except (ValueError, TypeError):
        return False

def validate_protocol(protocol: str) -> bool:
    """
    Validate protocol: must be SCTP or TCP.
    """
    return protocol.upper() in ["SCTP", "TCP"]