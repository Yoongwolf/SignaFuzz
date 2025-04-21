# utils/validators.py

import re

def validate_imsi(imsi: str) -> bool:
    return bool(re.fullmatch(r"\d{15}", imsi))

def validate_msisdn(msisdn: str) -> bool:
    return bool(re.fullmatch(r"\+?\d{10,15}", msisdn))

def validate_gt(gt: str) -> bool:
    return bool(re.fullmatch(r"\d{10,15}", gt))

def validate_ssn(ssn: str) -> bool:
    return ssn.isdigit() and 0 <= int(ssn) <= 254
