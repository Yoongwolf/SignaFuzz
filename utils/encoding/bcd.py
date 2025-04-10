# utils/encoding/bcd.py

def encode_bcd(number_str: str) -> bytes:
    if not number_str.isdigit():
        raise ValueError("Input must contain digits only.")

    digits = list(number_str)

    if len(digits) % 2 != 0:
        digits.append('F')  # BCD padding for odd-length

    bcd = bytearray()

    for i in range(0, len(digits), 2):
        low_nibble = int(digits[i + 1], 16) if digits[i + 1] != 'F' else 0xF
        high_nibble = int(digits[i], 16)
        bcd_byte = (low_nibble << 4) | high_nibble
        bcd.append(bcd_byte)

    return bytes(bcd)

