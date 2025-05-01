# utils/encoding/bcd.py
def encode_bcd(number: str) -> bytes:
    """
    Encode a number string into BCD (Binary-Coded Decimal) format.

    Args:
        number: String of digits to encode (may include leading '+')

    Returns:
        BCD-encoded bytes

    Raises:
        ValueError: If input contains non-digits or is empty
    """
    number = number.lstrip('+')
    if not number:
        raise ValueError("Input cannot be empty")
    if not number.isdigit():
        raise ValueError("Input must contain only digits")
    
    if len(number) % 2 != 0:
        number += 'F'
    
    result = bytearray()
    for i in range(0, len(number), 2):
        first = int(number[i])
        second = 0xF if i+1 >= len(number) or number[i+1] == 'F' else int(number[i+1])
        byte = (second << 4) | first  # Swap digits: second in high nibble, first in low
        result.append(byte)
    
    return bytes(result)

def decode_bcd(bcd_data: str) -> str:
    """
    Decode BCD (Binary-Coded Decimal) data to a number string.

    Args:
        bcd_data: Hex string or bytes to decode

    Returns:
        Decoded number string

    Raises:
        ValueError: If input is not valid hex or contains invalid BCD digits
    """
    if isinstance(bcd_data, bytes):
        bcd_data = bcd_data.hex()
    
    if not bcd_data:
        raise ValueError("Input cannot be empty")
    try:
        bytes.fromhex(bcd_data)
    except ValueError:
        raise ValueError("Input must be a valid hex string")
    
    result = []
    for i in range(0, len(bcd_data), 2):
        byte = int(bcd_data[i:i+2], 16)
        first = byte & 0x0F        # Low nibble (first digit)
        second = (byte >> 4) & 0x0F  # High nibble (second digit)
        if first > 9 and first != 0xF:
            raise ValueError(f"Invalid BCD digit: {first}")
        if second > 9 and second != 0xF:
            raise ValueError(f"Invalid BCD digit: {second}")
        if first != 0xF:
            result.append(str(first))
        if second != 0xF:
            result.append(str(second))
    
    decoded = ''.join(result)
    if not decoded:
        raise ValueError("No valid digits decoded")
    return decoded