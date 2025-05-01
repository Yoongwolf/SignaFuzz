#test/TestResponseParser.py
import unittest
from app.response_parser import ResponseParser
from utils.encoding.bcd import encode_bcd

class TestResponseParser(unittest.TestCase):
    def test_parse_simple_response(self):
        """Test parsing a valid SRI response."""
        imsi = "123456789012345"
        msisdn = "9876543210"
        encoded_imsi = encode_bcd(imsi)
        encoded_msisdn = encode_bcd(msisdn)
        response = (
            bytes([0x02, 0x02, 0x02, 0x02, 0x01, 0x04]) +  # Header
            bytes([0x30, 0x11, 0x80, 0x08]) + encoded_imsi +  # IMSI
            bytes([0x81, 0x05]) + encoded_msisdn  # MSISDN
        )
        result = ResponseParser.parse_response(response)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["invoke_id"], 2)
        self.assertEqual(result["opcode"], 0x04)
        self.assertEqual(result["params"]["imsi"], "123456789012345")
        self.assertEqual(result["params"]["msisdn"], "9876543210")

    def test_parse_empty_response(self):
        """Test parsing an empty response."""
        response = b""
        result = ResponseParser.parse_response(response)
        self.assertEqual(result["status"], "no_response")
        self.assertEqual(result["message"], "Empty response")

    def test_parse_short_response(self):
        """Test parsing a response that's too short."""
        response = bytes.fromhex("020202")
        result = ResponseParser.parse_response(response)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["message"], "Response too short")

if __name__ == "__main__":
    unittest.main()