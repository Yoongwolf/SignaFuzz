import unittest
from app.response_parser import ResponseParser

class TestResponseParser(unittest.TestCase):
    def test_parse_empty_response(self):
        """Test parsing an empty response."""
        result = ResponseParser.parse_response(b"")
        self.assertEqual(result["status"], "no_response")
        self.assertEqual(result["message"], "No response received")

    def test_parse_short_response(self):
        """Test parsing a too-short response."""
        result = ResponseParser.parse_response(b"\x00\x01\x02")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["message"], "Response too short")

    def test_parse_simple_response(self):
        """Test parsing a valid SRI response."""
        response = bytes.fromhex("0202020201043011800821436587092143F581058967452301")
        result = ResponseParser.parse_response(response)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["invoke_id"], 0x02)
        self.assertEqual(result["opcode"], 0x04)
        self.assertEqual(result["params"]["imsi"], "123456789012345")
        self.assertEqual(result["params"]["msisdn"], "9876543210")

    def test_format_empty_response(self):
        """Test formatting an empty response."""
        parsed = {"status": "no_response", "message": "No response received"}
        formatted = ResponseParser.format_response(parsed)
        self.assertEqual(formatted, "⚠️ No response received")

    def test_format_error_response(self):
        """Test formatting an error response."""
        parsed = {"status": "error", "message": "Invalid response"}
        formatted = ResponseParser.format_response(parsed)
        self.assertEqual(formatted, "⚠️ Response Error: Invalid response")

    def test_format_success_response(self):
        """Test formatting a successful response."""
        parsed = {
            "status": "success",
            "invoke_id": 2,
            "opcode": 0x04,
            "params": {"imsi": "123456789012345", "msisdn": "9876543210"}
        }
        formatted = ResponseParser.format_response(parsed)
        self.assertIn("Parsed MAP Response", formatted)
        self.assertIn("Invoke ID: 2", formatted)
        self.assertIn("Opcode: SendRoutingInfo (0x04)", formatted)
        self.assertIn("Imsi: 123456789012345", formatted)
        self.assertIn("Msisdn: 9876543210", formatted)

if __name__ == "__main__":
    unittest.main()