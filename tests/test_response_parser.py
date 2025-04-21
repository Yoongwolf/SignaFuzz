# tests/test_response_parser.py

import unittest
from app.response_parser import ResponseParser

class TestResponseParser(unittest.TestCase):
    
    def test_parse_empty_response(self):
        # Test handling of empty response
        result = ResponseParser.parse_response(b'')
        self.assertEqual(result["status"], "empty")
    
    def test_parse_simple_response(self):
        # Test parsing of a simple response
        response = b'\x01\x02\x03\x04\x05'
        result = ResponseParser.parse_response(response)
        
        self.assertEqual(result["status"], "received")
        self.assertEqual(result["length"], 5)
        self.assertEqual(result["raw_hex"], "0102030405")
    
    def test_parse_tcap_result(self):
        # Test parsing of a TCAP result response
        # Creating a mock TCAP response with result tag at position 5
        response = b'\x01\x02\x03\x04\x05\xA2\x07\x08\x00\x0A\x0B\x0C'
        result = ResponseParser.parse_response(response)
        
        self.assertEqual(result["type"], "TCAP_RESULT")
        self.assertEqual(result["operation_status"], "success")
    
    def test_format_empty_response(self):
        # Test formatting of an empty response
        parsed = {"status": "empty"}
        formatted = ResponseParser.format_response(parsed)
        self.assertIn("No response received", formatted)
    
    def test_format_error_response(self):
        # Test formatting of an error response
        parsed = {"status": "error", "error": "Test error"}
        formatted = ResponseParser.format_response(parsed)
        self.assertIn("Error parsing response", formatted)
        self.assertIn("Test error", formatted)
    
    def test_format_success_response(self):
        # Test formatting of a successful response
        parsed = {
            "status": "received",
            "length": 10,
            "raw_hex": "0102030405060708090A",
            "type": "TCAP_RESULT",
            "operation_status": "success"
        }
        formatted = ResponseParser.format_response(parsed)
        
        self.assertIn("Response received", formatted)
        self.assertIn("Size: 10 bytes", formatted)
        self.assertIn("0102030405060708090A", formatted)
        self.assertIn("TCAP_RESULT", formatted)
        self.assertIn("SUCCESS", formatted)

if __name__ == '__main__':
    unittest.main()