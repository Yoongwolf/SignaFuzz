# tests/test_core.py

import unittest
from unittest.mock import patch, MagicMock
from app.core import Ss7Tool

class TestSs7Tool(unittest.TestCase):
    
    def setUp(self):
        # Valid configuration for testing
        self.valid_config = {
            "imsi": "123456789012345",
            "msisdn": "9876543210",
            "target_ip": "192.168.1.1",
            "target_port": 2905,
            "protocol": "SCTP",
            "ssn": "6",
            "gt": "1234567890"
        }
    
    def test_initialization(self):
        # Test that the tool initializes correctly with valid config
        tool = Ss7Tool(self.valid_config)
        self.assertEqual(tool.imsi, "123456789012345")
        self.assertEqual(tool.msisdn, "9876543210")
        self.assertEqual(tool.target_ip, "192.168.1.1")
        self.assertEqual(tool.target_port, 2905)
        self.assertEqual(tool.protocol, "SCTP")
        self.assertEqual(tool.ssn, "6")
        self.assertEqual(tool.gt, "1234567890")
    
    def test_invalid_imsi(self):
        # Test that invalid IMSI raises ValueError
        invalid_config = self.valid_config.copy()
        invalid_config["imsi"] = "123"  # Too short
        
        with self.assertRaises(ValueError):
            Ss7Tool(invalid_config)
    
    def test_invalid_protocol(self):
        # Test that invalid protocol raises ValueError
        invalid_config = self.valid_config.copy()
        invalid_config["protocol"] = "UDP"  # Unsupported
        
        with self.assertRaises(ValueError):
            Ss7Tool(invalid_config)
    
    @patch('app.core.build_map_send_routing_info')
    @patch('app.core.SCTPClient')
    def test_send_message(self, mock_sctp_client, mock_build_msg):
        # Mock the packet builder and SCTP client
        mock_packet = MagicMock()
        mock_build_msg.return_value = mock_packet
        
        # Mock the SCTP client instance
        mock_client_instance = MagicMock()
        mock_sctp_client.return_value = mock_client_instance
        mock_client_instance.send.return_value = b'mock_response'
        
        # Create and send message
        tool = Ss7Tool(self.valid_config)
        tool.send_message()
        
        # Assert that the message was built with the correct IMSI
        mock_build_msg.assert_called_once_with(self.valid_config["imsi"])
        
        # Assert that the SCTP client was created with the correct parameters
        mock_sctp_client.assert_called_once_with(self.valid_config["target_ip"], self.valid_config["target_port"])
        
        # Assert that connect and send were called
        mock_client_instance.connect.assert_called_once()
        mock_client_instance.send.assert_called_once()
        mock_client_instance.close.assert_called_once()
        
        # Check that the response was stored
        self.assertEqual(tool.response, b'mock_response')

if __name__ == '__main__':
    unittest.main()