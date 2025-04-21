# tests/test_message_factory.py

import unittest
from app.message_factory import MessageFactory

class TestMessageFactory(unittest.TestCase):
    
    def test_create_send_routing_info(self):
        # Create a SendRoutingInfo message
        imsi = "123456789012345"
        message = MessageFactory.create_send_routing_info(imsi)
        
        # Check that the message has the correct fields
        self.assertEqual(message.invoke_id, 0x02)
        self.assertEqual(message.opcode, 0x04)  # SendRoutingInfo opcode
        self.assertEqual(message.imsi_tag, 0x80)
        
        # Check that IMSI is encoded in the message
        # Note: We're not checking the exact BCD encoding here
        self.assertIsNotNone(message.imsi)
    
    def test_create_any_time_interrogation(self):
        # Create an AnyTimeInterrogation message
        imsi = "123456789012345"
        message = MessageFactory.create_any_time_interrogation(imsi)
        
        # Check that the message has the correct fields
        self.assertEqual(message.invoke_id, 0x02)
        self.assertEqual(message.opcode, 0x71)  # AnyTimeInterrogation opcode
        self.assertEqual(message.imsi_tag, 0x80)
        
        # Check that IMSI is encoded in the message
        self.assertIsNotNone(message.imsi)
    
    def test_create_update_location(self):
        # Create an UpdateLocation message
        imsi = "123456789012345"
        vlr_number = "1234567890"
        message = MessageFactory.create_update_location(imsi, vlr_number)
        
        # Check that the message has the correct fields
        self.assertEqual(message.invoke_id, 0x02)
        self.assertEqual(message.opcode, 0x02)  # UpdateLocation opcode
        self.assertEqual(message.imsi_tag, 0x80)
        self.assertEqual(message.vlr_tag, 0x81)
        
        # Check that IMSI and VLR are encoded in the message
        self.assertIsNotNone(message.imsi)
        self.assertIsNotNone(message.vlr_number)

if __name__ == '__main__':
    unittest.main()