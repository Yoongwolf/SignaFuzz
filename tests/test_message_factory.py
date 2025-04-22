import unittest
from app.message_factory import MessageFactory
from utils.encoding.bcd import encode_bcd

class TestMessageFactory(unittest.TestCase):
    def test_create_send_routing_info(self):
        """Test SendRoutingInfo message creation."""
        imsi = "123456789012345"
        msisdn = "9876543210"
        packet = MessageFactory.create_send_routing_info(imsi, msisdn)
        self.assertEqual(packet.invoke_id, 0x02)
        self.assertEqual(packet.opcode, 0x04)  # SRI opcode
        expected_params = (
            bytes([0x80, 8]) + encode_bcd(imsi) +
            bytes([0x81, 5]) + encode_bcd(msisdn)
        )
        self.assertEqual(packet.params, expected_params)
        
        # Test without MSISDN
        packet = MessageFactory.create_send_routing_info(imsi)
        self.assertEqual(packet.params, bytes([0x80, 8]) + encode_bcd(imsi))

        # Test invalid IMSI
        with self.assertRaises(ValueError):
            MessageFactory.create_send_routing_info("123")

    def test_create_any_time_interrogation(self):
        """Test AnyTimeInterrogation message creation."""
        imsi = "123456789012345"
        packet = MessageFactory.create_any_time_interrogation(imsi)
        self.assertEqual(packet.invoke_id, 0x02)
        self.assertEqual(packet.opcode, 0x71)  # ATI opcode
        self.assertEqual(packet.params, bytes([0x80, 8]) + encode_bcd(imsi))

        # Test invalid IMSI
        with self.assertRaises(ValueError):
            MessageFactory.create_any_time_interrogation("123")

    def test_create_update_location(self):
        """Test UpdateLocation message creation."""
        imsi = "123456789012345"
        vlr_number = "9876543210"
        packet = MessageFactory.create_update_location(imsi, vlr_number)
        self.assertEqual(packet.invoke_id, 0x02)
        self.assertEqual(packet.opcode, 0x02)  # UL opcode
        expected_params = (
            bytes([0x80, 8]) + encode_bcd(imsi) +
            bytes([0x81, 5]) + encode_bcd(vlr_number)
        )
        self.assertEqual(packet.params, expected_params)

        # Test invalid VLR
        with self.assertRaises(ValueError):
            MessageFactory.create_update_location(imsi, "123")

    def test_create_provide_subscriber_info(self):
        """Test ProvideSubscriberInfo message creation."""
        imsi = "123456789012345"
        packet = MessageFactory.create_provide_subscriber_info(imsi)
        self.assertEqual(packet.invoke_id, 0x02)
        self.assertEqual(packet.opcode, 0x70)  # PSI opcode
        self.assertEqual(packet.params, bytes([0x80, 8]) + encode_bcd(imsi))

        # Test invalid IMSI
        with self.assertRaises(ValueError):
            MessageFactory.create_provide_subscriber_info("123")

if __name__ == "__main__":
    unittest.main()