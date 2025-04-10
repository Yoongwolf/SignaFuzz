import unittest
from app.map_builder import build_map_send_routing_info
from utils.protocols.ss7_layers import MAP

class TestMAPBuilder(unittest.TestCase):

    def test_map_encoding(self):
        imsi = "404550123456789"
        packet = build_map_send_routing_info(imsi)
        self.assertIsInstance(packet, MAP)
        self.assertEqual(packet.imsi_length, 8)
        self.assertEqual(packet.imsi, b'\x04\x40\x55\x10\x32\x54\x76\x98')  # BCD

if __name__ == "__main__":
    unittest.main()
