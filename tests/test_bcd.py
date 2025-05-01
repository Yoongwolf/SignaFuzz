#test/test_bcd.py
import unittest
from utils.encoding.bcd import encode_bcd, decode_bcd

class TestBCDEncoding(unittest.TestCase):
    def test_encode_bcd(self):
        self.assertEqual(encode_bcd("123456789012345").hex(), "21436587092143f5")
        self.assertEqual(encode_bcd("9876543210").hex(), "8967452301")

    def test_decode_bcd(self):
        self.assertEqual(decode_bcd("21436587092143f5"), "123456789012345")
        self.assertEqual(decode_bcd("8967452301"), "9876543210")