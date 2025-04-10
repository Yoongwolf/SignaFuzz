import unittest
from utils.encoding.bcd import encode_bcd

class TestBCDEncoding(unittest.TestCase):

    def test_even_digits(self):
        self.assertEqual(encode_bcd("12345678"), b'\x21\x43\x65\x87')

    def test_odd_digits(self):
        self.assertEqual(encode_bcd("1234567"), b'\x21\x43\x65\xF7')

    def test_all_zeroes(self):
        self.assertEqual(encode_bcd("000000"), b'\x00\x00\x00')

    def test_max_length(self):
        self.assertEqual(encode_bcd("123456789012345"), b'\x21\x43\x65\x87\x09\x21\x43\xF5')

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            encode_bcd("12A456")

if __name__ == '__main__':
    unittest.main()
