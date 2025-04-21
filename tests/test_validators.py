# tests/test_validators.py

import unittest
from utils.validators import validate_imsi, validate_msisdn, validate_gt, validate_ssn

class TestValidators(unittest.TestCase):
    
    def test_validate_imsi(self):
        # Valid IMSI
        self.assertTrue(validate_imsi("123456789012345"))
        
        # Invalid IMSI - too short
        self.assertFalse(validate_imsi("12345678901234"))
        
        # Invalid IMSI - too long
        self.assertFalse(validate_imsi("1234567890123456"))
        
        # Invalid IMSI - non-digits
        self.assertFalse(validate_imsi("12345678901234X"))
    
    def test_validate_msisdn(self):
        # Valid MSISDN
        self.assertTrue(validate_msisdn("+919876543210"))
        self.assertTrue(validate_msisdn("919876543210"))
        self.assertTrue(validate_msisdn("9876543210"))
        
        # Invalid MSISDN - too short
        self.assertFalse(validate_msisdn("+91"))
        
        # Invalid MSISDN - non-digits after plus
        self.assertFalse(validate_msisdn("+91X987654321"))
    
    def test_validate_gt(self):
        # Valid GT
        self.assertTrue(validate_gt("1234567890"))
        self.assertTrue(validate_gt("123456789012345"))
        
        # Invalid GT - non-digits
        self.assertFalse(validate_gt("123456X890"))
        
        # Invalid GT - too short
        self.assertFalse(validate_gt("123456789"))
    
    def test_validate_ssn(self):
        # Valid SSN
        self.assertTrue(validate_ssn("0"))
        self.assertTrue(validate_ssn("6"))
        self.assertTrue(validate_ssn("254"))
        
        # Invalid SSN - negative
        self.assertFalse(validate_ssn("-1"))
        
        # Invalid SSN - too large
        self.assertFalse(validate_ssn("255"))
        
        # Invalid SSN - non-digits
        self.assertFalse(validate_ssn("abc"))

if __name__ == '__main__':
    unittest.main()