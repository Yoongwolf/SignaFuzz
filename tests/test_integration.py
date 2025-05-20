#test/test_Integration.py
import unittest
from unittest.mock import patch
from app.core import SS7Core
from app.response_parser import ResponseParser

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.core = SS7Core(api_key="test_key_123")
        self.target_ip = "127.0.0.1"
        self.target_port = 2905
        self.ssn = 6
        self.gt = "1234567890"
        self.imsi = "123456789012345"
        self.msisdn = "9876543210"
        self.vlr_gt = "9876543210"

    @patch.object(ResponseParser, "parse_response")
    def test_sri_workflow_sctp(self, mock_parse):
        """Test end-to-end SRI message sending and response parsing with SCTP."""
        mock_parse.return_value = {
            "status": "success",
            "invoke_id": 2,
            "opcode": 4,
            "params": {"imsi": self.imsi, "msisdn": self.msisdn}
        }
        response = self.core.send_sri(
            imsi=self.imsi,
            msisdn=self.msisdn,
            target_ip=self.target_ip,
            target_port=self.target_port,
            ssn=self.ssn,
            gt=self.gt,
            protocol="SCTP"
        )
        self.assertEqual(response["status"], "success")
        self.assertIn("params", response)
        self.assertEqual(response["params"]["imsi"], self.imsi)
        self.assertEqual(response["params"]["msisdn"], self.msisdn)

    @patch.object(ResponseParser, "parse_response")
    def test_sri_workflow_tcp(self, mock_parse):
        """Test end-to-end SRI message sending and response parsing with TCP."""
        mock_parse.return_value = {
            "status": "success",
            "invoke_id": 2,
            "opcode": 4,
            "params": {"imsi": self.imsi, "msisdn": self.msisdn}
        }
        response = self.core.send_sri(
            imsi=self.imsi,
            msisdn=self.msisdn,
            target_ip=self.target_ip,
            target_port=self.target_port,
            ssn=self.ssn,
            gt=self.gt,
            protocol="TCP"
        )
        self.assertEqual(response["status"], "success")
        self.assertIn("params", response)
        self.assertEqual(response["params"]["imsi"], self.imsi)
        self.assertEqual(response["params"]["msisdn"], self.msisdn)

    @patch.object(ResponseParser, "parse_response")
    def test_ati_workflow(self, mock_parse):
        """Test end-to-end ATI message sending and response parsing."""
        mock_parse.return_value = {
            "status": "success",
            "invoke_id": 2,
            "opcode": 71,
            "params": {"imsi": self.imsi}
        }
        response = self.core.send_ati(
            imsi=self.imsi,
            target_ip=self.target_ip,
            target_port=self.target_port,
            ssn=self.ssn,
            gt=self.gt,
            protocol="SCTP"
        )
        self.assertEqual(response["status"], "success")
        self.assertIn("params", response)
        self.assertEqual(response["params"]["imsi"], self.imsi)

    @patch.object(ResponseParser, "parse_response")
    def test_ul_workflow(self, mock_parse):
        """Test end-to-end UL message sending and response parsing."""
        mock_parse.return_value = {
            "status": "success",
            "invoke_id": 2,
            "opcode": 2,
            "params": {"imsi": self.imsi, "vlr_gt": self.vlr_gt}
        }
        response = self.core.send_ul(
            imsi=self.imsi,
            vlr_gt=self.vlr_gt,
            target_ip=self.target_ip,
            target_port=self.target_port,
            ssn=self.ssn,
            gt=self.gt,
            protocol="SCTP"
        )
        self.assertEqual(response["status"], "success")
        self.assertIn("params", response)
        self.assertEqual(response["params"]["imsi"], self.imsi)
        self.assertEqual(response["params"]["vlr_gt"], self.vlr_gt)

    @patch.object(ResponseParser, "parse_response")
    def test_psi_workflow(self, mock_parse):
        """Test end-to-end PSI message sending and response parsing."""
        mock_parse.return_value = {
            "status": "success",
            "invoke_id": 2,
            "opcode": 59,
            "params": {"imsi": self.imsi}
        }
        response = self.core.send_psi(
            imsi=self.imsi,
            target_ip=self.target_ip,
            target_port=self.target_port,
            ssn=self.ssn,
            gt=self.gt,
            protocol="SCTP"
        )
        self.assertEqual(response["status"], "success")
        self.assertIn("params", response)
        self.assertEqual(response["params"]["imsi"], self.imsi)

    def test_invalid_api_key(self):
        """Test handling of invalid API key."""
        with self.assertRaises(ValueError):
            SS7Core(api_key="invalid_key")

if __name__ == "__main__":
    unittest.main()