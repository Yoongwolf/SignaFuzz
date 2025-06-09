#test/test_Integration.py
import sys
import os
import unittest
from unittest.mock import patch
from app.core import SS7Core

sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.core = SS7Core(api_key="test_key_123")
        self.target_ip = "127.0.0.1"
        self.target_port = 2905  # SCTP
        self.target_port_tcp = 2906  # TCP
        self.ssn = 6
        self.gt = "1234567890"
        self.imsi = "123456789012345"
        self.msisdn = "9876543210"
        self.vlr_gt = "9876543210"

    @patch('utils.network.sctp_client.SCTPClient.send_packet')
    def test_sri_workflow_sctp(self, mock_sctp):
        """Test end-to-end SRI message sending and response parsing with SCTP."""
        mock_sctp.return_value = b"\x04\x0B\x02\x01\x02\x30\x06\x02\x01\x04\x04\x00"
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

    @patch('utils.network.tcp_client.TCPClient.send_packet')
    def test_sri_workflow_tcp(self, mock_tcp):
        """Test end-to-end SRI message sending and response parsing with TCP."""
        mock_tcp.return_value = b"\x04\x0B\x02\x01\x02\x30\x06\x02\x01\x04\x04\x00"
        response = self.core.send_sri(
            imsi=self.imsi,
            msisdn=self.msisdn,
            target_ip=self.target_ip,
            target_port=self.target_port_tcp,
            ssn=self.ssn,
            gt=self.gt,
            protocol="TCP"
        )
        self.assertEqual(response["status"], "success")
        self.assertIn("params", response)
        self.assertEqual(response["params"]["imsi"], self.imsi)
        self.assertEqual(response["params"]["msisdn"], self.msisdn)

    @patch('utils.network.sctp_client.SCTPClient.send_packet')
    def test_ati_workflow(self, mock_sctp):
        """Test end-to-end ATI message sending and response parsing."""
        mock_sctp.return_value = b"\x04\x0B\x02\x01\x02\x30\x06\x02\x01\x47\x04\x00"
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

    @patch('utils.network.sctp_client.SCTPClient.send_packet')
    def test_ul_workflow(self, mock_sctp):
        """Test end-to-end UL message sending and response parsing."""
        mock_sctp.return_value = b"\x04\x0B\x02\x01\x02\x30\x06\x02\x01\x02\x04\x00"
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

    @patch('utils.network.sctp_client.SCTPClient.send_packet')
    def test_psi_workflow(self, mock_sctp):
        """Test end-to-end PSI message sending and response parsing."""
        mock_sctp.return_value = b"\x04\x0B\x02\x01\x02\x30\x06\x02\x01\x46\x04\x00"
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