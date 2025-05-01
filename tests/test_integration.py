#test/test_Integration.py
import unittest
import subprocess
import time
from app.core import Ss7Tool
from app.response_parser import ResponseParser

class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Start the mock SS7 server."""
        cls.server_process = subprocess.Popen(
            ["python", "tests/mock_ss7_server.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(3)  # Increased delay for server startup

    @classmethod
    def tearDownClass(cls):
        """Stop the mock SS7 server."""
        cls.server_process.terminate()
        cls.server_process.wait()

    def test_sri_workflow(self):
        """Test end-to-end SRI message sending and response parsing."""
        config = {
            "imsi": "123456789012345",
            "msisdn": "9876543210",
            "target_ip": "127.0.0.1",
            "target_port": 2905,
            "protocol": "SCTP",
            "ssn": 6,
            "gt": "1234567890"
        }
        tool = Ss7Tool(config)
        for _ in range(3):  # Retry up to 3 times
            tool.send_message("sri")
            if tool.response:
                parsed_response = ResponseParser.parse_response(tool.response)
                self.assertEqual(parsed_response["status"], "success")
                self.assertEqual(parsed_response["opcode"], 0x04)
                self.assertEqual(parsed_response["params"]["imsi"], "123456789012345")
                self.assertEqual(parsed_response["params"]["msisdn"], "9876543210")
                return
            time.sleep(1)  # Wait before retry
        self.fail("No response received from server after retries")

if __name__ == "__main__":
    unittest.main()