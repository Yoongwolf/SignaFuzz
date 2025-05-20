#test/TestMessageFactory.py
import unittest
from app.message_factory import MessageFactory
from utils.protocols.ss7_layers import SCCP_UDT, TCAP_Invoke

class TestMessageFactory(unittest.TestCase):
    def setUp(self):
        self.factory = MessageFactory()

    def test_create_send_routing_info(self):
        packet = self.factory.create_sri_message(
            imsi="123456789012345",
            msisdn="9876543210",
            gt="1234567890",
            ssn=6
        )
        sccp = SCCP_UDT(packet)
        self.assertTrue(sccp.haslayer(TCAP_Invoke))
        self.assertEqual(sccp[TCAP_Invoke].opcode, 4)

    def test_create_any_time_interrogation(self):
        packet = self.factory.create_ati_message(
            imsi="123456789012345",
            gt="1234567890",
            ssn=6
        )
        sccp = SCCP_UDT(packet)
        self.assertTrue(sccp.haslayer(TCAP_Invoke))
        self.assertEqual(sccp[TCAP_Invoke].opcode, 71)

    def test_create_update_location(self):
        packet = self.factory.create_ul_message(
            imsi="123456789012345",
            vlr_gt="9876543210",
            gt="1234567890",
            ssn=6
        )
        sccp = SCCP_UDT(packet)
        self.assertTrue(sccp.haslayer(TCAP_Invoke))
        self.assertEqual(sccp[TCAP_Invoke].opcode, 2)

    def test_create_provide_subscriber_info(self):
        packet = self.factory.create_psi_message(
            imsi="123456789012345",
            gt="1234567890",
            ssn=6
        )
        sccp = SCCP_UDT(packet)
        self.assertTrue(sccp.haslayer(TCAP_Invoke))
        self.assertEqual(sccp[TCAP_Invoke].opcode, 59)

if __name__ == "__main__":
    unittest.main()