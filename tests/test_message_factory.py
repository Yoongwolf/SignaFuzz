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
        from scapy.all import hexdump
        print("SRI Packet hexdump:")
        hexdump(packet)
        print("Has TCAP_Invoke:", sccp.haslayer(TCAP_Invoke))
        print("Packet layers:", [layer.__class__.__name__ for layer in sccp if layer])
        print("Data field hex:", sccp.data.hex() if sccp.data else "None")
        try:
            tcap = TCAP_Invoke(sccp.data)
            print("Manual TCAP_Invoke parse:")
            tcap.show()
        except Exception as e:
            print("Manual parse error:", str(e))
        self.assertTrue(sccp.haslayer(TCAP_Invoke))
        self.assertEqual(sccp[TCAP_Invoke].opcode, 4)

    def test_create_any_time_interrogation(self):
        packet = self.factory.create_ati_message(
            imsi="123456789012345",
            gt="1234567890",
            ssn=6
        )
        sccp = SCCP_UDT(packet)
        from scapy.all import hexdump
        print("ATI Packet hexdump:")
        hexdump(packet)
        print("Has TCAP_Invoke:", sccp.haslayer(TCAP_Invoke))
        print("Packet layers:", [layer.__class__.__name__ for layer in sccp if layer])
        print("Data field hex:", sccp.data.hex() if sccp.data else "None")
        try:
            tcap = TCAP_Invoke(sccp.data)
            print("Manual TCAP_Invoke parse:")
            tcap.show()
        except Exception as e:
            print("Manual parse error:", str(e))
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
        from scapy.all import hexdump
        print("UL Packet hexdump:")
        hexdump(packet)
        print("Has TCAP_Invoke:", sccp.haslayer(TCAP_Invoke))
        print("Packet layers:", [layer.__class__.__name__ for layer in sccp if layer])
        print("Data field hex:", sccp.data.hex() if sccp.data else "None")
        try:
            tcap = TCAP_Invoke(sccp.data)
            print("Manual TCAP_Invoke parse:")
            tcap.show()
        except Exception as e:
            print("Manual parse error:", str(e))
        self.assertTrue(sccp.haslayer(TCAP_Invoke))
        self.assertEqual(sccp[TCAP_Invoke].opcode, 2)

    def test_create_provide_subscriber_info(self):
        packet = self.factory.create_psi_message(
            imsi="123456789012345",
            gt="1234567890",
            ssn=6
        )
        sccp = SCCP_UDT(packet)
        from scapy.all import hexdump
        print("PSI Packet hexdump:")
        hexdump(packet)
        print("Has TCAP_Invoke:", sccp.haslayer(TCAP_Invoke))
        print("Packet layers:", [layer.__class__.__name__ for layer in sccp if layer])
        print("Data field hex:", sccp.data.hex() if sccp.data else "None")
        try:
            tcap = TCAP_Invoke(sccp.data)
            print("Manual TCAP_Invoke parse:")
            tcap.show()
        except Exception as e:
            print("Manual parse error:", str(e))
        self.assertTrue(sccp.haslayer(TCAP_Invoke))
        self.assertEqual(sccp[TCAP_Invoke].opcode, 59)

if __name__ == "__main__":
    unittest.main()