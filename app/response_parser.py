#app/response_parser.py
import sqlite3
import logging
from scapy.all import raw
from utils.protocols.ss7_layers import SCCP_UDT, TCAP_ReturnResultLast, MAP_SRI, MAP_ATI, MAP_UL, MAP_PSI

logging.basicConfig(
    filename="logs/ss7_tool.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class ResponseParser:
    def __init__(self, db_path="ss7_data.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DROP TABLE IF EXISTS responses")
                cursor.execute("""
                    CREATE TABLE responses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        operation TEXT,
                        invoke_id INTEGER,
                        opcode INTEGER,
                        status TEXT,
                        imsi TEXT,
                        msisdn TEXT,
                        vlr_gt TEXT,
                        error TEXT,
                        raw_response TEXT
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database initialization error: {e}")
            raise

    def parse_response(self, response: bytes) -> dict:
        try:
            raw_hex = response.hex()
            logging.debug(f"Raw response: {raw_hex}")
            packet = SCCP_UDT(response)
            logging.debug(f"SCCP_UDT fields: {packet.fields}")
            logging.debug(f"SCCP_UDT data: {packet.data.hex()}")

            if not packet.data:
                logging.error("No data in SCCP_UDT")
                result = {
                    "status": "error",
                    "message": "No data in SCCP_UDT",
                    "operation": "unknown",
                    "raw_response": raw_hex
                }
                self._store_response(result)
                return result

            tcap_tag = packet.data[0]
            logging.debug(f"TCAP tag: {hex(tcap_tag)}")
            if tcap_tag != 0x04:
                logging.error(f"Expected TCAP_ReturnResultLast tag 0x04, got {hex(tcap_tag)}")
                result = {
                    "status": "error",
                    "message": f"Unknown TCAP tag: {hex(tcap_tag)}",
                    "operation": "unknown",
                    "raw_response": raw_hex
                }
                self._store_response(result)
                return result

            tcap = TCAP_ReturnResultLast(packet.data)
            logging.debug(f"TCAP_ReturnResultLast fields: {tcap.fields}")
            opcode = getattr(tcap, "opcode", -1)
            invoke_id = getattr(tcap, "invoke_id", -1)

            opcode_map = {
                4: "MAP_SRI",
                71: "MAP_ATI",
                2: "MAP_UL",
                59: "MAP_PSI"
            }
            operation = opcode_map.get(opcode, f"unknown_opcode_{opcode}")
            result = {
                "status": "success",
                "invoke_id": invoke_id,
                "opcode": opcode,
                "operation": operation,
                "params": {},
                "raw_response": raw_hex
            }

            if tcap.haslayer(MAP_SRI):
                map_layer = tcap[MAP_SRI]
                logging.debug(f"MAP_SRI fields: {map_layer.fields}")
                result["params"]["imsi"] = map_layer.imsi.decode('utf-8', errors='ignore')
                result["params"]["msisdn"] = map_layer.msisdn.decode('utf-8', errors='ignore')
            elif tcap.haslayer(MAP_ATI):
                map_layer = tcap[MAP_ATI]
                result["params"]["imsi"] = map_layer.imsi.decode('utf-8', errors='ignore')
            elif tcap.haslayer(MAP_UL):
                map_layer = tcap[MAP_UL]
                result["params"]["imsi"] = map_layer.imsi.decode('utf-8', errors='ignore')
                result["params"]["vlr_gt"] = map_layer.vlr_gt.decode('utf-8', errors='ignore')
            elif tcap.haslayer(MAP_PSI):
                map_layer = tcap[MAP_PSI]
                result["params"]["imsi"] = map_layer.imsi.decode('utf-8', errors='ignore')
            else:
                logging.error(f"No recognized MAP layer for opcode {opcode}")
                result["status"] = "error"
                result["message"] = f"No recognized MAP layer for opcode {opcode}"

            logging.debug(f"Parsed result: {result}")
            self._store_response(result)
            return result

        except Exception as e:
            logging.error(f"Response parsing error: {str(e)}")
            result = {
                "status": "error",
                "message": f"Parsing failed: {str(e)}",
                "operation": "unknown",
                "raw_response": raw_hex
            }
            self._store_response(result)
            return result

    def _store_response(self, result):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO responses (
                        operation, invoke_id, opcode, status, imsi, msisdn, vlr_gt, error, raw_response
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.get("operation", "unknown"),
                    result.get("invoke_id", -1),
                    result.get("opcode", -1),
                    result.get("status", "error"),
                    result.get("params", {}).get("imsi"),
                    result.get("params", {}).get("msisdn"),
                    result.get("params", {}).get("vlr_gt"),
                    result.get("error", result.get("message")),
                    result.get("raw_response")
                ))
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database storage error: {e}")

if __name__ == "__main__":
    parser = ResponseParser()
    test_response = b"\x09\x00\x03\x00\x00\x05\x00\x05\x00\x1a\x04\x18\x02\x01\x02\x30\x13\x02\x01\x04\x04\x0e\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34"
    parsed = parser.parse_response(test_response)
    print(parsed)