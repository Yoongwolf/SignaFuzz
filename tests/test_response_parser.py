#test/TestResponseParser.py
import sqlite3
import logging
from datetime import datetime
from utils.protocols.ss7_layers import SCCP_UDT, TCAP_ReturnResultLast, MAP_SRI, MAP_ATI, MAP_UL, MAP_PSI
from utils.encoding.bcd import decode_bcd

class ResponseParser:
    def __init__(self, db_path: str = "ss7_data.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ss7_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation TEXT NOT NULL,
                    imsi TEXT,
                    msisdn TEXT,
                    vlr_gt TEXT,
                    gt TEXT,
                    ssn INTEGER,
                    target_ip TEXT,
                    target_port INTEGER,
                    protocol TEXT,
                    request_hex TEXT,
                    response_hex TEXT,
                    status TEXT,
                    invoke_id INTEGER,
                    opcode INTEGER,
                    timestamp DATETIME
                )
            """)
            conn.commit()

    def save_transaction(self, operation: str, request_data: dict, request_hex: str, response_hex: str, parsed_response: dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ss7_transactions (
                    operation, imsi, msisdn, vlr_gt, gt, ssn, target_ip, target_port, protocol,
                    request_hex, response_hex, status, invoke_id, opcode, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                operation,
                request_data.get("imsi"),
                request_data.get("msisdn"),
                request_data.get("vlr_gt"),
                request_data.get("gt"),
                request_data.get("ssn"),
                request_data.get("target_ip"),
                request_data.get("target_port"),
                request_data.get("protocol"),
                request_hex,
                response_hex,
                parsed_response.get("status"),
                parsed_response.get("invoke_id"),
                parsed_response.get("opcode"),
                datetime.utcnow()
            ))
            conn.commit()

    def get_history(self, limit: int = 10) -> list:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ss7_transactions ORDER BY timestamp DESC LIMIT ?", (limit,))
            return cursor.fetchall()

    def get_filtered_history(self, operation: str = None, start_date: str = None, end_date: str = None, limit: int = 10) -> list:
        query = "SELECT * FROM ss7_transactions WHERE 1=1"
        params = []
        if operation:
            query += " AND operation = ?"
            params.append(operation)
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()

    def parse_response(self, response: bytes) -> dict:
        if not response:
            logging.warning("Empty response received")
            return {"status": "no_response", "message": "Empty response"}
        
        if len(response) < 6:
            logging.warning("Response too short for MAP parsing")
            return {"status": "error", "message": "Response too short"}
        
        try:
            sccp = SCCP_UDT(response)
            if not sccp.haslayer(TCAP_ReturnResultLast):
                return {"status": "error", "message": "No TCAP layer"}
            
            tcap = sccp[TCAP_ReturnResultLast]
            result = {
                "status": "success",
                "invoke_id": tcap.invoke_id,
                "opcode": tcap.opcode
            }
            
            if tcap.haslayer(MAP_SRI):
                map_sri = tcap[MAP_SRI]
                result.update({
                    "params": {
                        "imsi": decode_bcd(map_sri.imsi),
                        "msisdn": decode_bcd(map_sri.msisdn)
                    }
                })
            elif tcap.haslayer(MAP_ATI):
                map_ati = tcap[MAP_ATI]
                result.update({
                    "params": {
                        "imsi": decode_bcd(map_ati.imsi)
                    }
                })
            elif tcap.haslayer(MAP_UL):
                map_ul = tcap[MAP_UL]
                result.update({
                    "params": {
                        "imsi": decode_bcd(map_ul.imsi),
                        "vlr_gt": decode_bcd(map_ul.vlr_gt)
                    }
                })
            elif tcap.haslayer(MAP_PSI):
                map_psi = tcap[MAP_PSI]
                result.update({
                    "params": {
                        "imsi": decode_bcd(map_psi.imsi)
                    }
                })
            else:
                return {"status": "error", "message": "Unknown MAP layer"}
            
            return result
        except Exception as e:
            logging.error(f"Parsing error: {e}")
            return {"status": "error", "message": str(e)}