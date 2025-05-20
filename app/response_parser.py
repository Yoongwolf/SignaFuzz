#app/respons_parser.py
import sqlite3
import logging
from datetime import datetime
from utils.protocols.ss7_layers import SCCP_UDT, TCAP_ReturnResultLast, MAP_SRI, MAP_ATI, MAP_UL, MAP_PSI
from utils.encoding.bcd import decode_bcd

class ResponseParser:
    def __init__(self, db_path: str = "ss7_data.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS ss7_transactions")
            cursor.execute("""
                CREATE TABLE ss7_transactions (
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
                    request_data TEXT,
                    response_data TEXT,
                    status TEXT,
                    invoke_id INTEGER,
                    opcode INTEGER,
                    timestamp TEXT
                )
            """)
            conn.commit()

    def store_transaction(self, operation: str, imsi: str, msisdn: str, vlr_gt: str, gt: str, ssn: int, target_ip: str, target_port: int, protocol: str, request_data: str, response_data: str, status: str, invoke_id: int, opcode: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            timestamp = datetime.utcnow().isoformat()
            cursor.execute("""
                INSERT INTO ss7_transactions (
                    operation, imsi, msisdn, vlr_gt, gt, ssn, target_ip, target_port, protocol,
                    request_data, response_data, status, invoke_id, opcode, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                operation, imsi, msisdn, vlr_gt, gt, ssn, target_ip, target_port, protocol,
                request_data, response_data, status, invoke_id, opcode, timestamp
            ))
            conn.commit()

    def get_history(self, limit: int = 10) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ss7_transactions ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

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
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def parse_response(self, response: bytes) -> dict:
        if not response:
            self.logger.warning("Empty response received")
            return {"status": "no_response", "message": "Empty response"}
        
        try:
            sccp = SCCP_UDT(response)
            if not sccp.haslayer(TCAP_ReturnResultLast):
                self.logger.warning("No TCAP_ReturnResultLast layer in response")
                return {"status": "error", "message": "No TCAP layer"}
            
            tcap = sccp[TCAP_ReturnResultLast]
            result = {
                "status": "success",
                "invoke_id": tcap.invoke_id,
                "opcode": tcap.opcode,
                "params": {}
            }
            
            if tcap.haslayer(MAP_SRI):
                map_sri = tcap[MAP_SRI]
                result["params"].update({
                    "imsi": decode_bcd(map_sri.imsi) if map_sri.imsi else None,
                    "msisdn": decode_bcd(map_sri.msisdn) if map_sri.msisdn else None
                })
            elif tcap.haslayer(MAP_ATI):
                map_ati = tcap[MAP_ATI]
                result["params"].update({
                    "imsi": decode_bcd(map_ati.imsi) if map_ati.imsi else None
                })
            elif tcap.haslayer(MAP_UL):
                map_ul = tcap[MAP_UL]
                result["params"].update({
                    "imsi": decode_bcd(map_ul.imsi) if map_ul.imsi else None,
                    "vlr_gt": decode_bcd(map_ul.vlr_gt) if map_ul.vlr_gt else None
                })
            elif tcap.haslayer(MAP_PSI):
                map_psi = tcap[MAP_PSI]
                result["params"].update({
                    "imsi": decode_bcd(map_psi.imsi) if map_psi.imsi else None
                })
            else:
                self.logger.warning("Unknown MAP layer in response")
                return {"status": "error", "message": "Unknown MAP layer"}
            
            return result
        except Exception as e:
            self.logger.error(f"Response parsing error: {e}")
            return {"status": "error", "message": str(e)}