#app/respons_parser.py
import logging
from typing import Dict, Any
from utils.encoding.bcd import decode_bcd

class ResponseParser:
    """
    Parse SS7 MAP responses.
    """

    @staticmethod
    def parse_response(response: bytes) -> Dict[str, Any]:
        """
        Parse an SS7 MAP response.

        Args:
            response: Raw response bytes

        Returns:
            Dictionary with parsed response fields (status, invoke_id, opcode, params)

        Raises:
            ValueError: If response is invalid or cannot be parsed
        """
        if not response:
            logging.warning("Empty response received")
            return {"status": "no_response", "message": "Empty response"}

        if len(response) < 6:
            logging.warning("Response too short for MAP parsing")
            return {"status": "error", "message": "Response too short"}

        try:
            # Extract TCAP/MAP fields
            invoke_id = response[2]
            opcode = response[5]
            params_start = 8
            params_len = response[7]

            if len(response) < params_start + params_len:
                logging.warning("Incomplete parameters in response")
                return {"status": "error", "message": "Incomplete parameters"}

            params_data = response[params_start:params_start + params_len]

            # Decode IMSI and MSISDN
            imsi = None
            msisdn = None
            if len(params_data) >= 10:
                imsi_data = params_data[2:10]  # Skip tag and length
                imsi = decode_bcd(imsi_data)
            if len(params_data) >= 17:
                msisdn_data = params_data[12:17]  # Skip tag and length
                msisdn = decode_bcd(msisdn_data)

            result = {
                "status": "success",
                "invoke_id": invoke_id,
                "opcode": opcode,
                "params": {
                    "imsi": imsi,
                    "msisdn": msisdn
                }
            }
            logging.info(f"Parsed response: {result}")
            return result

        except Exception as e:
            logging.error(f"Error parsing response: {e}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def format_response(parsed: Dict[str, Any]) -> str:
        """
        Format a parsed response into a human-readable string.

        Args:
            parsed: Parsed response dictionary

        Returns:
            Formatted string
        """
        status = parsed.get("status", "unknown")
        if status == "no_response":
            return "No response received"
        elif status == "error":
            return f"Error: {parsed.get('message', 'Unknown error')}"
        elif status == "success":
            result = [f"Status: Success", f"Invoke ID: {parsed.get('invoke_id')}", f"Opcode: {parsed.get('opcode')}"]
            params = parsed.get("params", {})
            if params.get("imsi"):
                result.append(f"IMSI: {params['imsi']}")
            if params.get("msisdn"):
                result.append(f"MSISDN: {params['msisdn']}")
            return "\n".join(result)
        return "Unknown response format"