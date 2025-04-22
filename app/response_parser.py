import logging
from typing import Dict, Any
from utils.encoding.bcd import decode_bcd

class ResponseParser:
    @staticmethod
    def parse_response(response: bytes) -> Dict[str, Any]:
        """
        Parse SS7 MAP response bytes.

        Args:
            response: Raw response bytes

        Returns:
            Dictionary with parsed response data
        """
        try:
            if not response:
                logging.warning("Empty response received")
                return {"status": "no_response", "message": "No response received"}

            if len(response) < 12:
                logging.warning("Response too short for MAP parsing")
                return {"status": "error", "message": "Response too short"}

            # Parse TCAP/MAP headers
            invoke_id = response[2]
            opcode = response[5]
            params_length = response[7]  # Length of parameters

            params = {}
            offset = 8  # Start of parameters
            while offset < len(response) and offset < 8 + params_length:
                if offset + 2 > len(response):
                    break
                tag = response[offset]
                length = response[offset + 1]
                if offset + 2 + length > len(response):
                    break
                value = response[offset + 2:offset + 2 + length]
                if tag == 0x80:  # IMSI
                    params["imsi"] = decode_bcd(value.hex())
                elif tag == 0x81:  # MSISDN
                    params["msisdn"] = decode_bcd(value.hex())
                offset += 2 + length

            parsed_response = {
                "status": "success",
                "invoke_id": invoke_id,
                "opcode": opcode,
                "params": params
            }
            logging.info(f"Parsed response: {parsed_response}")
            return parsed_response
        except Exception as e:
            logging.error(f"Error parsing response: {e}")
            return {"status": "error", "message": f"Error parsing response: {e}"}

    @staticmethod
    def format_response(parsed_response: Dict[str, Any]) -> str:
        """
        Format parsed response for display.

        Args:
            parsed_response: Parsed response dictionary

        Returns:
            Formatted string
        """
        status = parsed_response.get("status")
        if status == "no_response":
            return "⚠️ No response received"
        if status == "error":
            return f"⚠️ Response Error: {parsed_response.get('message', 'Unknown error')}"
        
        lines = ["📨 Parsed MAP Response:"]
        lines.append(f"  Invoke ID: {parsed_response.get('invoke_id')}")
        lines.append(f"  Opcode: {'SendRoutingInfo' if parsed_response.get('opcode') == 0x04 else 'Unknown'} (0x{parsed_response.get('opcode'):02x})")
        lines.append("  Parameters:")
        params = parsed_response.get("params", {})
        if not params:
            lines.append("    (None)")
        else:
            for key, value in params.items():
                lines.append(f"    {key.capitalize()}: {value}")
        return "\n".join(lines)