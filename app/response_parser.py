# app/response_parser.py

import logging
import binascii
from typing import Dict, Any, Optional

class ResponseParser:
    """
    Parser for SS7 MAP responses.
    """
    
    @staticmethod
    def parse_response(response: bytes) -> Dict[str, Any]:
        """
        Parse a raw SS7 response into a structured format.
        
        Args:
            response: Raw bytes from the SS7 network
            
        Returns:
            Dictionary with parsed response fields
        """
        if not response:
            logging.warning("Empty response received")
            return {"status": "empty"}
        
        try:
            # Basic hex representation
            hex_data = binascii.hexlify(response).decode('utf-8').upper()
            
            # Start with basic parsing
            result = {
                "status": "received",
                "raw_hex": hex_data,
                "length": len(response),
            }
            
            # Attempt to identify MAP operation result
            operation_result = ResponseParser._identify_operation_result(response)
            if operation_result:
                result.update(operation_result)
                
            return result
            
        except Exception as e:
            logging.error(f"Error parsing response: {e}")
            return {
                "status": "error",
                "error": str(e),
                "raw_hex": binascii.hexlify(response).decode('utf-8').upper() if response else ""
            }
    
    @staticmethod
    def _identify_operation_result(response: bytes) -> Optional[Dict[str, Any]]:
        """
        Identify the MAP operation result in the response.
        
        Args:
            response: Raw response bytes
            
        Returns:
            Dictionary with operation details if identified, None otherwise
        """
        # This is a simplistic implementation that should be expanded
        # based on actual SS7 MAP response formats
        try:
            # Check for common response patterns
            # Example: Looking for TCAP result tag (0xA2) and extracting operation code
            if len(response) > 10 and response[5] == 0xA2:
                # This is a simplified example - actual parsing would be more complex
                return {
                    "type": "TCAP_RESULT",
                    "operation_status": "success" if response[8] == 0x00 else "error"
                }
            
            return None
        except Exception as e:
            logging.error(f"Error identifying operation: {e}")
            return None
    
    @staticmethod
    def format_response(parsed_response: Dict[str, Any]) -> str:
        """
        Format a parsed response for display.
        
        Args:
            parsed_response: Dictionary with parsed response fields
            
        Returns:
            Formatted string representation
        """
        if parsed_response["status"] == "empty":
            return "📭 No response received from network"
        
        if parsed_response["status"] == "error":
            return f"❌ Error parsing response: {parsed_response.get('error', 'Unknown error')}"
        
        # Basic formatting
        result = "📨 Response received:\n"
        result += f"  • Size: {parsed_response['length']} bytes\n"
        result += f"  • Raw hex: {parsed_response['raw_hex']}\n"
        
        # Add operation details if available
        if "type" in parsed_response:
            result += f"  • Type: {parsed_response['type']}\n"
            
        if "operation_status" in parsed_response:
            status = parsed_response['operation_status']
            icon = "✅" if status == "success" else "❌"
            result += f"  • Status: {icon} {status.upper()}\n"
            
        return result