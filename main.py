## 22. Enhanced main.py

#!/usr/bin/env python3
# main.py

import os
import sys
import logging
import argparse
from typing import Dict, Any

from app.core import Ss7Tool
from app.config_manager import ConfigManager
from app.message_factory import MessageFactory
from app.response_parser import ResponseParser
from cli.command_handler import CommandHandler
from cli.ui import UI

def setup_logging():
    """Set up logging configuration."""
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler("logs/ss7_tool.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def get_user_input() -> Dict[str, Any]:
    """Get user input interactively."""
    print("=== SS7 Security Research Tool ===")
    config = {
        "imsi": input("Enter IMSI: "),
        "msisdn": input("Enter MSISDN: "),
        "target_ip": input("Enter Target Network IP: "),
        "target_port": input("Enter Target Port: "),
        "protocol": input("Enter Protocol (SCTP/TCP): "),
        "ssn": input("Enter SSN: "),
        "gt": input("Enter Global Title (GT): "),
    }
    return config

def run_message_operation(args):
    """Run specified message operation."""
    try:
        # Create configuration from args
        config = {
            "imsi": args.get("imsi"),
            "msisdn": args.get("msisdn"),
            "target_ip": args.get("target_ip"),
            "target_port": args.get("target_port"),
            "protocol": args.get("protocol", "SCTP"),
            "ssn": args.get("ssn"),
            "gt": args.get("gt"),
        }
        
        # Create SS7 tool instance
        tool = Ss7Tool(config)
        
        # Send the message
        logging.info(f"Sending {args.get('command')} message to {args.get('target_ip')}:{args.get('target_port')}")
        tool.send_message()
        
        # Parse and display the response
        if tool.response:
            parsed_response = ResponseParser.parse_response(tool.response)
            formatted_response = ResponseParser.format_response(parsed_response)
            print(formatted_response)
        else:
            print("📭 No response received")
            
        return True
    except Exception as e:
        logging.error(f"Error during operation: {e}")
        print(f"❌ Error: {e}")
        return False

def main():
    """Main entry point."""
    setup_logging()
    
    try:
        # Parse command-line arguments
        command_handler = CommandHandler()
        args = command_handler.parse_args()
        
        command = args.get("command")
        
        if command == "interactive":
            # Run interactive mode
            ui = UI()
            ui.run_interactive_mode()
        elif command in ["sri", "ati", "ul"]:
            # Run specific operation
            run_message_operation(args)
        elif command == "config":
            # Handle configuration
            config_manager = ConfigManager()
            if args.get("show"):
                print("Current configuration:")
                print(config_manager.config)
            elif args.get("save"):
                config_manager.save(args.get("save"))
                print(f"Configuration saved to {args.get('save')}")
            elif args.get("load"):
                config_manager = ConfigManager(args.get("load"))
                print(f"Configuration loaded from {args.get('load')}")
        else:
            # No command specified, show help
            command_handler.print_help()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        logging.exception("Unhandled exception")
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()