#!/usr/bin/env python3
# main.py
import argparse
import logging
import os
import sys
from app.core import Ss7Tool
from app.config_manager import ConfigManager
from app.response_parser import ResponseParser
from cli.ui import CommandHandler

def setup_logging():
    """
    Set up logging configuration.
    """
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler("logs/ss7_tool.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def run_message_operation(args):
    """
    Run specified message operation.
    """
    try:
        config = {
            "imsi": args.imsi,
            "msisdn": args.msisdn,
            "target_ip": args.target_ip,
            "target_port": args.target_port,
            "protocol": args.protocol or "SCTP",
            "ssn": args.ssn,
            "gt": args.gt,
        }
        
        tool = Ss7Tool(config)
        command = args.command
        kwargs = {}
        if command == "ul":
            kwargs["vlr_number"] = args.vlr
            if not kwargs["vlr_number"]:
                raise ValueError("VLR number required for UpdateLocation")
        
        logging.info(f"Sending {command} message to {args.target_ip}:{args.target_port}")
        tool.send_message(command, **kwargs)
        
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
    """
    Main entry point for SS7 Security Research Tool.
    """
    setup_logging()
    
    # Check API key
    api_key = os.getenv("SS7_API_KEY")
    if not api_key or api_key != "test_key_123":
        print("❌ Error: Invalid or missing SS7_API_KEY")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="SS7 Security Research Tool")
    subparsers = parser.add_subparsers(dest="command")
    
    # Interactive mode
    subparsers.add_parser("interactive", help="Run interactive CLI")
    
    # SRI command
    sri_parser = subparsers.add_parser("sri", help="Send SendRoutingInfo message")
    sri_parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
    sri_parser.add_argument("--msisdn", required=True, help="MSISDN (10-15 digits)")
    sri_parser.add_argument("--target-ip", required=True, help="Target IP address")
    sri_parser.add_argument("--target-port", type=int, required=True, help="Target port")
    sri_parser.add_argument("--protocol", default="SCTP", help="Protocol (SCTP or TCP)")
    sri_parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
    sri_parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")
    
    # ATI command
    ati_parser = subparsers.add_parser("ati", help="Send AnyTimeInterrogation message")
    ati_parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
    ati_parser.add_argument("--target-ip", required=True, help="Target IP address")
    ati_parser.add_argument("--target-port", type=int, required=True, help="Target port")
    ati_parser.add_argument("--protocol", default="SCTP", help="Protocol (SCTP or TCP)")
    ati_parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
    ati_parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")
    
    # UL command
    ul_parser = subparsers.add_parser("ul", help="Send UpdateLocation message")
    ul_parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
    ul_parser.add_argument("--vlr", required=True, help="VLR number")
    ul_parser.add_argument("--target-ip", required=True, help="Target IP address")
    ul_parser.add_argument("--target-port", type=int, required=True, help="Target port")
    ul_parser.add_argument("--protocol", default="SCTP", help="Protocol (SCTP or TCP)")
    ul_parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
    ul_parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")
    
    # PSI command
    psi_parser = subparsers.add_parser("psi", help="Send ProvideSubscriberInfo message")
    psi_parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
    psi_parser.add_argument("--target-ip", required=True, help="Target IP address")
    psi_parser.add_argument("--target-port", type=int, required=True, help="Target port")
    psi_parser.add_argument("--protocol", default="SCTP", help="Protocol (SCTP or TCP)")
    psi_parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
    psi_parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")
    
    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument("--show", action="store_true", help="Show current configuration")
    config_parser.add_argument("--save", help="Save configuration to file")
    config_parser.add_argument("--load", help="Load configuration from file")
    
    args = parser.parse_args()
    
    if args.command == "interactive":
        CommandHandler().cmdloop()
    elif args.command in ["sri", "ati", "ul", "psi"]:
        run_message_operation(args)
    elif args.command == "config":
        config_manager = ConfigManager()
        if args.show:
            print("Current configuration:")
            print(config_manager.config)
        elif args.save:
            config_manager.save(args.save)
            print(f"Configuration saved to {args.save}")
        elif args.load:
            config_manager = ConfigManager(args.load)
            print(f"Configuration loaded from {args.load}")
        else:
            parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()