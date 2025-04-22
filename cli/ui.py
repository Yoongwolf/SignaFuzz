import sys
import logging
import shlex
from typing import Dict, Any, Optional, List
from app.core import Ss7Tool
from app.response_parser import ResponseParser
from utils.validators import validate_imsi, validate_msisdn, validate_gt, validate_ip, validate_port

class UI:
    """
    User interface handler for interactive mode.
    """
    
    BANNER = """
  ___ ___ _____   ___ ___ ___ _   _ ___ ___ _____   _____ ___   ___  _    
 / __/ __|___  | / __| __/ __| | | | _ \_ _| __\ \ / /_  / _ \ / _ \| |   
 \__ \__ \  / /  \__ \ _| (__| |_| |   /| || _| \ V / / / (_) | (_) | |__ 
 |___/___/ /_/   |___/___\___|\___/|_|_\___|___| \_/ /___\___/ \___/|____|
                                                                          
    Security Research Tool - v0.2.0
    """
    
    def __init__(self):
        """
        Initialize user interface.
        """
        self.operation_handlers = {
            "sri": self._handle_sri,
            "ati": self._handle_ati,
            "ul": self._handle_ul,
            "psi": self._handle_psi,
            "help": self._handle_help,
            "exit": self._handle_exit
        }
    
    def show_banner(self) -> None:
        """
        Display application banner.
        """
        print(self.BANNER)
        print("Type 'help' for available commands or 'exit' to quit.")
        print()
    
    def print_colored(self, text: str, color_code: int) -> None:
        """
        Print colored text.
        
        Args:
            text: Text to print
            color_code: ANSI color code
        """
        print(f"\033[{color_code}m{text}\033[0m")
        
    def print_success(self, text: str) -> None:
        """
        Print success message.
        
        Args:
            text: Success message
        """
        self.print_colored(text, 32)  # Green
        
    def print_error(self, text: str) -> None:
        """
        Print error message.
        
        Args:
            text: Error message
        """
        self.print_colored(text, 31)  # Red
        
    def print_info(self, text: str) -> None:
        """
        Print info message.
        
        Args:
            text: Info message
        """
        self.print_colored(text, 36)  # Cyan
    
    def get_input(self, prompt: str, default: Optional[str] = None) -> str:
        """
        Get user input with prompt.
        
        Args:
            prompt: Input prompt
            default: Default value (optional)
            
        Returns:
            User input or default value
        """
        prompt_text = f"{prompt}: " if default is None else f"{prompt} [{default}]: "
        value = input(prompt_text).strip()
        return value if value else default if default is not None else ""
    
    def run_interactive_mode(self) -> None:
        """
        Run interactive command loop.
        """
        self.show_banner()
        
        while True:
            try:
                command_line = input("\033[1m\033[34mSS7> \033[0m").strip()
                if not command_line:
                    continue
                
                if command_line.strip().startswith("python main.py"):
                    self.print_error("Error: CLI commands cannot be run in interactive mode.")
                    self.print_info("Use the command directly, e.g.:")
                    self.print_info("  sri --imsi 123456789012345 --msisdn 9876543210 --target-ip 127.0.0.1 --target-port 2905 --ssn 6 --gt 1234567890")
                    self._handle_help([])
                    continue
                    
                parts = shlex.split(command_line)
                command = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if command in self.operation_handlers:
                    self.operation_handlers[command](args)
                else:
                    self.print_error(f"Unknown command: {command}")
                    self._handle_help([])
                    
            except KeyboardInterrupt:
                self.print_info("\nExiting...")
                break
            except Exception as e:
                self.print_error(f"Error: {e}")
                logging.exception("Error in interactive mode")
    
    def _handle_help(self, args: List[str]) -> None:
        """
        Handle help command.
        
        Args:
            args: Command arguments (unused)
        """
        self.print_info("Available commands:")
        print("  sri  [--imsi IMSI] --msisdn MSISDN --target-ip IP [--target-port PORT]")
        print("       [--protocol {SCTP,TCP}] [--ssn SSN] [--gt GT]")
        print("       Send Routing Info operation")
        print()
        print("  ati  [--imsi IMSI] --target-ip IP [--target-port PORT]")
        print("       [--protocol {SCTP,TCP}] [--ssn SSN] [--gt GT]")
        print("       Any Time Interrogation operation")
        print()
        print("  ul   [--imsi IMSI] --vlr VLR --target-ip IP [--target-port PORT]")
        print("       [--protocol {SCTP,TCP}] [--ssn SSN] [--gt GT]")
        print("       Update Location operation")
        print()
        print("  psi  [--imsi IMSI] --target-ip IP [--target-port PORT]")
        print("       [--protocol {SCTP,TCP}] [--ssn SSN] [--gt GT]")
        print("       Provide Subscriber Info operation")
        print()
        print("  help Show this help message")
        print("  exit Exit the program")
    
    def _handle_exit(self, args: List[str]) -> None:
        """
        Handle exit command.
        
        Args:
            args: Command arguments (unused)
        """
        self.print_info("Goodbye!")
        sys.exit(0)
    
    def _handle_sri(self, args: List[str]) -> None:
        """
        Handle SendRoutingInfo command.
        
        Args:
            args: Command arguments
        """
        self.print_info("Executing SendRoutingInfo operation...")
        config = self._parse_args(args, required=["msisdn", "target_ip"])
        if not config:
            return
        try:
            tool = Ss7Tool(config)
            tool.send_message("sri")
            if tool.response:
                parsed = ResponseParser.parse_response(tool.response)
                self.print_success(ResponseParser.format_response(parsed))
            else:
                self.print_error("No response received")
        except Exception as e:
            self.print_error(f"Error: {e}")
        
    def _handle_ati(self, args: List[str]) -> None:
        """
        Handle AnyTimeInterrogation command.
        
        Args:
            args: Command arguments
        """
        self.print_info("Executing AnyTimeInterrogation operation...")
        config = self._parse_args(args, required=["target_ip"])
        if not config:
            return
        try:
            tool = Ss7Tool(config)
            tool.send_message("ati")
            if tool.response:
                parsed = ResponseParser.parse_response(tool.response)
                self.print_success(ResponseParser.format_response(parsed))
            else:
                self.print_error("No response received")
        except Exception as e:
            self.print_error(f"Error: {e}")
        
    def _handle_ul(self, args: List[str]) -> None:
        """
        Handle UpdateLocation command.
        
        Args:
            args: Command arguments
        """
        self.print_info("Executing UpdateLocation operation...")
        config = self._parse_args(args, required=["vlr", "target_ip"])
        if not config:
            return
        try:
            tool = Ss7Tool(config)
            tool.send_message("ul", vlr_number=config["vlr"])
            if tool.response:
                parsed = ResponseParser.parse_response(tool.response)
                self.print_success(ResponseParser.format_response(parsed))
            else:
                self.print_error("No response received")
        except Exception as e:
            self.print_error(f"Error: {e}")
    
    def _handle_psi(self, args: List[str]) -> None:
        """
        Handle ProvideSubscriberInfo command.
        
        Args:
            args: Command arguments
        """
        self.print_info("Executing ProvideSubscriberInfo operation...")
        config = self._parse_args(args, required=["target_ip"])
        if not config:
            return
        try:
            tool = Ss7Tool(config)
            tool.send_message("psi")
            if tool.response:
                parsed = ResponseParser.parse_response(tool.response)
                self.print_success(ResponseParser.format_response(parsed))
            else:
                self.print_error("No response received")
        except Exception as e:
            self.print_error(f"Error: {e}")
    
    def _parse_args(self, args: List[str], required: List[str]) -> Optional[Dict[str, Any]]:
        """
        Parse command-line arguments for interactive mode.

        Args:
            args: List of arguments
            required: List of required arguments

        Returns:
            Parsed config dictionary or None if invalid
        """
        config = {
            "imsi": "123456789012345",  # Default for testing
            "msisdn": "9876543210",
            "target_ip": None,
            "target_port": 2905,
            "protocol": "SCTP",
            "ssn": "6",
            "gt": "1234567890",
            "vlr": None
        }
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ["--imsi", "--msisdn", "--target-ip", "--target-port", "--protocol", "--ssn", "--gt", "--vlr"]:
                if i + 1 >= len(args):
                    self.print_error(f"Missing value for {arg}")
                    return None
                key = arg.lstrip("--").replace("-", "_")
                config[key] = args[i + 1]
                i += 2
            else:
                self.print_error(f"Unknown argument: {arg}")
                return None

        for key in required:
            if not config[key]:
                self.print_error(f"Missing required argument: --{key.replace('_', '-')}")
                return None

        # Validate inputs
        if not validate_imsi(config["imsi"]):
            self.print_error("Invalid IMSI: must be 15 digits")
            return None
        if config["msisdn"] and not validate_msisdn(config["msisdn"]):
            self.print_error("Invalid MSISDN: must be 10-15 digits")
            return None
        if not validate_gt(config["gt"]):
            self.print_error("Invalid Global Title: must be 10-15 digits")
            return None
        if not config["ssn"].isdigit() or not (0 <= int(config["ssn"]) <= 254):
            self.print_error("Invalid SSN: must be integer 0-254")
            return None
        if not validate_ip(config["target_ip"]):
            self.print_error("Invalid Target IP: must be a valid IPv4 address")
            return None
        if not validate_port(config["target_port"]):
            self.print_error("Invalid Target Port: must be integer 1-65535")
            return None
        if config["protocol"] not in ["SCTP", "TCP"]:
            self.print_error("Invalid Protocol: must be SCTP or TCP")
            return None

        return config

if __name__ == "__main__":
    ui = UI()
    ui.run_interactive_mode()