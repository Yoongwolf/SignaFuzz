# cli/ui.py

import sys
import logging
from typing import Dict, Any, Optional, List

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
                    
                parts = command_line.split(" ", 1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""
                
                if command in self.operation_handlers:
                    self.operation_handlers[command](args)
                else:
                    self.print_error(f"Unknown command: {command}")
                    self._handle_help("")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                self.print_error(f"Error: {e}")
                logging.exception("Error in interactive mode")
    
    def _handle_help(self, args: str) -> None:
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
        print("  help Show this help message")
        print("  exit Exit the program")
    
    def _handle_exit(self, args: str) -> None:
        """
        Handle exit command.
        
        Args:
            args: Command arguments (unused)
        """
        self.print_info("Goodbye!")
        sys.exit(0)
    
    def _handle_sri(self, args: str) -> None:
        """
        Handle SendRoutingInfo command.
        
        Args:
            args: Command arguments
        """
        # This would parse args and call the appropriate function
        # For demonstration, we'll just show what would happen
        self.print_info("Executing SendRoutingInfo operation...")
        # Parse args and extract parameters
        # Execute operation using your core functionality
        
    def _handle_ati(self, args: str) -> None:
        """
        Handle AnyTimeInterrogation command.
        
        Args:
            args: Command arguments
        """
        self.print_info("Executing AnyTimeInterrogation operation...")
        # Parse args and execute
        
    def _handle_ul(self, args: str) -> None:
        """
        Handle UpdateLocation command.
        
        Args:
            args: Command arguments
        """
        self.print_info("Executing UpdateLocation operation...")
        # Parse args and execute