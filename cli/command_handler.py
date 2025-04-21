# cli/command_handler.py

import argparse
import logging
from typing import Dict, Any, List

class CommandHandler:
    """
    Handler for command-line arguments.
    """
    
    def __init__(self):
        """
        Initialize command handler.
        """
        self.parser = self._create_parser()
        
    def _create_parser(self) -> argparse.ArgumentParser:
        """
        Create argument parser.
        
        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            description="SS7 Security Research Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Main command subparsers
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # SendRoutingInfo command
        sri_parser = subparsers.add_parser("sri", help="Send Routing Info operation")
        self._add_common_args(sri_parser)
        sri_parser.add_argument("--msisdn", required=True, help="Target MSISDN number")
        
        # AnyTimeInterrogation command
        ati_parser = subparsers.add_parser("ati", help="Any Time Interrogation operation")
        self._add_common_args(ati_parser)
        
        # UpdateLocation command
        ul_parser = subparsers.add_parser("ul", help="Update Location operation")
        self._add_common_args(ul_parser)
        ul_parser.add_argument("--vlr", required=True, help="VLR number")
        
        # Interactive mode
        interactive_parser = subparsers.add_parser("interactive", help="Run in interactive mode")
        
        # Configuration
        config_parser = subparsers.add_parser("config", help="Manage configuration")
        config_parser.add_argument("--show", action="store_true", help="Show current configuration")
        config_parser.add_argument("--save", help="Save configuration to specified file")
        config_parser.add_argument("--load", help="Load configuration from specified file")
        
        return parser
    
    def _add_common_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Add common arguments to a subparser.
        
        Args:
            parser: Subparser to add arguments to
        """
        parser.add_argument("--imsi", help="Target IMSI")
        parser.add_argument("--target-ip", required=True, help="Target network IP")
        parser.add_argument("--target-port", type=int, default=2905, help="Target port")
        parser.add_argument("--protocol", choices=["SCTP", "TCP"], default="SCTP", help="Transport protocol")
        parser.add_argument("--ssn", default="6", help="Subsystem Number")
        parser.add_argument("--gt", help="Global Title")
        parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    
    def parse_args(self, args: List[str] = None) -> Dict[str, Any]:
        """
        Parse command-line arguments.
        
        Args:
            args: Command-line arguments (optional)
            
        Returns:
            Dictionary with parsed arguments
        """
        parsed_args = self.parser.parse_args(args)
        
        # Set log level based on verbosity
        if hasattr(parsed_args, "verbose"):
            if parsed_args.verbose == 1:
                logging.getLogger().setLevel(logging.INFO)
            elif parsed_args.verbose >= 2:
                logging.getLogger().setLevel(logging.DEBUG)
        
        return vars(parsed_args)
    
    def print_help(self) -> None:
        """
        Print help message.
        """
        self.parser.print_help()