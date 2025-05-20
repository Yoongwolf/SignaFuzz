#cli/ui.py
import cmd
import logging
import os
import shlex
from typing import Optional
import argparse
from app.config_manager import ConfigManager

class SS7CLI(cmd.Cmd):
    prompt = "SS7> "
    intro = """
  ___ ___ _____   ___ ___ ___ _   _ ___ ___ _____   _____ ___   ___  _    
 / __/ __|___  | / __| __/ __| | | | _ \\_ _| __\\ \\ / /_  / _ \\ / _ \\| |   
 \\__ \\__ \\  / /  \\__ \\ _| (__| |_| |   /| || _| \\ V / / / (_) | (_) | |__ 
 |___/___/ /_/   |___/___\\___|\\___/|_|_\\___|___| \\_/ /___\\___/ \\___/|____|
                                                                          
    Security Research Tool - v0.2.0
    
Type 'help' for available commands or 'exit' to quit.
    """

    def __init__(self, core, config_manager: Optional[ConfigManager] = None):
        super().__init__()
        self.core = core
        self.config_manager = config_manager or ConfigManager(api_key=os.getenv("SS7_API_KEY"))
        self.api_key = self.config_manager.api_key
        if not self.api_key:
            self.api_key = input("Enter API key: ")
            self.config_manager.api_key = self.api_key
        self.logger = logging.getLogger(__name__)

    def do_sri(self, arg: str) -> None:
        """Send Routing Info (SRI) query: sri --imsi <imsi> --msisdn <msisdn> --target-ip <ip> --target-port <port> --ssn <ssn> --gt <gt> [--protocol <SCTP|TCP>]"""
        try:
            args = self._parse_args(arg, ["imsi", "msisdn", "target-ip", "target-port", "ssn", "gt"], ["protocol"])
            protocol = args.protocol if hasattr(args, "protocol") and args.protocol else self.config_manager.get_config("protocol", "SCTP")
            response = self.core.send_sri(
                imsi=args.imsi,
                msisdn=args.msisdn,
                target_ip=args.target_ip,
                target_port=int(args.target_port),
                ssn=int(args.ssn),
                gt=args.gt,
                protocol=protocol
            )
            self._print_response(response)
        except Exception as e:
            self.logger.error(f"SRI error: {e}")
            print(f"❌ Error: {e}")

    def do_ati(self, arg: str) -> None:
        """Any Time Interrogation (ATI) query: ati --imsi <imsi> --target-ip <ip> --target-port <port> --ssn <ssn> --gt <gt> [--protocol <SCTP|TCP>]"""
        try:
            args = self._parse_args(arg, ["imsi", "target-ip", "target-port", "ssn", "gt"], ["protocol"])
            protocol = args.protocol if hasattr(args, "protocol") and args.protocol else self.config_manager.get_config("protocol", "SCTP")
            response = self.core.send_ati(
                imsi=args.imsi,
                target_ip=args.target_ip,
                target_port=int(args.target_port),
                ssn=int(args.ssn),
                gt=args.gt,
                protocol=protocol
            )
            self._print_response(response)
        except Exception as e:
            self.logger.error(f"ATI error: {e}")
            print(f"❌ Error: {e}")

    def do_ul(self, arg: str) -> None:
        """Update Location (UL) query: ul --imsi <imsi> --vlr-gt <vlr_gt> --target-ip <ip> --target-port <port> --ssn <ssn> --gt <gt> [--protocol <SCTP|TCP>]"""
        try:
            args = self._parse_args(arg, ["imsi", "vlr-gt", "target-ip", "target-port", "ssn", "gt"], ["protocol"])
            protocol = args.protocol if hasattr(args, "protocol") and args.protocol else self.config_manager.get_config("protocol", "SCTP")
            response = self.core.send_ul(
                imsi=args.imsi,
                vlr_gt=args.vlr_gt,
                target_ip=args.target_ip,
                target_port=int(args.target_port),
                ssn=int(args.ssn),
                gt=args.gt,
                protocol=protocol
            )
            self._print_response(response)
        except Exception as e:
            self.logger.error(f"UL error: {e}")
            print(f"❌ Error: {e}")

    def do_psi(self, arg: str) -> None:
        """Provide Subscriber Info (PSI) query: psi --imsi <imsi> --target-ip <ip> --target-port <port> --ssn <ssn> --gt <gt> [--protocol <SCTP|TCP>]"""
        try:
            args = self._parse_args(arg, ["imsi", "target-ip", "target-port", "ssn", "gt"], ["protocol"])
            protocol = args.protocol if hasattr(args, "protocol") and args.protocol else self.config_manager.get_config("protocol", "SCTP")
            response = self.core.send_psi(
                imsi=args.imsi,
                target_ip=args.target_ip,
                target_port=int(args.target_port),
                ssn=int(args.ssn),
                gt=args.gt,
                protocol=protocol
            )
            self._print_response(response)
        except Exception as e:
            self.logger.error(f"PSI error: {e}")
            print(f"❌ Error: {e}")

    def do_history(self, arg: str) -> None:
        """View transaction history: history [--operation <op>] [--start-date <date>] [--end-date <date>] [--limit <limit>]"""
        try:
            args = self._parse_args(arg, [], ["operation", "start-date", "end-date", "limit"])
            limit = int(args.limit) if hasattr(args, "limit") and args.limit else 10
            history = self.core.get_filtered_history(
                operation=args.operation if hasattr(args, "operation") else None,
                start_date=args.start_date if hasattr(args, "start-date") else None,
                end_date=args.end_date if hasattr(args, "end-date") else None,
                limit=limit
            )
            self.display_history(history)
        except Exception as e:
            self.logger.error(f"History error: {e}")
            print(f"❌ Error: {e}")

    def do_exit(self, arg: str) -> bool:
        """Exit the CLI"""
        print("Exiting...")
        return True

    def _parse_args(self, arg: str, required: list, optional: list = []) -> argparse.Namespace:
        parser = argparse.ArgumentParser(prog="", add_help=False)
        for req in required:
            parser.add_argument(f"--{req}", required=True)
        for opt in optional:
            parser.add_argument(f"--{opt}")
        return parser.parse_args(shlex.split(arg))

    def _print_response(self, response: dict) -> None:
        if response.get("status") == "success":
            params = response.get("params", {})
            print("\nResponse:")
            print("-" * 40)
            for key, value in params.items():
                print(f"{key.upper()}: {value}")
            print("-" * 40)
        else:
            print(f"❌ Error: {response.get('message', 'Unknown error')}")

    def display_result(self, response: dict) -> None:
        """Display response for main.py compatibility."""
        self._print_response(response)

    def display_history(self, history: list) -> None:
        """Display transaction history for main.py compatibility."""
        if not history:
            print("No transactions found.")
            return
        print("\nRecent Transactions:")
        print("-" * 80)
        for tx in history:
            print(f"ID: {tx['id']} | Time: {tx['timestamp']} | Operation: {tx['operation']}")
            print(f"IMSI: {tx['imsi']} | MSISDN: {tx['msisdn'] or 'N/A'} | VLR GT: {tx['vlr_gt'] or 'N/A'}")
            print(f"Target: {tx['target_ip']}:{tx['target_port']} | SSN: {tx['ssn']} | GT: {tx['gt'] or 'N/A'}")
            print(f"Status: {tx['status']} | Invoke ID: {tx['invoke_id'] or 'N/A'} | Opcode: {tx['opcode'] or 'N/A'}")
            print(f"Request Hex: {tx['request_data'][:10]}...")
            print(f"Response Hex: {tx['response_data'][:10]}...")
            print("-" * 80)

    def do_help(self, arg: str) -> None:
        """Show help for commands"""
        print("\nAvailable Commands:")
        print("-" * 40)
        print("sri: Send Routing Info query")
        print("ati: Any Time Interrogation query")
        print("ul: Update Location query")
        print("psi: Provide Subscriber Info query")
        print("history: View transaction history")
        print("exit: Exit the CLI")
        print("-" * 40)
        print("Use '<command> --help' for specific command options.")

    def run_interactive_mode(self) -> None:
        """Run interactive CLI mode for main.py compatibility."""
        self.cmdloop()