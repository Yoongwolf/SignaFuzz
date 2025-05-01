#cli/ui.py
import logging
import cmd
import argparse
from datetime import datetime
from typing import Optional
from colorama import init, Fore
from app.core import Ss7Tool
from app.response_parser import ResponseParser
from utils.validators import validate_imsi, validate_msisdn, validate_ip, validate_port, validate_gt, validate_ssn

init(autoreset=True)

def print_colored(message: str, color: str = Fore.WHITE) -> None:
    """
    Print a colored message to the console.
    """
    print(f"{color}{message}")

def print_success(message: str) -> None:
    """
    Print a success message in green.
    """
    print_colored(f"✅ {message}", Fore.GREEN)

def print_error(message: str) -> None:
    """
    Print an error message in red.
    """
    print_colored(f"❌ Error: {message}", Fore.RED)

class CommandHandler(cmd.Cmd):
    """
    Interactive CLI for SS7 Security Research Tool.
    """
    prompt = "SS7> "
    intro = """
  ___ ___ _____   ___ ___ ___ _   _ ___ ___ _____   _____ ___   ___  _    
 / __/ __|___  | / __| __/ __| | | | _ \\_ _| __\\ \\ / /_  / _ \\ / _ \\| |   
 \\__ \\__ \\  / /  \\__ \\ _| (__| |_| |   /| || _| \\ V / / / (_) | (_) | |__ 
 |___/___/ /_/   |___/___\\___|\\___/|_|_\\___|___| \\_/ /___\\___/ \\___/|____|
                                                                          
    Security Research Tool - v0.2.0
    
Type 'help' for available commands or 'exit' to quit.
    """

    def __init__(self):
        super().__init__()
        self.api_key: Optional[str] = None
        self.tool: Optional[Ss7Tool] = None

    def preloop(self) -> None:
        """
        Authenticate API key before starting the command loop.
        """
        try:
            while not self.api_key:
                key = input("Enter API key: ").strip()
                if key == "test_key_123":  # Replace with actual authentication
                    self.api_key = key
                    logging.info(f"[{datetime.now()}] INFO: API key authenticated")
                else:
                    print_error("Invalid API key")
        except KeyboardInterrupt:
            print("\nExiting...")
            raise SystemExit

    def do_sri(self, arg: str) -> None:
        """
        Send SendRoutingInfo (SRI) message.
        Usage: sri --imsi <IMSI> --msisdn <MSISDN> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>
        """
        parser = argparse.ArgumentParser(prog="sri")
        parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
        parser.add_argument("--msisdn", required=True, help="MSISDN (10-15 digits)")
        parser.add_argument("--target-ip", required=True, help="Target IP address")
        parser.add_argument("--target-port", type=int, required=True, help="Target port")
        parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
        parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")

        try:
            args = parser.parse_args(arg.split())
            config = {
                "imsi": args.imsi,
                "msisdn": args.msisdn,
                "target_ip": args.target_ip,
                "target_port": args.target_port,
                "protocol": "SCTP",
                "ssn": args.ssn,
                "gt": args.gt
            }
            self.tool = Ss7Tool(config)
            logging.info(f"[{datetime.now()}] INFO: Sending sri message to {args.target_ip}:{args.target_port}")
            self.tool.send_message("sri")
            parsed_response = ResponseParser.parse_response(self.tool.response)
            print_success(f"Parsed response: {parsed_response}")
            self.tool.handle_response()
        except argparse.ArgumentError as e:
            print_error(f"Argument error: {e}")
        except ValueError as e:
            print_error(f"Validation error: {e}")
        except RuntimeError as e:
            print_error(f"Runtime error: {e}")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            logging.error(f"[{datetime.now()}] ERROR: Error during operation: {e}")

    def do_ati(self, arg: str) -> None:
        """
        Send AnyTimeInterrogation (ATI) message.
        Usage: ati --imsi <IMSI> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>
        """
        parser = argparse.ArgumentParser(prog="ati")
        parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
        parser.add_argument("--target-ip", required=True, help="Target IP address")
        parser.add_argument("--target-port", type=int, required=True, help="Target port")
        parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
        parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")

        try:
            args = parser.parse_args(arg.split())
            config = {
                "imsi": args.imsi,
                "msisdn": None,
                "target_ip": args.target_ip,
                "target_port": args.target_port,
                "protocol": "SCTP",
                "ssn": args.ssn,
                "gt": args.gt
            }
            self.tool = Ss7Tool(config)
            logging.info(f"[{datetime.now()}] INFO: Sending ati message to {args.target_ip}:{args.target_port}")
            self.tool.send_message("ati")
            parsed_response = ResponseParser.parse_response(self.tool.response)
            print_success(f"Parsed response: {parsed_response}")
            self.tool.handle_response()
        except argparse.ArgumentError as e:
            print_error(f"Argument error: {e}")
        except ValueError as e:
            print_error(f"Validation error: {e}")
        except RuntimeError as e:
            print_error(f"Runtime error: {e}")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            logging.error(f"[{datetime.now()}] ERROR: Error during operation: {e}")

    def do_ul(self, arg: str) -> None:
        """
        Send UpdateLocation (UL) message.
        Usage: ul --imsi <IMSI> --vlr-number <VLR> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>
        """
        parser = argparse.ArgumentParser(prog="ul")
        parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
        parser.add_argument("--vlr-number", required=True, help="VLR number")
        parser.add_argument("--target-ip", required=True, help="Target IP address")
        parser.add_argument("--target-port", type=int, required=True, help="Target port")
        parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
        parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")

        try:
            args = parser.parse_args(arg.split())
            config = {
                "imsi": args.imsi,
                "msisdn": None,
                "vlr": args.vlr_number,
                "target_ip": args.target_ip,
                "target_port": args.target_port,
                "protocol": "SCTP",
                "ssn": args.ssn,
                "gt": args.gt
            }
            self.tool = Ss7Tool(config)
            logging.info(f"[{datetime.now()}] INFO: Sending ul message to {args.target_ip}:{args.target_port}")
            self.tool.send_message("ul", vlr_number=args.vlr_number)
            parsed_response = ResponseParser.parse_response(self.tool.response)
            print_success(f"Parsed response: {parsed_response}")
            self.tool.handle_response()
        except argparse.ArgumentError as e:
            print_error(f"Argument error: {e}")
        except ValueError as e:
            print_error(f"Validation error: {e}")
        except RuntimeError as e:
            print_error(f"Runtime error: {e}")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            logging.error(f"[{datetime.now()}] ERROR: Error during operation: {e}")

    def do_psi(self, arg: str) -> None:
        """
        Send ProvideSubscriberInfo (PSI) message.
        Usage: psi --imsi <IMSI> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>
        """
        parser = argparse.ArgumentParser(prog="psi")
        parser.add_argument("--imsi", required=True, help="IMSI (15 digits)")
        parser.add_argument("--target-ip", required=True, help="Target IP address")
        parser.add_argument("--target-port", type=int, required=True, help="Target port")
        parser.add_argument("--ssn", type=int, required=True, help="Subsystem Number (0-254)")
        parser.add_argument("--gt", required=True, help="Global Title (10-15 digits)")

        try:
            args = parser.parse_args(arg.split())
            config = {
                "imsi": args.imsi,
                "msisdn": None,
                "target_ip": args.target_ip,
                "target_port": args.target_port,
                "protocol": "SCTP",
                "ssn": args.ssn,
                "gt": args.gt
            }
            self.tool = Ss7Tool(config)
            logging.info(f"[{datetime.now()}] INFO: Sending psi message to {args.target_ip}:{args.target_port}")
            self.tool.send_message("psi")
            parsed_response = ResponseParser.parse_response(self.tool.response)
            print_success(f"Parsed response: {parsed_response}")
            self.tool.handle_response()
        except argparse.ArgumentError as e:
            print_error(f"Argument error: {e}")
        except ValueError as e:
            print_error(f"Validation error: {e}")
        except RuntimeError as e:
            print_error(f"Runtime error: {e}")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            logging.error(f"[{datetime.now()}] ERROR: Error during operation: {e}")

    def do_exit(self, arg: str) -> bool:
        """
        Exit the CLI.
        """
        print("Exiting...")
        return True

    def do_help(self, arg: str) -> None:
        """
        Show help for commands.
        """
        commands = {
            "sri": "Send SendRoutingInfo message. Usage: sri --imsi <IMSI> --msisdn <MSISDN> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>",
            "ati": "Send AnyTimeInterrogation message. Usage: ati --imsi <IMSI> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>",
            "ul": "Send UpdateLocation message. Usage: ul --imsi <IMSI> --vlr-number <VLR> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>",
            "psi": "Send ProvideSubscriberInfo message. Usage: psi --imsi <IMSI> --target-ip <IP> --target-port <PORT> --ssn <SSN> --gt <GT>",
            "exit": "Exit the CLI",
            "help": "Show this help message"
        }
        if arg:
            if arg in commands:
                print(commands[arg])
            else:
                print_error(f"Unknown command: {arg}")
        else:
            print("Available commands:")
            for cmd, desc in commands.items():
                print(f"  {cmd}: {desc}")

    def default(self, line: str) -> None:
        """
        Handle unknown commands.
        """
        print_error(f"Unknown command: {line}")

    def emptyline(self) -> None:
        """
        Do nothing on empty input.
        """
        pass

def run_interactive() -> None:
    """
    Run the interactive CLI.
    """
    try:
        CommandHandler().cmdloop()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print_error(f"CLI error: {e}")
        logging.error(f"[{datetime.now()}] ERROR: CLI error: {e}")

if __name__ == "__main__":
    logging.basicConfig(filename="logs/ss7_tool.log", level=logging.INFO)
    run_interactive()