#!/usr/bin/env python3
# main.py
#!/usr/bin/env python3
import argparse
import logging
import os
from app.core import SS7Core
from cli.ui import SS7CLI
from app.config_manager import ConfigManager

logging.basicConfig(
    filename="logs/ss7_tool.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)

def parse_args():
    parser = argparse.ArgumentParser(description="SS7 Security Research Tool")
    subparsers = parser.add_subparsers(dest="command")

    sri_parser = subparsers.add_parser("sri", help="Send Routing Info query")
    sri_parser.add_argument("--imsi", required=True)
    sri_parser.add_argument("--msisdn", required=True)
    sri_parser.add_argument("--target-ip", required=True)
    sri_parser.add_argument("--target-port", type=int, required=True)
    sri_parser.add_argument("--ssn", type=int, required=True)
    sri_parser.add_argument("--gt", required=True)
    sri_parser.add_argument("--protocol", choices=["SCTP", "TCP"], default="SCTP")

    ati_parser = subparsers.add_parser("ati", help="Any Time Interrogation query")
    ati_parser.add_argument("--imsi", required=True)
    ati_parser.add_argument("--target-ip", required=True)
    ati_parser.add_argument("--target-port", type=int, required=True)
    ati_parser.add_argument("--ssn", type=int, required=True)
    ati_parser.add_argument("--gt", required=True)
    ati_parser.add_argument("--protocol", choices=["SCTP", "TCP"], default="SCTP")

    ul_parser = subparsers.add_parser("ul", help="Update Location query")
    ul_parser.add_argument("--imsi", required=True)
    ul_parser.add_argument("--vlr-gt", required=True)
    ul_parser.add_argument("--target-ip", required=True)
    ul_parser.add_argument("--target-port", type=int, required=True)
    ul_parser.add_argument("--ssn", type=int, required=True)
    ul_parser.add_argument("--gt", required=True)
    ul_parser.add_argument("--protocol", choices=["SCTP", "TCP"], default="SCTP")

    psi_parser = subparsers.add_parser("psi", help="Provide Subscriber Info query")
    psi_parser.add_argument("--imsi", required=True)
    psi_parser.add_argument("--target-ip", required=True)
    psi_parser.add_argument("--target-port", type=int, required=True)
    psi_parser.add_argument("--ssn", type=int, required=True)
    psi_parser.add_argument("--gt", required=True)
    psi_parser.add_argument("--protocol", choices=["SCTP", "TCP"], default="SCTP")

    history_parser = subparsers.add_parser("history", help="View transaction history")
    history_parser.add_argument("--operation")
    history_parser.add_argument("--start-date")
    history_parser.add_argument("--end-date")
    history_parser.add_argument("--limit", type=int, default=10)

    subparsers.add_parser("interactive", help="Start interactive CLI")

    return parser.parse_args()

def main():
    args = parse_args()
    config_manager = ConfigManager()
    api_key = os.getenv("SS7_API_KEY") or config_manager.api_key
    if not api_key:
        logging.error("No API key found in environment or config")
        print("Error: SS7_API_KEY environment variable or config must be set")
        return

    core = SS7Core(api_key)
    cli = SS7CLI(core=core, config_manager=config_manager)

    if args.command == "sri":
        response = core.send_sri(
            imsi=args.imsi,
            msisdn=args.msisdn,
            target_ip=args.target_ip,
            target_port=args.target_port,
            ssn=args.ssn,
            gt=args.gt,
            protocol=args.protocol
        )
        cli.display_result(response)

    elif args.command == "ati":
        response = core.send_ati(
            imsi=args.imsi,
            target_ip=args.target_ip,
            target_port=args.target_port,
            ssn=args.ssn,
            gt=args.gt,
            protocol=args.protocol
        )
        cli.display_result(response)

    elif args.command == "ul":
        response = core.send_ul(
            imsi=args.imsi,
            vlr_gt=args.vlr_gt,
            target_ip=args.target_ip,
            target_port=args.target_port,
            ssn=args.ssn,
            gt=args.gt,
            protocol=args.protocol
        )
        cli.display_result(response)

    elif args.command == "psi":
        response = core.send_psi(
            imsi=args.imsi,
            target_ip=args.target_ip,
            target_port=args.target_port,
            ssn=args.ssn,
            gt=args.gt,
            protocol=args.protocol
        )
        cli.display_result(response)

    elif args.command == "history":
        history = core.get_filtered_history(
            operation=args.operation,
            start_date=args.start_date,
            end_date=args.end_date,
            limit=args.limit
        )
        cli.display_history(history)

    elif args.command == "interactive":
        cli.run_interactive_mode()

if __name__ == "__main__":
    main()