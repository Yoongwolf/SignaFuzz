SSS7 Security Research Tool (v0.2.0)
A Python-based tool for sending MAP-layer SS7 messages (SendRoutingInfo, AnyTimeInterrogation, UpdateLocation, ProvideSubscriberInfo) over SCTP/TCP to a lab SS7 network, parsing responses, and logging transactions.
Features

Send MAP messages (SRI, ATI, UL, PSI) with dynamic inputs (IMSI, MSISDN, GT, etc.).
CLI and interactive mode for operations.
BCD encoding/decoding for IMSI, MSISDN, GT.
SCTP/TCP communication with retry logic.
SQLite storage for transaction history.
Encrypted configuration management.
Unit and integration tests.

Installation
git clone <repository_url>
cd ss7-security-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Usage
Set the API key:
export SS7_API_KEY="test_key_123"

Run a command (e.g., SRI):
python main.py sri --imsi 123456789012345 --msisdn 9876543210 --target-ip 127.0.0.1 --target-port 2905 --ssn 6 --gt 1234567890

Interactive mode:
python main.py interactive
SS7> sri --imsi 123456789012345 --msisdn 9876543210 --target-ip 127.0.0.1 --target-port 2905 --ssn 6 --gt 1234567890

View transaction history:
sqlite3 ss7_data.db "SELECT * FROM ss7_transactions LIMIT 4;"

Project Structure

app/: Core logic (core.py, message_factory.py, response_parser.py, config_manager.py).
cli/: CLI and interactive mode (ui.py, command_handler.py).
utils/: Utilities for encoding (bcd.py), networking (sctp_client.py, tcp_client.py), protocols (ss7_layers.py), and validation (validators.py).
tests/: Unit and integration tests (test_bcd.py, test_validators.py, test_message_factory.py, etc.).
configs/: YAML configuration files (default_config.yml, logging_config.yml).
logs/: Log files (ss7_tool.log).
docs/: Documentation (message_flow.mmd).
ss7_data.db: SQLite database for transactions.

Requirements

Python 3.10+
Dependencies: scapy, pysctp, pyyaml, cryptography, pytest (see requirements.txt).

Development
Run tests:
python -m unittest discover tests -v

Start mock SS7 server:
python -m tests.mock_ss7_server

Roadmap

By May 15, 2025: SCCP/TCAP testing with real SS7 testbed.
By May 22, 2025: CSV export, enhanced security, CLI profiles, full documentation.
By June 5, 2025: Structured JSON logging.

License
MIT License
