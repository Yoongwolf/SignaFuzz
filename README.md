# SS7 Security Research Tool

A Python-based tool for SS7 security research and testing in laboratory environments.

## Features

- Send customized MAP-layer SS7 messages to target networks
- Support for multiple MAP operations:
  - SendRoutingInfo (SRI)
  - AnyTimeInterrogation (ATI)
  - UpdateLocation (UL)
- Accept dynamic input (IMSI, MSISDN, IP, Port, Protocol, SSN, GT)
- Handle and process responses from the SS7 stack
- Comprehensive logging and error handling
- Clean, modular, production-ready structure

## Installation

### Prerequisites

- Python 3.7 or later
- SCTP support for your operating system

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/ss7-security-tool.git
cd ss7-security-tool

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .