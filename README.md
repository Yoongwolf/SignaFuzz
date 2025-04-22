# SS7 Security Research Tool

A Python-based backend tool for SS7 security research and testing in controlled laboratory environments, developed for Nokia.

---

## 🚀 Features

- Send customized **MAP-layer SS7 messages** to target networks over SCTP.
- Supported MAP operations:
  - ✅ **SendRoutingInfo (SRI)** – Fully implemented
  - 🟡 **AnyTimeInterrogation (ATI)** – Partially implemented
  - 🟡 **UpdateLocation (UL)** – Partially implemented
  - 🟡 **ProvideSubscriberInfo (PSI)** – Partially implemented
- Accept dynamic inputs:
  - **IMSI**, **MSISDN**, target **IP/port**, **SSN**, **Global Title (GT)**, **protocol (SCTP/TCP)**
- Process and parse SS7 responses (partial support for IMSI/MSISDN extraction)
- Comprehensive logging of operations and errors to file: `logs/ss7_tool.log`
- API key authentication for secure access
- Input validation for IMSI, MSISDN, GT, SSN, IP, and port
- Modular, production-ready structure with unit and integration tests
- CLI and interactive modes for operation execution

---

## 🛠 Installation

### ✅ Prerequisites

- **Operating System:** Ubuntu (tested on Ubuntu with Python 3.10)
- **Python:** 3.7 or later
- **SCTP Support:** Ensure `libsctp-dev` is installed:
  
  ```bash
  sudo apt-get install libsctp-dev
