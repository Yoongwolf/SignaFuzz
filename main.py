# main.py

from app.core import Ss7Tool

def get_user_input():
    print("=== SS7 Security Research Tool ===")
    config = {
        "imsi": input("Enter IMSI: "),
        "msisdn": input("Enter MSISDN: "),
        "target_ip": input("Enter Target Network IP: "),
        "target_port": input("Enter Target Port: "),
        "protocol": input("Enter Protocol (SCTP/TCP): "),
        "ssn": input("Enter SSN: "),
        "gt": input("Enter Global Title (GT): "),
    }
    return config

def main():
    config = get_user_input()
    tool = Ss7Tool(config)
    tool.send_message()
    tool.handle_response()

if __name__ == "__main__":
    main()
