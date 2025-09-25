import json
import time
import threading
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

rules = {}

def load_rules():
    global rules
    try:
        with open("rules.json", "r") as f:
            rules = json.load(f)
    except Exception as e:
        print("[ERROR] Could not load rules.json:", e)

# Thread để reload rules.json định kỳ
def auto_reload(interval=5):
    while True:
        load_rules()
        time.sleep(interval)

def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    proto = scapy_pkt.proto

    verdict = "ACCEPT"

    # Rule 1: Block theo IP nguồn
    if src_ip in rules.get("block_ip", []):
        verdict = "DROP (src_ip)"
        packet.drop()
    # Rule 2: Block theo port đích TCP
    elif proto == 6 and scapy_pkt.haslayer(TCP):
        dport = scapy_pkt[TCP].dport
        if dport in rules.get("block_dst_port", []):
            verdict = f"DROP (dport={dport})"
            packet.drop()
        else:
            packet.accept()
    else:
        packet.accept()

    print(f"[{verdict}] {src_ip} -> {dst_ip} (proto={proto})")

def main():
    # Khởi động thread reload rules
    threading.Thread(target=auto_reload, daemon=True).start()

    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process_packet)
    try:
        print("Firewall đang chạy... Nhấn Ctrl+C để dừng.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping firewall...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
