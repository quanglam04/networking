from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP

# Định nghĩa rule
BLOCK_IP = "192.168.1.100"
BLOCK_PORT = 22  # SSH

def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())  # parse packet thành IP object
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    proto = scapy_pkt.proto

    verdict = "ACCEPT"

    # Rule 1: Block theo IP
    if src_ip == BLOCK_IP:
        verdict = "DROP"
        packet.drop()
    # Rule 2: Block theo port TCP
    elif proto == 6 and scapy_pkt.haslayer(TCP):  # 6 = TCP
        dport = scapy_pkt[TCP].dport
        if dport == BLOCK_PORT:
            verdict = "DROP"
            packet.drop()
        else:
            packet.accept()
    else:
        packet.accept()

    print(f"[{verdict}] {src_ip} -> {dst_ip} (proto={proto})")

def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process_packet)  # lắng nghe queue số 0
    try:
        print("Firewall đang chạy... Nhấn Ctrl+C để dừng.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping firewall...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
