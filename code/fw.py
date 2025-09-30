from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR
import os
import sys

# ========== CẤU HÌNH RULES ==========

# Danh sách domain bị chặn
BLOCKED_DOMAINS = [
    "facebook.com",
    "tiktok.com",
]

# Danh sách IP bị chặn
BLOCKED_IPS = [
    "31.13.",  # Facebook IP range
]

# Danh sách port bị chặn
BLOCKED_PORTS = [
    # 22,  # SSH (uncomment để chặn)
]

# ========== HÀM XỬ LÝ PACKET ==========

def process_packet(packet):
    try:
        scapy_packet = IP(packet.get_payload())
        
        # Lấy thông tin cơ bản
        src_ip = scapy_packet[IP].src
        dst_ip = scapy_packet[IP].dst
        protocol = scapy_packet[IP].proto
        
        # Xác định protocol name
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"Proto-{protocol}")
        
        # Lấy port info nếu có
        port_info = ""
        if scapy_packet.haslayer(TCP):
            dst_port = scapy_packet[TCP].dport
            port_info = f":{dst_port}"
            
            # Rule: Chặn port cụ thể
            if dst_port in BLOCKED_PORTS:
                print(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}:{dst_port} (Port blocked)")
                packet.drop()
                return
                
        elif scapy_packet.haslayer(UDP):
            dst_port = scapy_packet[UDP].dport
            port_info = f":{dst_port}"
        
        # Rule: Chặn DNS queries cho domain bị chặn
        if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
            queried_domain = scapy_packet[DNSQR].qname.decode('utf-8').lower()
            
            for blocked in BLOCKED_DOMAINS:
                if blocked in queried_domain:
                    print(f"[BLOCKED] DNS {src_ip} → {queried_domain.strip('.')} (Domain blocked)")
                    packet.drop()
                    return
        
        # Rule: Chặn IP bị chặn
        for blocked_ip in BLOCKED_IPS:
            if dst_ip.startswith(blocked_ip):
                print(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}{port_info} (IP blocked)")
                packet.drop()
                return
        
        # ACCEPT: Cho qua nếu không vi phạm rules
        print(f"[PASS] {proto_name} {src_ip} → {dst_ip}{port_info}")
        packet.accept()
        
    except Exception as e:
        print(f"[ERROR] {e}")
        packet.accept()  # Khi lỗi, cho qua để tránh gián đoạn

# ========== MAIN ==========

def main():
    # Kiểm tra quyền root
    if os.geteuid() != 0:
        print("[!] Script phải chạy với quyền root!")
        print("Chạy: sudo python3 firewall.py")
        sys.exit(1)
    
    print("=" * 70)
    print(" PYTHON FIREWALL - VM ROUTER")
    print("=" * 70)
    print("[*] Đang khởi động...")
    
    # Bind với NFQUEUE
    queue = NetfilterQueue()
    queue.bind(0, process_packet)
    
    print("[*] Firewall đã sẵn sàng!")
    print("[*] Nhấn Ctrl+C để dừng\n")
    print("-" * 70)
    
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n" + "-" * 70)
        print("[*] Đang dừng firewall...")
    finally:
        queue.unbind()
        print("[*] Đã dừng!")

if __name__ == "__main__":
    main()
