from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR
import os
import sys
import json
from pathlib import Path

# ========== ĐỌC RULES TỪ FILE JSON ==========

def load_rules(rules_file="rules.json"):
    """Đọc rules từ file JSON"""
    try:
        # Tìm file rules.json trong cùng thư mục với script
        script_dir = Path(__file__).parent
        rules_path = script_dir / rules_file
        
        if not rules_path.exists():
            print(f"[!] Không tìm thấy file: {rules_path}")
            print("[!] Tạo file rules.json mẫu...")
            create_default_rules(rules_path)
            return load_rules(rules_file)
        
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        print(f"[✓] Đã load rules từ: {rules_path}")
        return rules
    
    except json.JSONDecodeError as e:
        print(f"[!] Lỗi format JSON: {e}")
        print("[!] Kiểm tra lại file rules.json")
        sys.exit(1)
    
    except Exception as e:
        print(f"[!] Lỗi đọc file rules: {e}")
        sys.exit(1)


def create_default_rules(rules_path):
    """Tạo file rules.json mẫu"""
    default_rules = {
        "blocked_domains": [
            "facebook.com",
            "tiktok.com"
        ],
        "blocked_ips": [
            "31.13."
        ],
        "blocked_ports": [],
        "allowed_ips": [],
        "allowed_domains": [],
        "log_all_traffic": False,
        "block_icmp": False
    }
    
    try:
        with open(rules_path, 'w', encoding='utf-8') as f:
            json.dump(default_rules, f, indent=2, ensure_ascii=False)
        print(f"[✓] Đã tạo file mẫu: {rules_path}")
    except Exception as e:
        print(f"[!] Không thể tạo file: {e}")
        sys.exit(1)


def reload_rules_if_changed(rules_file, last_mtime):
    """Kiểm tra và reload rules nếu file thay đổi"""
    try:
        script_dir = Path(__file__).parent
        rules_path = script_dir / rules_file
        current_mtime = rules_path.stat().st_mtime
        
        if current_mtime != last_mtime:
            print("\n[*] Phát hiện thay đổi rules, đang reload...")
            rules = load_rules(rules_file)
            print_rules_summary(rules)
            return rules, current_mtime
        
        return None, last_mtime
    
    except Exception as e:
        print(f"[!] Lỗi kiểm tra file: {e}")
        return None, last_mtime


def print_rules_summary(rules):
    """In tóm tắt rules"""
    print("\n" + "=" * 70)
    print(" RULES HIỆN TẠI")
    print("=" * 70)
    
    print(f"Blocked Domains ({len(rules.get('blocked_domains', []))}): ", end="")
    print(", ".join(rules.get('blocked_domains', [])) if rules.get('blocked_domains') else "None")
    
    print(f"Blocked IPs ({len(rules.get('blocked_ips', []))}): ", end="")
    print(", ".join(rules.get('blocked_ips', [])) if rules.get('blocked_ips') else "None")
    
    print(f"Blocked Ports ({len(rules.get('blocked_ports', []))}): ", end="")
    print(", ".join(map(str, rules.get('blocked_ports', []))) if rules.get('blocked_ports') else "None")
    
    print(f"Block ICMP: {'Yes' if rules.get('block_icmp') else 'No'}")
    print(f"Log All Traffic: {'Yes' if rules.get('log_all_traffic') else 'No'}")
    
    print("=" * 70 + "\n")


# ========== BIẾN TOÀN CỤC ==========

RULES = {}
RULES_FILE = "rules.json"
LAST_MTIME = 0
PACKET_COUNT = 0


# ========== HÀM XỬ LÝ PACKET ==========

def process_packet(packet):
    global RULES, LAST_MTIME, PACKET_COUNT
    
    # Kiểm tra và reload rules nếu file thay đổi (mỗi 5 packets)
    PACKET_COUNT += 1
    if PACKET_COUNT % 5 == 0:
        new_rules, new_mtime = reload_rules_if_changed(RULES_FILE, LAST_MTIME)
        if new_rules:
            RULES = new_rules
            LAST_MTIME = new_mtime
    
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
        dst_port = None
        
        if scapy_packet.haslayer(TCP):
            dst_port = scapy_packet[TCP].dport
            port_info = f":{dst_port}"
        elif scapy_packet.haslayer(UDP):
            dst_port = scapy_packet[UDP].dport
            port_info = f":{dst_port}"
        
        # ========== KIỂM TRA ALLOWED (ƯU TIÊN CAO) ==========
        
        # Cho phép IP trong whitelist
        for allowed_ip in RULES.get('allowed_ips', []):
            if dst_ip.startswith(allowed_ip):
                if RULES.get('log_all_traffic', False):
                    print(f"[ALLOW] {proto_name} {src_ip} → {dst_ip}{port_info} (Whitelisted IP)")
                packet.accept()
                return
        
        # ========== KIỂM TRA BLOCKED ==========
        
        # Rule: Chặn ICMP (nếu enabled)
        if RULES.get('block_icmp', False) and scapy_packet.haslayer(ICMP):
            print(f"[BLOCKED] ICMP {src_ip} → {dst_ip} (ICMP blocked)")
            packet.drop()
            return
        
        # Rule: Chặn DNS queries cho domain bị chặn
        if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
            queried_domain = scapy_packet[DNSQR].qname.decode('utf-8').lower()
            
            # Kiểm tra allowed domains trước
            for allowed in RULES.get('allowed_domains', []):
                if allowed in queried_domain:
                    if RULES.get('log_all_traffic', False):
                        print(f"[ALLOW] DNS {src_ip} → {queried_domain.strip('.')} (Whitelisted)")
                    packet.accept()
                    return
            
            # Kiểm tra blocked domains
            for blocked in RULES.get('blocked_domains', []):
                if blocked in queried_domain:
                    print(f"[BLOCKED] DNS {src_ip} → {queried_domain.strip('.')} (Domain blocked)")
                    packet.drop()
                    return
        
        # Rule: Chặn IP bị chặn
        for blocked_ip in RULES.get('blocked_ips', []):
            if dst_ip.startswith(blocked_ip):
                print(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}{port_info} (IP blocked)")
                packet.drop()
                return
        
        # Rule: Chặn port cụ thể
        if dst_port and dst_port in RULES.get('blocked_ports', []):
            print(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}:{dst_port} (Port blocked)")
            packet.drop()
            return
        
        # ========== ACCEPT: Cho qua nếu không vi phạm ==========
        
        if RULES.get('log_all_traffic', False):
            print(f"[PASS] {proto_name} {src_ip} → {dst_ip}{port_info}")
        
        packet.accept()
        
    except Exception as e:
        print(f"[ERROR] {e}")
        packet.accept()  # Khi lỗi, cho qua để tránh gián đoạn


# ========== MAIN ==========

def main():
    global RULES, LAST_MTIME
    
    # Kiểm tra quyền root
    if os.geteuid() != 0:
        print("[!] Script phải chạy với quyền root!")
        print("Chạy: sudo python3 firewall.py")
        sys.exit(1)
    
    print("=" * 70)
    print(" PYTHON FIREWALL - VM ROUTER (JSON Rules)")
    print("=" * 70)
    print("[*] Đang khởi động...")
    
    # Load rules từ JSON
    RULES = load_rules(RULES_FILE)
    
    # Lưu mtime để phát hiện thay đổi
    try:
        script_dir = Path(__file__).parent
        rules_path = script_dir / RULES_FILE
        LAST_MTIME = rules_path.stat().st_mtime
    except:
        LAST_MTIME = 0
    
    # In tóm tắt rules
    print_rules_summary(RULES)
    
    # Bind với NFQUEUE
    queue = NetfilterQueue()
    queue.bind(0, process_packet)
    
    print("[*] Firewall đã sẵn sàng!")
    print(f"[*] Đang theo dõi file: {RULES_FILE}")
    print("[*] Sửa file rules.json và lưu lại để reload rules tự động")
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
