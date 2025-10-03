#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR
import os
import sys
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import pytz
import time


# ========== RATE LIMITING CLASS ==========
class RateLimiter:
    def __init__(self):
        self.packet_counter = defaultdict(list)      # IP -> [timestamps]
        self.connection_counter = defaultdict(int)   # IP -> số connections
        self.dns_queries = defaultdict(list)         # IP -> [timestamps]
        self.cleanup_interval = 60
        self.last_cleanup = time.time()
    
    def cleanup_old_data(self):
        """Xóa dữ liệu cũ để tránh memory leak"""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        # Cleanup packet counter (giữ lại 1 giây)
        for ip in list(self.packet_counter.keys()):
            self.packet_counter[ip] = [t for t in self.packet_counter[ip] if current_time - t < 1]
            if not self.packet_counter[ip]:
                del self.packet_counter[ip]
        
        # Cleanup DNS queries (giữ lại 60 giây)
        for ip in list(self.dns_queries.keys()):
            self.dns_queries[ip] = [t for t in self.dns_queries[ip] if current_time - t < 60]
            if not self.dns_queries[ip]:
                del self.dns_queries[ip]
        
        self.last_cleanup = current_time
    
    def check_packet_rate(self, ip, max_pps):
        """Kiểm tra số packets per second từ một IP"""
        current_time = time.time()
        
        # Lọc timestamps trong 1 giây qua
        self.packet_counter[ip] = [t for t in self.packet_counter[ip] if current_time - t < 1]
        
        # Thêm timestamp hiện tại
        self.packet_counter[ip].append(current_time)
        
        # Kiểm tra vượt ngưỡng
        return len(self.packet_counter[ip]) > max_pps
    
    def check_dns_rate(self, ip, max_queries_per_minute):
        """Kiểm tra số DNS queries per minute từ một IP"""
        current_time = time.time()
        
        # Lọc timestamps trong 60 giây qua
        self.dns_queries[ip] = [t for t in self.dns_queries[ip] if current_time - t < 60]
        
        # Thêm timestamp hiện tại
        self.dns_queries[ip].append(current_time)
        
        # Kiểm tra vượt ngưỡng
        return len(self.dns_queries[ip]) > max_queries_per_minute
    
    def increment_connection(self, ip):
        """Tăng số connection từ một IP"""
        self.connection_counter[ip] += 1
    
    def check_connection_limit(self, ip, max_connections):
        """Kiểm tra số connections từ một IP"""
        return self.connection_counter[ip] > max_connections
    
    def get_stats(self, ip):
        """Lấy thống kê rate limiting cho một IP"""
        current_time = time.time()
        
        # Packets per second
        recent_packets = [t for t in self.packet_counter.get(ip, []) if current_time - t < 1]
        pps = len(recent_packets)
        
        # DNS queries per minute
        recent_dns = [t for t in self.dns_queries.get(ip, []) if current_time - t < 60]
        qpm = len(recent_dns)
        
        # Connections
        connections = self.connection_counter.get(ip, 0)
        
        return {
            'pps': pps,
            'qpm': qpm,
            'connections': connections
        }


# ========== HÀM LOG CÓ THỜI GIAN ==========
def log(msg):
    tz = pytz.timezone("Asia/Ho_Chi_Minh")
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {msg}")


# ========== ĐỌC RULES TỪ FILE JSON ==========
def load_rules(rules_file="rules.json"):
    """Đọc rules từ file JSON"""
    try:
        script_dir = Path(__file__).parent
        rules_path = script_dir / rules_file

        if not rules_path.exists():
            log(f"[!] Không tìm thấy file: {rules_path}")
            log("[!] Tạo file rules.json mẫu...")
            create_default_rules(rules_path)
            return load_rules(rules_file)

        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)

        log(f"[✓] Đã load rules từ: {rules_path}")
        return rules

    except json.JSONDecodeError as e:
        log(f"[!] Lỗi format JSON: {e}")
        log("[!] Kiểm tra lại file rules.json")
        sys.exit(1)

    except Exception as e:
        log(f"[!] Lỗi đọc file rules: {e}")
        sys.exit(1)


def create_default_rules(rules_path):
    """Tạo file rules.json mẫu"""
    default_rules = {
        "blocked_domains": ["facebook.com", "tiktok.com"],
        "blocked_ips": ["31.13."],
        "blocked_ports": [],
        "allowed_ips": [],
        "allowed_domains": [],
        "log_all_traffic": False,
        "block_icmp": False,
        "rate_limiting": {
            "enabled": True,
            "max_packets_per_second": 100,
            "max_connections_per_ip": 50,
            "max_dns_queries_per_minute": 60,
            "action": "drop"
        },
        "time_based_rules": {
            "enabled": True,
            "timezone": "Asia/Ho_Chi_Minh",
            "rules": [
                {
                    "name": "Block social media during work hours",
                    "domains": ["facebook.com"],
                    "days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
                    "start_time": "08:00",
                    "end_time": "17:00",
                    "action": "block"
                }
            ]
        }
    }

    try:
        with open(rules_path, 'w', encoding='utf-8') as f:
            json.dump(default_rules, f, indent=2, ensure_ascii=False)
        log(f"[✓] Đã tạo file mẫu: {rules_path}")
    except Exception as e:
        log(f"[!] Không thể tạo file: {e}")
        sys.exit(1)


def reload_rules_if_changed(rules_file, last_mtime):
    """Kiểm tra và reload rules nếu file thay đổi"""
    try:
        script_dir = Path(__file__).parent
        rules_path = script_dir / rules_file
        current_mtime = rules_path.stat().st_mtime

        if current_mtime != last_mtime:
            log("[*] Phát hiện thay đổi rules, đang reload...")
            rules = load_rules(rules_file)
            print_rules_summary(rules)
            return rules, current_mtime

        return None, last_mtime

    except Exception as e:
        log(f"[!] Lỗi kiểm tra file: {e}")
        return None, last_mtime


def print_rules_summary(rules):
    """In tóm tắt rules"""
    log("=" * 70)
    log(" RULES HIỆN TẠI")
    log("=" * 70)

    log(f"Blocked Domains ({len(rules.get('blocked_domains', []))}): " +
        (", ".join(rules.get('blocked_domains', [])) if rules.get('blocked_domains') else "None"))

    log(f"Blocked IPs ({len(rules.get('blocked_ips', []))}): " +
        (", ".join(rules.get('blocked_ips', [])) if rules.get('blocked_ips') else "None"))

    log(f"Blocked Ports ({len(rules.get('blocked_ports', []))}): " +
        (", ".join(map(str, rules.get('blocked_ports', []))) if rules.get('blocked_ports') else "None"))

    log(f"Block ICMP: {'Yes' if rules.get('block_icmp') else 'No'}")
    log(f"Log All Traffic: {'Yes' if rules.get('log_all_traffic') else 'No'}")

    # Rate limiting summary
    rate_limit = rules.get('rate_limiting', {})
    if rate_limit.get('enabled'):
        log(f"Rate Limiting: Enabled")
        log(f"  Max Packets/Second: {rate_limit.get('max_packets_per_second', 100)}")
        log(f"  Max Connections/IP: {rate_limit.get('max_connections_per_ip', 50)}")
        log(f"  Max DNS Queries/Minute: {rate_limit.get('max_dns_queries_per_minute', 60)}")
        log(f"  Action: {rate_limit.get('action', 'drop').upper()}")
    else:
        log("Rate Limiting: Disabled")

    # Time-based rules summary
    time_rules = rules.get('time_based_rules', {})
    if time_rules.get('enabled'):
        log(f"Time-based Rules: Enabled ({len(time_rules.get('rules', []))} rules)")
        log(f"Timezone: {time_rules.get('timezone', 'UTC')}")
        for idx, rule in enumerate(time_rules.get('rules', []), 1):
            log(f"  {idx}. {rule['name']}")
            log(f"     Days: {', '.join(rule['days'])}")
            log(f"     Time: {rule['start_time']} - {rule['end_time']}")
            log(f"     Action: {rule['action'].upper()}")
            log(f"     Domains: {', '.join(rule['domains'])}")
    else:
        log("Time-based Rules: Disabled")

    log("=" * 70)


# ========== TIME-BASED RULES LOGIC ==========
def is_time_in_range(start_time_str, end_time_str, current_time):
    """Kiểm tra xem thời gian hiện tại có nằm trong khoảng không"""
    start = datetime.strptime(start_time_str, "%H:%M").time()
    end = datetime.strptime(end_time_str, "%H:%M").time()

    if start <= end:
        return start <= current_time <= end
    else:
        return current_time >= start or current_time <= end


def check_time_based_rules(domain, rules):
    time_rules_config = rules.get('time_based_rules', {})
    if not time_rules_config.get('enabled'):
        return None

    timezone_str = time_rules_config.get('timezone', 'UTC')
    try:
        tz = pytz.timezone(timezone_str)
    except:
        tz = pytz.UTC

    now = datetime.now(tz)
    current_day = now.strftime("%A").lower()
    current_time = now.time()

    for rule in time_rules_config.get('rules', []):
        if not any(r in domain for r in rule.get('domains', [])):
            continue
        if current_day not in rule.get('days', []):
            continue
        if not is_time_in_range(rule['start_time'], rule['end_time'], current_time):
            continue
        return rule.get('action', 'block')

    return None


# ========== BIẾN TOÀN CỤC ==========
RULES = {}
RULES_FILE = "rules.json"
LAST_MTIME = 0
PACKET_COUNT = 0
RATE_LIMITER = RateLimiter()


# ========== HÀM XỬ LÝ PACKET ==========
def process_packet(packet):
    global RULES, LAST_MTIME, PACKET_COUNT, RATE_LIMITER
    
    # Cleanup old data định kỳ
    RATE_LIMITER.cleanup_old_data()
    
    # Kiểm tra và reload rules nếu file thay đổi
    PACKET_COUNT += 1
    if PACKET_COUNT % 5  == 0:
        new_rules, new_mtime = reload_rules_if_changed(RULES_FILE, LAST_MTIME)
        if new_rules:
            RULES = new_rules
            LAST_MTIME = new_mtime

    try:
        scapy_packet = IP(packet.get_payload())
        src_ip = scapy_packet[IP].src
        dst_ip = scapy_packet[IP].dst
        protocol = scapy_packet[IP].proto
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"Proto-{protocol}")
        port_info = ""
        dst_port = None

        if scapy_packet.haslayer(TCP):
            dst_port = scapy_packet[TCP].dport
            port_info = f":{dst_port}"
            # Track TCP SYN connections
            if scapy_packet[TCP].flags & 0x02:  # SYN flag
                RATE_LIMITER.increment_connection(src_ip)
        elif scapy_packet.haslayer(UDP):
            dst_port = scapy_packet[UDP].dport
            port_info = f":{dst_port}"

        # ========== KIỂM TRA RATE LIMITING (ƯU TIÊN CAO) ==========
        rate_limit_config = RULES.get('rate_limiting', {})
        
        if rate_limit_config.get('enabled'):
            # Kiểm tra packet rate
            max_pps = rate_limit_config.get('max_packets_per_second', 100)
            if RATE_LIMITER.check_packet_rate(src_ip, max_pps):
                stats = RATE_LIMITER.get_stats(src_ip)
                log(f"[RATE_LIMIT] {src_ip} → {dst_ip}{port_info} | PPS: {stats['pps']} (limit: {max_pps})")
                packet.drop()
                return
            
            # Kiểm tra connection limit
            max_conn = rate_limit_config.get('max_connections_per_ip', 50)
            if RATE_LIMITER.check_connection_limit(src_ip, max_conn):
                stats = RATE_LIMITER.get_stats(src_ip)
                log(f"[RATE_LIMIT] {src_ip} → {dst_ip}{port_info} | Connections: {stats['connections']} (limit: {max_conn})")
                packet.drop()
                return
            
            # Kiểm tra DNS query rate
            if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
                max_dns = rate_limit_config.get('max_dns_queries_per_minute', 60)
                if RATE_LIMITER.check_dns_rate(src_ip, max_dns):
                    stats = RATE_LIMITER.get_stats(src_ip)
                    log(f"[RATE_LIMIT] {src_ip} DNS flood | QPM: {stats['qpm']} (limit: {max_dns})")
                    packet.drop()
                    return

        # ========== KIỂM TRA ALLOWED IPS ==========
        for allowed_ip in RULES.get('allowed_ips', []):
            if dst_ip.startswith(allowed_ip):
                if RULES.get('log_all_traffic', False):
                    log(f"[ALLOW] {proto_name} {src_ip} → {dst_ip}{port_info} (Whitelisted IP)")
                packet.accept()
                return

        # ========== KIỂM TRA BLOCK ICMP ==========
        if RULES.get('block_icmp', False) and scapy_packet.haslayer(ICMP):
            log(f"[BLOCKED] ICMP {src_ip} → {dst_ip} (ICMP blocked)")
            packet.drop()
            return

        # ========== XỬ LÝ DNS QUERIES ==========
        if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
            queried_domain = scapy_packet[DNSQR].qname.decode('utf-8').lower()
            
            # Kiểm tra time-based rules
            time_action = check_time_based_rules(queried_domain, RULES)
            if time_action == "block":
                log(f"[BLOCKED] DNS {src_ip} → {queried_domain.strip('.')} (Time-based rule)")
                packet.drop()
                return
            elif time_action == "allow":
                log(f"[ALLOW] DNS {src_ip} → {queried_domain.strip('.')} (Time-based allow)")
                packet.accept()
                return
            
            # Kiểm tra allowed domains
            for allowed in RULES.get('allowed_domains', []):
                if allowed in queried_domain:
                    if RULES.get('log_all_traffic', False):
                        log(f"[ALLOW] DNS {src_ip} → {queried_domain.strip('.')} (Whitelisted)")
                    packet.accept()
                    return
            
            # Kiểm tra blocked domains
            for blocked in RULES.get('blocked_domains', []):
                if blocked in queried_domain:
                    log(f"[BLOCKED] DNS {src_ip} → {queried_domain.strip('.')} (Domain blocked)")
                    packet.drop()
                    return

        # ========== KIỂM TRA BLOCKED IPS ==========
        for blocked_ip in RULES.get('blocked_ips', []):
            if dst_ip.startswith(blocked_ip):
                log(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}{port_info} (IP blocked)")
                packet.drop()
                return

        # ========== KIỂM TRA BLOCKED PORTS ==========
        if dst_port and dst_port in RULES.get('blocked_ports', []):
            log(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}:{dst_port} (Port blocked)")
            packet.drop()
            return

        # ========== ACCEPT: Cho qua nếu không vi phạm ==========
        if RULES.get('log_all_traffic', False):
            log(f"[PASS] {proto_name} {src_ip} → {dst_ip}{port_info}")

        packet.accept()
        
    except Exception as e:
        log(f"[ERROR] {e}")
        packet.accept()


# ========== MAIN ==========
def main():
    global RULES, LAST_MTIME

    if os.geteuid() != 0:
        log("[!] Script phải chạy với quyền root!")
        log("Chạy: sudo python3 firewall.py")
        sys.exit(1)

    log("=" * 70)
    log(" PYTHON FIREWALL - VM ROUTER (Rate Limiting + Time-based Rules)")
    log("=" * 70)
    log("[*] Đang khởi động...")

    RULES = load_rules(RULES_FILE)
    try:
        script_dir = Path(__file__).parent
        rules_path = script_dir / RULES_FILE
        LAST_MTIME = rules_path.stat().st_mtime
    except:
        LAST_MTIME = 0

    print_rules_summary(RULES)

    queue = NetfilterQueue()
    queue.bind(0, process_packet)

    log("[*] Firewall đã sẵn sàng!")
    log(f"[*] Đang theo dõi file: {RULES_FILE}")
    log("[*] Sửa file rules.json và lưu lại để reload rules tự động")
    log("[*] Nhấn Ctrl+C để dừng")
    log("-" * 70)

    try:
        queue.run()
    except KeyboardInterrupt:
        log("-" * 70)
        log("[*] Đang dừng firewall...")
    finally:
        queue.unbind()
        log("[*] Đã dừng!")


if __name__ == "__main__":
    main()
