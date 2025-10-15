from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR
from datetime import datetime
import pytz
from core.logger import log 
from features.rate_limiter import RateLimiter 
from features.geo_blocker import GeoBlocker 
from config.rules_manager import reload_rules_if_changed, print_rules_summary 
import time

# Global State (Biến trạng thái toàn cục)
RULES = {}
LAST_MTIME = 0
PACKET_COUNT = 0
RATE_LIMITER = RateLimiter() 
GEO_BLOCKER = None 

# ========== CẤU HÌNH LỌC LOG MỤC TIÊU (SỬA GIÁ TRỊ NÀY) ==========
TARGET_LOG_SRC_IP = "192.168.100.10" 
EXCLUDED_DST_IPS = ["8.8.8.8", "1.1.1.1"]

def update_global_state(rules, last_mtime, geo_blocker):
    global RULES, LAST_MTIME, GEO_BLOCKER
    RULES = rules
    LAST_MTIME = last_mtime
    GEO_BLOCKER = geo_blocker

# ========== TIME-BASED RULES LOGIC (Hàm dùng chung) ==========
def is_time_in_range(start_time_str, end_time_str, current_time):
    start = datetime.strptime(start_time_str, "%H:%M").time()
    end = datetime.strptime(end_time_str, "%H:%M").time()
    if start <= end:
        return start <= current_time < end
    else:
        return current_time >= start or current_time < end

# Hàm check_time_based_rules() đã được loại bỏ

# ========== HÀM XỬ LÝ PACKET CHÍNH ==========
def process_packet(packet):
    global RULES, LAST_MTIME, PACKET_COUNT, RATE_LIMITER, GEO_BLOCKER
    
    RATE_LIMITER.cleanup_old_data()
    
    PACKET_COUNT += 1
    # Kiểm tra và reload rules 
    if PACKET_COUNT % 5 == 0:
        from config.rules_manager import RULES_FILE 
        from features.geo_blocker import init_geo_blocker 
        
        new_rules, new_mtime = reload_rules_if_changed(RULES_FILE, LAST_MTIME)
        if new_rules:
            RULES = new_rules
            LAST_MTIME = new_mtime
            GEO_BLOCKER = init_geo_blocker(RULES)

    try:
        scapy_packet = IP(packet.get_payload())
        src_ip = scapy_packet[IP].src
        dst_ip = scapy_packet[IP].dst
        protocol = scapy_packet[IP].proto
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"Proto-{protocol}")
        port_info = ""
        dst_port = None
        packet_bytes = len(packet.get_payload())
        
        # ==========================================================
        # ============ LOGIC LỌC GÓI TIN (ĐIỀU KIỆN KÉP) ===========
        # ==========================================================
        is_log_filtered = bool(TARGET_LOG_SRC_IP) 

        if dst_ip in EXCLUDED_DST_IPS:
            packet.accept()
            return
            
        # 2. BƯỚC LỌC THỨ HAI: Chỉ cho phép gói tin từ TARGET_LOG_SRC_IP tiếp tục xử lý
        if is_log_filtered and src_ip != TARGET_LOG_SRC_IP:
            packet.accept()
            return 

        # ... (Khối xác định Port và cờ SYN giữ nguyên) ...

        if scapy_packet.haslayer(TCP):
            dst_port = scapy_packet[TCP].dport
            port_info = f":{dst_port}"
            if scapy_packet[TCP].flags & 0x02: # SYN
                RATE_LIMITER.increment_connection(src_ip)
        elif scapy_packet.haslayer(UDP):
            dst_port = scapy_packet[UDP].dport
            port_info = f":{dst_port}"

        # 1. KIỂM TRA GEO-BLOCKING
        if GEO_BLOCKER:
            geo_config = RULES.get('geo_blocking', {})
            should_block, country, reason = GEO_BLOCKER.should_block(dst_ip, geo_config)
            
            if should_block:
                log(f"[GEO_BLOCKED] {src_ip} → {dst_ip}{port_info} | Country: {country} | {reason}",
                    src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                    action="GEO_BLOCKED", bytes=packet_bytes, reason=reason)
                packet.drop()
                return
            elif country and geo_config.get('log_country_info'):
                if RULES.get('log_all_traffic', False):
                    log(f"[GEO_INFO] {dst_ip} → Country: {country}")


        # 2. KIỂM TRA RATE LIMITING
        rate_limit_config = RULES.get('rate_limiting', {})
        if rate_limit_config.get('enabled'):
            max_pps = rate_limit_config.get('max_packets_per_second', 100)
            if RATE_LIMITER.check_packet_rate(src_ip, max_pps):
                stats = RATE_LIMITER.get_stats(src_ip)
                log(f"[RATE_LIMIT] {src_ip} → {dst_ip}{port_info} | PPS: {stats['pps']} (max: {max_pps})",
                    src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                    action="RATE_LIMIT", bytes=packet_bytes, reason=f"PPS exceeded")
                packet.drop()
                return
            
            max_conn = rate_limit_config.get('max_connections_per_ip', 50)
            if RATE_LIMITER.check_connection_limit(src_ip, max_conn):
                stats = RATE_LIMITER.get_stats(src_ip)
                log(f"[RATE_LIMIT] {src_ip} → {dst_ip}{port_info} | Conn: {stats['connections']} (max: {max_conn})",
                    src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                    action="RATE_LIMIT", bytes=packet_bytes, reason=f"Connection limit exceeded")
                packet.drop()
                return
            
            # GIỮ LẠI LOGIC RATE LIMIT cho DNS
            if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
                max_dns = rate_limit_config.get('max_dns_queries_per_minute', 60)
                if RATE_LIMITER.check_dns_rate(src_ip, max_dns):
                    stats = RATE_LIMITER.get_stats(src_ip)
                    log(f"[RATE_LIMIT] {src_ip} DNS flood | QPM: {stats['qpm']} (max: {max_dns})",
                        src_ip=src_ip, dst_ip=dst_ip, protocol="DNS", port=dst_port,
                        action="RATE_LIMIT", bytes=packet_bytes, reason="DNS flood")
                    packet.drop()
                    return

        # 3. ALLOWED IPS
        for allowed_ip in RULES.get('allowed_ips', []):
            if dst_ip.startswith(allowed_ip):
                if RULES.get('log_all_traffic', False):
                    log(f"[ALLOW] {proto_name} {src_ip} → {dst_ip}{port_info} (Whitelisted)",
                        src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                        action="ALLOW", bytes=packet_bytes, reason="Whitelisted")
                packet.accept()
                return
                
        # ==========================================================
        # 3.5. KIỂM TRA TIME-BASED RULE CHO IP ĐÍCH (DEMO PING/ICMP)
        # ==========================================================
        time_based_config = RULES.get('time_based_rules', {})
        
        if time_based_config.get('enabled'):
            timezone_str = time_based_config.get('timezone', 'UTC')
            try:
                tz = pytz.timezone(timezone_str)
            except:
                tz = pytz.UTC

            now = datetime.now(tz)
            current_day = now.strftime("%A").lower()
            current_time = now.time()

            for rule in time_based_config.get('rules', []):
                # CHỈ XỬ LÝ rule CÓ 'action': 'block_ip_time'
                if rule.get('action') == 'block_ip_time':
                    
                    target_ips = rule.get('target_ips', [])
                    # Đảm bảo rule này chỉ áp dụng nếu có target_ips
                    if not target_ips or not any(dst_ip.startswith(ip) for ip in target_ips):
                        continue

                    if current_day not in rule.get('days', []):
                        continue
                    if not is_time_in_range(rule['start_time'], rule['end_time'], current_time):
                        continue
                    
                    log(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}{port_info} (Time-based IP Block)",
                        src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                        action="BLOCKED", bytes=packet_bytes, reason="Time-based IP Block")
                    packet.drop()
                    return 

        # 4. BLOCK ICMP (Logic chặn ICMP cố định)
        if RULES.get('block_icmp', False) and scapy_packet.haslayer(ICMP):
            log(f"[BLOCKED] ICMP {src_ip} → {dst_ip} (ICMP blocked)",
                src_ip=src_ip, dst_ip=dst_ip, protocol="ICMP", port=None,
                action="BLOCKED", bytes=packet_bytes, reason="ICMP blocked")
            packet.drop()
            return
            
        # 5. DNS QUERIES
        if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
            queried_domain = scapy_packet[DNSQR].qname.decode('utf-8').lower()
            
            # Khối DNS hiện tại chỉ còn lại logic Rate Limiting và Logging.
            # Không có Blocked/Allowed Domains cố định nào được kiểm tra.
            if RULES.get('log_all_traffic', False):
                log(f"[PASS] DNS {src_ip} → {queried_domain.strip('.')}",
                    src_ip=src_ip, dst_ip=queried_domain.strip('.'), protocol="DNS", port=dst_port,
                    action="PASS", bytes=packet_bytes, reason="")


        # 6. BLOCKED IPS (Sẽ chứa các IP chặn Facebook/YouTube cố định)
        if dst_ip.startswith(tuple(RULES.get('blocked_ips', []))): 
            log(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}{port_info} (IP blocked)",
                src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                action="BLOCKED", bytes=packet_bytes, reason="IP blocked")
            packet.drop()
            return

        # 7. BLOCKED PORTS
        if dst_port and dst_port in RULES.get('blocked_ports', []):
            log(f"[BLOCKED] {proto_name} {src_ip} → {dst_ip}:{dst_port} (Port blocked)",
                src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                action="BLOCKED", bytes=packet_bytes, reason="Port blocked")
            packet.drop()
            return

        # 8. ACCEPT (Default Policy)
        if RULES.get('log_all_traffic', False):
            log(f"[PASS] {proto_name} {src_ip} → {dst_ip}{port_info}",
                src_ip=src_ip, dst_ip=dst_ip, protocol=proto_name, port=dst_port,
                action="PASS", bytes=packet_bytes, reason="")

        packet.accept()
        
    except Exception as e:
        log(f"[ERROR] {e}")
        packet.accept()