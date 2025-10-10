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
import geoip2.database
import geoip2.errors
import logging
import logging.handlers

# ========== ADVANCED LOGGING ==========
class JsonFormatter(logging.Formatter):
    def __init__(self, fields=None, datefmt=None):
        super().__init__(datefmt=datefmt) # Kế thừ từ lớp logging.Formatter

        # Lưu lại danh sách các trường được hiển thị (trong file rules.json - log_fields)
        self.fields = fields
    
    def format(self, record):
        # Tạo 1 object log đầy đủ với các thông tin
        full_log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage()
        }

        # Nếu có các extra_info, sẽ merge lại chung tạo JSON sau này tùy chỉnh ruless.json
        if hasattr(record, 'extra_info'):
            full_log_object.update(record.extra_info)
        
        # Nếu trong ruless.json không có log_fields, trả về json full log
        if not self.fields:
            return json.dumps(full_log_object, ensure_ascii=False)

        # Nếu có log_field, trả về các field y/cầu
        filtered_log_object = {}
        for field in self.fields:
            if field in full_log_object:
                filtered_log_object[field] = full_log_object[field]
            
        return json.dumps(filtered_log_object, ensure_ascii=False)
    
class LoggingManager:
    def __init__(self, rules):
        self.rules = rules
        self.setup_logging()
    
    def setup_logging(self):
        if not self.rules.get('enabled', False):
            logging.disable(logging.CRITICAL) # Tắt tất cả các log_level <= CRITICAL
            return

        # Bật lại logging (không giữ cấu ình disable từ lần trước)
        logging.disable(logging.NOTSET)
        
        # Lấy root logger, nếu có sẵn trước đó thì xóa hết cái cũ để tránh tạo double logger (.clear)
        logger = logging.getLogger()
        if logger.hasHandlers():
            logger.handlers.clear()

        # CHỉ xử lý các record có mức >= level này
        log_level_str = self.rules.get('log_level', 'info').lower()
        log_level = getattr(logging, log_level_str, logging.info)
        logger.setLevel(log_level)

        log_format = self.rules.get('log_format', 'text')
        log_fields = self.rules.get('log_fields') # Lấy danh sách fields từ rules

        if log_format == 'json':
            formatter = JsonFormatter(
                fields=log_fields, 
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

        # Luôn log ra console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if self.rules.get('log_to_file', False):
            log_file = self.rules.get('log_file', '/var/log/firewall.log')
            max_bytes = self.rules.get('max_log_size_mb', 100) * 1024 * 1024
            
            try:
                if self.rules.get('log_rotation', False):
                    file_handler = logging.handlers.RotatingFileHandler(
                        log_file, maxBytes=max_bytes, backupCount=5, encoding='utf-8'
                    )
                else:
                    file_handler = logging.FileHandler(log_file, encoding='utf-8')
                
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                print(f"[ERROR] Không thể tạo file log tại {log_file}: {e}")

        logging.info("Hệ thống logging đã được cấu hình.", extra={'extra_info': {'component': 'LoggingManager'}})

# ========== HÀM LOG ==========
def log(msg):
    tz = pytz.timezone("Asia/Ho_Chi_Minh")
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {msg}")


def log_event(level, message, **extra_fields):

    # ========== Giải thích chút về "**extra_fields" ==========
    """
    - Tính năng mạnh mẽ của Python - Keyword Arguments - kwargs
    - Hàm này có hai tham số bắt buộc là level và message.
      Ngoài ra, nếu người dùng truyền vào bất kỳ tham số nào khác có tên (ví dụ: component=..., src_ip=..., action=...),
      tự động gom tất cả lại và thành một dictionary tên là extra_fields
    """

    """
    - level: 'info', 'warning', 'error', 'debug'
    - message: Message chính
    - extra_fields: Các trường bổ sung (src_ip, dst_ip, protocol, port, action, reason, bytes...)
    """
    logger = logging.getLogger()
    
    extra_info = {
        'component': 'Firewall'
    }
    extra_info.update(extra_fields)
    
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(message, extra={'extra_info': extra_info})

# ========== GEO-BLOCKING CLASS ==========
class GeoBlocker:
    def __init__(self, db_path):
        self.reader = None
        self.db_path = db_path
        self.cache = {}
        self.cache_size_limit = 10000
        
        try:
            if not os.path.exists(db_path):
                log_event('warning', f'GeoIP database không tồn tại: {db_path}', component='GeoBlocker')
                log_event('warning', 'Geo-blocking sẽ bị tắt', component='GeoBlocker')
                return
            
            self.reader = geoip2.database.Reader(db_path)
            log_event('info', f'Đã load GeoIP database: {db_path}', component='GeoBlocker')
        except Exception as e:
            log_event('error', f'Lỗi load GeoIP database: {e}', component='GeoBlocker')
            log_event('warning', 'Geo-blocking sẽ bị tắt', component='GeoBlocker')
    
    def get_country(self, ip):
        """Lấy country code từ IP"""
        if self.reader is None:
            return None
        
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            response = self.reader.country(ip)
            country_code = response.country.iso_code
            
            if len(self.cache) < self.cache_size_limit:
                self.cache[ip] = country_code
            
            return country_code
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            log_event('error', f'Lỗi lookup GeoIP cho {ip}: {e}', component='GeoBlocker')
            return None
    
    def should_block(self, ip, config):
        """
        Kiểm tra xem IP có nên bị chặn theo geo rules không
        Returns: (should_block: bool, country_code: str, reason: str)
        """
        if not config.get('enabled'):
            return False, None, None
        
        country = self.get_country(ip)
        
        if country is None:
            return False, None, "Unknown country"
        
        mode = config.get('mode', 'blacklist')
        blocked_countries = config.get('blocked_countries', [])
        allowed_countries = config.get('allowed_countries', [])
        
        if mode == 'blacklist':
            if country in blocked_countries:
                return True, country, f"Country {country} in blacklist"
        
        elif mode == 'whitelist':
            if country not in allowed_countries:
                return True, country, f"Country {country} not in whitelist"
        
        return False, country, None
    
    def close(self):
        """Đóng database connection"""
        if self.reader:
            self.reader.close()


# ========== RATE LIMITING CLASS ==========
class RateLimiter:
    def __init__(self):
        self.packet_counter = defaultdict(list)
        self.connection_counter = defaultdict(int)
        self.dns_queries = defaultdict(list)
        self.cleanup_interval = 60
        self.last_cleanup = time.time()
    
    def cleanup_old_data(self):
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        for ip in list(self.packet_counter.keys()):
            self.packet_counter[ip] = [t for t in self.packet_counter[ip] if current_time - t < 1]
            if not self.packet_counter[ip]:
                del self.packet_counter[ip]
        
        for ip in list(self.dns_queries.keys()):
            self.dns_queries[ip] = [t for t in self.dns_queries[ip] if current_time - t < 60]
            if not self.dns_queries[ip]:
                del self.dns_queries[ip]
        
        self.last_cleanup = current_time
    
    def check_packet_rate(self, ip, max_pps):
        current_time = time.time()
        self.packet_counter[ip] = [t for t in self.packet_counter[ip] if current_time - t < 1]
        self.packet_counter[ip].append(current_time)
        return len(self.packet_counter[ip]) > max_pps
    
    def check_dns_rate(self, ip, max_queries_per_minute):
        current_time = time.time()
        self.dns_queries[ip] = [t for t in self.dns_queries[ip] if current_time - t < 60]
        self.dns_queries[ip].append(current_time)
        return len(self.dns_queries[ip]) > max_queries_per_minute
    
    def increment_connection(self, ip):
        self.connection_counter[ip] += 1
    
    def check_connection_limit(self, ip, max_connections):
        return self.connection_counter[ip] > max_connections
    
    def get_stats(self, ip):
        current_time = time.time()
        recent_packets = [t for t in self.packet_counter.get(ip, []) if current_time - t < 1]
        recent_dns = [t for t in self.dns_queries.get(ip, []) if current_time - t < 60]
        return {
            'pps': len(recent_packets),
            'qpm': len(recent_dns),
            'connections': self.connection_counter.get(ip, 0)
        }



# ========== ĐỌC RULES TỪ FILE JSON ==========
def load_rules(rules_file="rules.json"):
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
        sys.exit(1)
    except Exception as e:
        log(f"[!] Lỗi đọc file rules: {e}")
        sys.exit(1)


def create_default_rules(rules_path):
    default_rules = {
        "blocked_domains": ["facebook.com"],
        "blocked_ips": ["31.13."],
        "blocked_ports": [],
        "allowed_ips": [],
        "allowed_domains": [],
        "log_all_traffic": False,
        "block_icmp": False,
        "rate_limiting": {
            "enabled": False,
            "max_packets_per_second": 100,
            "max_connections_per_ip": 50,
            "max_dns_queries_per_minute": 60
        },
        "time_based_rules": {
            "enabled": False,
            "timezone": "Asia/Ho_Chi_Minh",
            "rules": []
        },
        "geo_blocking": {
            "enabled": False,
            "geoip_database": "/root/geoip/GeoLite2-Country.mmdb",
            "blocked_countries": ["CN", "RU"],
            "allowed_countries": ["VN", "US"],
            "mode": "blacklist",
            "log_country_info": True
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

    rate_limit = rules.get('rate_limiting', {})
    if rate_limit.get('enabled'):
        log(f"Rate Limiting: Enabled")
        log(f"  Max PPS: {rate_limit.get('max_packets_per_second', 100)}")
        log(f"  Max Conn/IP: {rate_limit.get('max_connections_per_ip', 50)}")
        log(f"  Max DNS/Min: {rate_limit.get('max_dns_queries_per_minute', 60)}")
    else:
        log("Rate Limiting: Disabled")

    time_rules = rules.get('time_based_rules', {})
    if time_rules.get('enabled'):
        log(f"Time-based Rules: Enabled ({len(time_rules.get('rules', []))} rules)")
    else:
        log("Time-based Rules: Disabled")

    geo = rules.get('geo_blocking', {})
    if geo.get('enabled'):
        log(f"Geo-blocking: Enabled")
        log(f"  Mode: {geo.get('mode', 'blacklist').upper()}")
        log(f"  Database: {geo.get('geoip_database', 'Not set')}")
        if geo.get('mode') == 'blacklist':
            log(f"  Blocked Countries: {', '.join(geo.get('blocked_countries', []))}")
        else:
            log(f"  Allowed Countries: {', '.join(geo.get('allowed_countries', []))}")
    else:
        log("Geo-blocking: Disabled")

    log("=" * 70)


# ========== TIME-BASED RULES ==========
def is_time_in_range(start_time_str, end_time_str, current_time):
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
GEO_BLOCKER = None
LOGGER_MANAGER = None

# ========== HÀM XỬ LÝ PACKET ==========
def process_packet(packet):
    global RULES, LAST_MTIME, PACKET_COUNT, RATE_LIMITER, GEO_BLOCKER, LOGGER_MANAGER
    
    RATE_LIMITER.cleanup_old_data()
    
    PACKET_COUNT += 1
    if PACKET_COUNT % 5 == 0:
        new_rules, new_mtime = reload_rules_if_changed(RULES_FILE, LAST_MTIME)
        if new_rules:
            RULES = new_rules
            LAST_MTIME = new_mtime
            init_geo_blocker(RULES)

    try:
        scapy_packet = IP(packet.get_payload())
        src_ip = scapy_packet[IP].src
        dst_ip = scapy_packet[IP].dst
        protocol = scapy_packet[IP].proto
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"Proto-{protocol}")
        port_info = ""
        dst_port = None
        packet_bytes = len(packet.get_payload())

        if scapy_packet.haslayer(TCP):
            dst_port = scapy_packet[TCP].dport
            port_info = f":{dst_port}"
            if scapy_packet[TCP].flags & 0x02:
                RATE_LIMITER.increment_connection(src_ip)
        elif scapy_packet.haslayer(UDP):
            dst_port = scapy_packet[UDP].dport
            port_info = f":{dst_port}"

        # ========== KIỂM TRA GEO-BLOCKING (ƯU TIÊN CAO NHẤT) ==========
        if GEO_BLOCKER:
            geo_config = RULES.get('geo_blocking', {})
            should_block, country, reason = GEO_BLOCKER.should_block(dst_ip, geo_config)
            
            if should_block:
                log_event('warning', f'Geo-blocking: {src_ip} → {dst_ip}',
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto_name,
                    port=dst_port,
                    action='block',
                    reason=f'Country {country} blocked',
                    bytes=packet_bytes,
                    country=country
                )
                packet.drop()
                return
            elif country and geo_config.get('log_country_info'):
                if RULES.get('log_all_traffic', False):
                    log_event('info', f'Geo info: {dst_ip} from {country}',
                        dst_ip=dst_ip,
                        country=country,
                        action='info'
                    )

        # ========== KIỂM TRA RATE LIMITING ==========
        rate_limit_config = RULES.get('rate_limiting', {})
        if rate_limit_config.get('enabled'):
            max_pps = rate_limit_config.get('max_packets_per_second', 100)
            if RATE_LIMITER.check_packet_rate(src_ip, max_pps):
                stats = RATE_LIMITER.get_stats(src_ip)
                log_event('warning', f'Rate limit exceeded: {src_ip}',
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto_name,
                    port=dst_port,
                    action='block',
                    reason=f'PPS {stats["pps"]} > {max_pps}',
                    bytes=packet_bytes
                )
                packet.drop()
                return
            
            max_conn = rate_limit_config.get('max_connections_per_ip', 50)
            if RATE_LIMITER.check_connection_limit(src_ip, max_conn):
                stats = RATE_LIMITER.get_stats(src_ip)
                log_event('warning', f'Connection limit exceeded: {src_ip}',
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto_name,
                    port=dst_port,
                    action='block',
                    reason=f'Connections {stats["connections"]} > {max_conn}',
                    bytes=packet_bytes
                )
                packet.drop()
                return
            
            if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
                max_dns = rate_limit_config.get('max_dns_queries_per_minute', 60)
                if RATE_LIMITER.check_dns_rate(src_ip, max_dns):
                    stats = RATE_LIMITER.get_stats(src_ip)
                    log_event('warning', f'DNS flood detected: {src_ip}',
                        src_ip=src_ip,
                        protocol='DNS',
                        action='block',
                        reason=f'DNS queries {stats["qpm"]} > {max_dns}',
                        bytes=packet_bytes
                    )
                    packet.drop()
                    return

        # ========== ALLOWED IPS ==========
        for allowed_ip in RULES.get('allowed_ips', []):
            if dst_ip.startswith(allowed_ip):
                if RULES.get('log_all_traffic', False):
                    log_event('info', f'Whitelisted IP: {dst_ip}',
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=proto_name,
                        port=dst_port,
                        action='allow',
                        reason='IP whitelisted',
                        bytes=packet_bytes
                    )
                packet.accept()
                return

        # ========== BLOCK ICMP ==========
        if RULES.get('block_icmp', False) and scapy_packet.haslayer(ICMP):
            log_event('warning', f'ICMP blocked: {src_ip} → {dst_ip}',
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol='ICMP',
                action='block',
                reason='ICMP blocked by rule',
                bytes=packet_bytes
            )
            packet.drop()
            return

        # ========== DNS QUERIES ==========
        if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
            queried_domain = scapy_packet[DNSQR].qname.decode('utf-8').lower().strip('.')
            
            time_action = check_time_based_rules(queried_domain, RULES)
            if time_action == "block":
                log_event('warning', f'Time-based block: {queried_domain}',
                    src_ip=src_ip,
                    protocol='DNS',
                    action='block',
                    reason='Time-based rule',
                    domain=queried_domain,
                    bytes=packet_bytes
                )
                packet.drop()
                return
            elif time_action == "allow":
                log_event('info', f'Time-based allow: {queried_domain}',
                    src_ip=src_ip,
                    protocol='DNS',
                    action='allow',
                    reason='Time-based allow',
                    domain=queried_domain,
                    bytes=packet_bytes
                )
                packet.accept()
                return
            
            for allowed in RULES.get('allowed_domains', []):
                if allowed in queried_domain:
                    if RULES.get('log_all_traffic', False):
                        log_event('info', f'Domain whitelisted: {queried_domain}',
                            src_ip=src_ip,
                            protocol='DNS',
                            action='allow',
                            reason='Domain whitelisted',
                            domain=queried_domain,
                            bytes=packet_bytes
                        )
                    packet.accept()
                    return
            
            for blocked in RULES.get('blocked_domains', []):
                if blocked in queried_domain:
                    log_event('warning', f'Domain blocked: {queried_domain}',
                        src_ip=src_ip,
                        protocol='DNS',
                        action='block',
                        reason='Domain in blocklist',
                        domain=queried_domain,
                        bytes=packet_bytes
                    )
                    packet.drop()
                    return

        # ========== BLOCKED IPS ==========
        for blocked_ip in RULES.get('blocked_ips', []):
            if dst_ip.startswith(blocked_ip):
                log_event('warning', f'IP blocked: {dst_ip}',
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto_name,
                    port=dst_port,
                    action='block',
                    reason='IP in blocklist',
                    bytes=packet_bytes
                )
                packet.drop()
                return

        # ========== BLOCKED PORTS ==========
        if dst_port and dst_port in RULES.get('blocked_ports', []):
            log_event('warning', f'Port blocked: {dst_port}',
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto_name,
                port=dst_port,
                action='block',
                reason='Port in blocklist',
                bytes=packet_bytes
            )
            packet.drop()
            return

        # ========== ACCEPT ==========
        if RULES.get('log_all_traffic', False):
            log_event('info', f'Packet accepted: {src_ip} → {dst_ip}',
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto_name,
                port=dst_port,
                action='allow',
                reason='No rule matched',
                bytes=packet_bytes
            )

        packet.accept()
        
    except Exception as e:
        log_event('error', f'Error processing packet: {str(e)}',
            action='error',
            reason=str(e)
        )
        packet.accept()


# ========== INIT GEO BLOCKER ==========
def init_geo_blocker(rules):
    global GEO_BLOCKER
    geo_config = rules.get('geo_blocking', {})
    
    if not geo_config.get('enabled'):
        return
    
    db_path = geo_config.get('geoip_database')
    if not db_path:
        log("[!] GeoIP database path không được cấu hình")
        return
    
    # Expand đường dẫn (xử lý ~)
    db_path = os.path.expanduser(db_path)
    
    GEO_BLOCKER = GeoBlocker(db_path)


# ========== MAIN ==========
def main():
    global RULES, LAST_MTIME, GEO_BLOCKER, LOGGER_MANAGER

    if os.geteuid() != 0:
        log("[!] Script phải chạy với quyền root!")
        sys.exit(1)

    log("=" * 70)
    log(" PYTHON FIREWALL - Full Features")
    log("=" * 70)
    log("[*] Đang khởi động...")

    RULES = load_rules(RULES_FILE)
    LOGGER_MANAGER = LoggingManager(RULES.get('logging', {}))
    
    try:
        script_dir = Path(__file__).parent
        rules_path = script_dir / RULES_FILE
        LAST_MTIME = rules_path.stat().st_mtime
    except:
        LAST_MTIME = 0

    init_geo_blocker(RULES)
    
    print_rules_summary(RULES)

    queue = NetfilterQueue()
    queue.bind(0, process_packet)

    log_event('info', 'Firewall started successfully', component='Main')
    log(f"[*] Đang theo dõi file: {RULES_FILE}")
    log("[*] Nhấn Ctrl+C để dừng")
    log("-" * 70)

    try:
        queue.run()
    except KeyboardInterrupt:
        log("-" * 70)
        log_event('info', 'Firewall shutting down', component='Main')
    finally:
        queue.unbind()
        if GEO_BLOCKER:
            GEO_BLOCKER.close()
        log("[*] Đã dừng!")


if __name__ == "__main__":
    main()