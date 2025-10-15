import json
import sys
from pathlib import Path
import os
from datetime import datetime
# Import các hàm cần thiết từ core
from core.logger import log, set_log_config

RULES_FILE = "rules.json"

def create_default_rules(rules_path):
    """Tạo file rules.json mẫu nếu chưa tồn tại."""
    default_rules = {
        # ... (Toàn bộ dict default_rules từ code gốc) ...
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
        },
        "logging": {
            "enabled": True,
            "log_level": "info",
            "log_to_file": True,
            "log_file": "/var/log/firewall.log",
            "log_rotation": True,
            "max_log_size_mb": 100,
            "log_format": "json",
            "log_fields": [
                "timestamp", "src_ip", "dst_ip", "protocol",
                "port", "action", "bytes", "reason"
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

def load_rules(rules_file=RULES_FILE):
    """Đọc rules từ file JSON và cập nhật cấu hình logging."""
    try:
        script_dir = Path(__file__).parent.parent # Lấy thư mục 'firewall'
        rules_path = script_dir / rules_file

        if not rules_path.exists():
            log(f"[!] Không tìm thấy file: {rules_path}")
            log("[!] Tạo file rules.json mẫu...")
            create_default_rules(rules_path)
            return load_rules(rules_file)

        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)

        # Cập nhật cấu hình logging
        logging_config = rules.get('logging', {})
        set_log_config(logging_config)
        
        # Tạo thư mục log nếu cần
        if logging_config.get('log_to_file'):
            log_file = logging_config.get('log_file', '/var/log/firewall.log')
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir)
                except Exception as e:
                    print(f"[!] Không thể tạo thư mục log: {e}") # Dùng print để đảm bảo log này được thấy ngay

        log(f"[✓] Đã load rules từ: {rules_path}")
        return rules

    except json.JSONDecodeError as e:
        log(f"[!] Lỗi format JSON: {e}")
        sys.exit(1)
    except Exception as e:
        log(f"[!] Lỗi đọc file rules: {e}")
        sys.exit(1)

def reload_rules_if_changed(rules_file, last_mtime):
    """Kiểm tra thời gian sửa đổi của file rules và reload nếu có thay đổi."""
    try:
        script_dir = Path(__file__).parent.parent
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
    """In ra tóm tắt các luật đã load."""
    log("=" * 70)
    log(" RULES HIỆN TẠI")
    log("=" * 70)
    
    # ... (Toàn bộ logic print_rules_summary từ code gốc) ...
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
        log(f"  Max PPS: {rate_limit.get('max_packets_per_second', 100)}")
        log(f"  Max Conn/IP: {rate_limit.get('max_connections_per_ip', 50)}")
        log(f"  Max DNS/Min: {rate_limit.get('max_dns_queries_per_minute', 60)}")
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
        log(f"  Mode: {geo.get('mode', 'blacklist').upper()}")
        log(f"  Database: {geo.get('geoip_database', 'Not set')}")
        if geo.get('mode') == 'blacklist':
            log(f"  Blocked Countries: {', '.join(geo.get('blocked_countries', []))}")
        else:
            log(f"  Allowed Countries: {', '.join(geo.get('allowed_countries', []))}")
    else:
        log("Geo-blocking: Disabled")

    logging_config = rules.get('logging', {})
    if logging_config.get('enabled'):
        log(f"Advanced Logging: Enabled")
        log(f"  Level: {logging_config.get('log_level', 'info').upper()}")
        log(f"  Format: {logging_config.get('log_format', 'text').upper()}")
        if logging_config.get('log_to_file'):
            log(f"  File: {logging_config.get('log_file', '/var/log/firewall.log')}")
            log(f"  Rotation: {'Yes' if logging_config.get('log_rotation') else 'No'}")
    else:
        log("Advanced Logging: Basic")

    log("=" * 70)