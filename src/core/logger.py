import os
import sys
import json
from datetime import datetime
import pytz
import time

# ========== BIẾN TOÀN CỤC CHO LOGGING ==========
# Sử dụng dictionary để dễ dàng chia sẻ giữa các module mà không cần import global
LOG_CONFIG = {}
LOG_FILE_HANDLE = None # Ít dùng trong thực tế, chủ yếu dùng open/close
LAST_LOG_CHECK = 0

def set_log_config(config):
    """Cập nhật cấu hình logging từ RulesManager."""
    global LOG_CONFIG
    LOG_CONFIG = config

def check_log_rotation(log_file):
    """Kiểm tra và thực hiện log rotation nếu cần."""
    global LOG_CONFIG
    try:
        if not os.path.exists(log_file):
            return
        
        max_size_mb = LOG_CONFIG.get('max_log_size_mb', 100)
        # Bỏ qua nếu file quá nhỏ, tránh lỗi
        if os.path.getsize(log_file) == 0:
            return 
            
        current_size_mb = os.path.getsize(log_file) / (1024 * 1024)
        
        if current_size_mb > max_size_mb:
            # Rotate log file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{log_file}.{timestamp}"
            os.rename(log_file, backup_file)
            print(f"[*] Log rotated: {backup_file}") # Dùng print để đảm bảo log này được thấy ngay
    except Exception as e:
        print(f"[!] Lỗi log rotation: {e}") # Dùng print thay vì log để tránh vòng lặp/lỗi

def log(msg, **kwargs):
    """
    Hàm log với advanced features và multiline format
    kwargs có thể chứa: src_ip, dst_ip, protocol, port, action, bytes, reason
    """
    global LOG_CONFIG, LAST_LOG_CHECK
    
    if not LOG_CONFIG.get('enabled', True):
        print(msg)
        return
    
    # Lấy timestamp
    tz_str = LOG_CONFIG.get('timezone', 'Asia/Ho_Chi_Minh')
    try:
        tz = pytz.timezone(tz_str)
    except:
        tz = pytz.UTC
    
    timestamp = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    # Format log theo config
    log_format = LOG_CONFIG.get('log_format', 'text')
    
    # Tạo JSON/Dict cơ sở
    log_entry = {
        'timestamp': timestamp,
        'message': msg
    }
    log_fields = LOG_CONFIG.get('log_fields', [])
    for field in log_fields:
        if field in kwargs:
            log_entry[field] = kwargs[field]

    if log_format == 'json':
        # JSON Pretty-Print (dễ đọc hơn JSON thô)
        log_message = json.dumps(log_entry, indent=2, ensure_ascii=False)
        
    elif log_format in ('text', 'multiline'):
        # Định dạng text multiline (Giữ nguyên cấu trúc cũ)
        log_lines = [
            "=" * 70,
            f"[{timestamp}] {msg}"
        ]
        
        if kwargs:
            for key, value in kwargs.items():
                if value is not None:
                    log_lines.append(f"-- {key}: {value}")
        
        log_lines.append("=" * 70)
        log_message = "\n".join(log_lines)
        
    else: # Mặc định hoặc 'singleline', 'pretty-text'
        # Định dạng single-line đẹp (Được đề xuất để thay thế log khó nhìn)
        action = log_entry.get('action', 'N/A')
        src_ip = log_entry.get('src_ip', 'N/A')
        dst_ip = log_entry.get('dst_ip', 'N/A')
        protocol = log_entry.get('protocol', 'N/A')
        port = log_entry.get('port')
        reason = log_entry.get('reason', '')

        # Tạo chuỗi log duy nhất
        log_message = (
            f"[{action:<12}] " # Căn trái 12 ký tự
            f"[{timestamp}] "
            f"{protocol:<4} "
            f"{src_ip:<15} "
            f"-> {dst_ip}{f':{port}' if port else ''} "
            f"| Reason: {reason}"
        )

    # Output ra console
    print(log_message)
    
    # Ghi vào file (Chỉ ghi JSON thô hoặc singleline để tiết kiệm dung lượng)
    if LOG_CONFIG.get('log_to_file', False):
        try:
            log_file = LOG_CONFIG.get('log_file', '/var/log/firewall.log')
            
            current_time = time.time()
            if LOG_CONFIG.get('log_rotation', False) and current_time - LAST_LOG_CHECK > 10:
                LAST_LOG_CHECK = current_time
                check_log_rotation(log_file)

            # Chỉ ghi JSON thô (hoặc singleline) vào file để dễ phân tích và tiết kiệm dung lượng
            if log_format == 'json':
                file_content = json.dumps(log_entry, ensure_ascii=False) + '\n'
            else:
                file_content = log_message + '\n'

            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(file_content)
        except Exception as e:
            print(f"[!] Lỗi ghi log file: {e}")