import os
import sys
import json
from datetime import datetime
import pytz
import time


LOG_CONFIG = {}
LOG_FILE_HANDLE = None 
LAST_LOG_CHECK = 0

def set_log_config(config):
    global LOG_CONFIG
    LOG_CONFIG = config

def check_log_rotation(log_file):
    global LOG_CONFIG
    try:
        if not os.path.exists(log_file):
            return
        
        max_size_mb = LOG_CONFIG.get('max_log_size_mb', 100)
        if os.path.getsize(log_file) == 0:
            return 
            
        current_size_mb = os.path.getsize(log_file) / (1024 * 1024)
        
        if current_size_mb > max_size_mb:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{log_file}.{timestamp}"
            os.rename(log_file, backup_file)
            print(f"[*] Log rotated: {backup_file}") 
    except Exception as e:
        print(f"[!] Lỗi log rotation: {e}") 

def log(msg, **kwargs):
    global LOG_CONFIG, LAST_LOG_CHECK
    if not LOG_CONFIG.get('enabled', True):
        print(msg)
        return
    
    tz_str = LOG_CONFIG.get('timezone', 'Asia/Ho_Chi_Minh')
    try:
        tz = pytz.timezone(tz_str)
    except:
        tz = pytz.UTC
    
    timestamp = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    log_format = LOG_CONFIG.get('log_format', 'text')
    
    log_entry = {
        'timestamp': timestamp,
        'message': msg
    }
    log_fields = LOG_CONFIG.get('log_fields', [])
    for field in log_fields:
        if field in kwargs:
            log_entry[field] = kwargs[field]

    if log_format == 'json':
        log_message = json.dumps(log_entry, indent=2, ensure_ascii=False)
        
    elif log_format in ('text', 'multiline'):
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
        action = log_entry.get('action', 'N/A')
        src_ip = log_entry.get('src_ip', 'N/A')
        dst_ip = log_entry.get('dst_ip', 'N/A')
        protocol = log_entry.get('protocol', 'N/A')
        port = log_entry.get('port')
        reason = log_entry.get('reason', '')

        log_message = (
            f"[{action:<12}] "
            f"[{timestamp}] "
            f"{protocol:<4} "
            f"{src_ip:<15} "
            f"-> {dst_ip}{f':{port}' if port else ''} "
            f"| Reason: {reason}"
        )

    print(log_message)
    
    if LOG_CONFIG.get('log_to_file', False):
        try:
            log_file = LOG_CONFIG.get('log_file', '/var/log/firewall.log')
            
            current_time = time.time()
            if LOG_CONFIG.get('log_rotation', False) and current_time - LAST_LOG_CHECK > 10:
                LAST_LOG_CHECK = current_time
                check_log_rotation(log_file)

            if log_format == 'json':
                file_content = json.dumps(log_entry, ensure_ascii=False) + '\n'
            else:
                file_content = log_message + '\n'

            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(file_content)
        except Exception as e:
            print(f"[!] Lỗi ghi log file: {e}")