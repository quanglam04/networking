import os
import sys
import time
from netfilterqueue import NetfilterQueue
from pathlib import Path
from config.rules_manager import load_rules, print_rules_summary, RULES_FILE
from core.packet_processor import process_packet, update_global_state, RATE_LIMITER
from core.logger import log 
from features.geo_blocker import init_geo_blocker

def main():
    if os.geteuid() != 0:
        log("[!] Script phải chạy với quyền root!")
        sys.exit(1)

    log("=" * 70)
    log(" PYTHON FIREWALL - Refactored")
    log("=" * 70)
    log("[*] Đang khởi động...")

    rules = load_rules(RULES_FILE)
    
    try:
        script_dir = Path(__file__).parent
        rules_path = script_dir / RULES_FILE
        last_mtime = rules_path.stat().st_mtime
    except:
        last_mtime = 0

    # Initialize Geo Blocker
    geo_blocker = init_geo_blocker(rules)
    
    # Cập nhật trạng thái toàn cục trong packet_processor
    # Điều này cần thiết vì NetfilterQueue.bind chỉ chấp nhận một hàm đơn
    update_global_state(rules, last_mtime, geo_blocker)
    
    print_rules_summary(rules)

    queue = NetfilterQueue()
    queue.bind(1, process_packet)
    log("Tạo Queue thành công")
    log("[*] Firewall đã sẵn sàng!")
    log(f"[*] Đang theo dõi file: {RULES_FILE}")
    log("[*] Nhấn Ctrl+C để dừng")
    log("-" * 70)

    try:
        queue.run()
    except KeyboardInterrupt:
        log("-" * 70)
        log("[*] Đang dừng firewall...")
    finally:
        queue.unbind()
        if geo_blocker:
            geo_blocker.close()
        log("[*] Đã dừng!")

if __name__ == "__main__":
    main()