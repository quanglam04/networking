
def check_packet_size(packet_bytes, rules):
    """
    Kiểm tra xem độ dài gói tin có nằm ngoài ngưỡng cho phép hay không.

    Args:
        packet_bytes (int): Tổng độ dài gói tin (từ len(packet.get_payload())).
        rules (dict): Cấu hình luật toàn cục.

    Returns:
        tuple: (bool, str) -> (True nếu chặn, lý do chặn)
    """
    size_config = rules.get('packet_size_filtering', {})
    if not size_config.get('enabled'):
        return False, ""

    min_size = size_config.get('min_size', 40)
    max_size = size_config.get('max_size', 1500)

    if packet_bytes < min_size:
        reason = f"Packet too small ({packet_bytes} < {min_size} bytes)"
        return True, reason
    
    if packet_bytes > max_size:
        reason = f"Packet too large ({packet_bytes} > {max_size} bytes)"
        return True, reason

    return False, ""