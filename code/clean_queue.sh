#!/bin/bash

# Script để clean NFQUEUE và reset firewall
# Chạy: sudo bash clean_queue.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   CLEAN NFQUEUE & RESET FIREWALL${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Kiểm tra root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Script phải chạy với quyền root"
    echo "Chạy: sudo bash clean_queue.sh"
    exit 1
fi

# =====================================
# FUNCTION: Dừng firewall
# =====================================
stop_firewall() {
    echo -e "${YELLOW}[1/6]${NC} Đang dừng firewall Python..."
    
    # Kill firewall process
    pkill -9 -f "python.*firewall.py" 2>/dev/null
    pkill -9 -f "python.*fw.py" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}  ✓ Đã dừng firewall${NC}"
    else
        echo -e "${YELLOW}  ⚠ Không tìm thấy firewall đang chạy${NC}"
    fi
    sleep 1
}

# =====================================
# FUNCTION: Flush iptables NFQUEUE
# =====================================
flush_nfqueue() {
    echo -e "${YELLOW}[2/6]${NC} Đang flush NFQUEUE rules..."
    
    # Xóa NFQUEUE rules khỏi FORWARD chain
    iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null
    
    # Xóa tất cả NFQUEUE rules
    iptables -t filter -L FORWARD --line-numbers -n | grep NFQUEUE | awk '{print $1}' | sort -rn | while read line; do
        iptables -D FORWARD $line 2>/dev/null
    done
    
    echo -e "${GREEN}  ✓ Đã xóa NFQUEUE rules${NC}"
}

# =====================================
# FUNCTION: Clear connection tracking
# =====================================
clear_conntrack() {
    echo -e "${YELLOW}[3/6]${NC} Đang xóa connection tracking..."
    
    # Flush conntrack table
    conntrack -F 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}  ✓ Đã xóa connection tracking${NC}"
    else
        echo -e "${YELLOW}  ⚠ conntrack-tools chưa cài (không bắt buộc)${NC}"
        echo -e "${YELLOW}    Cài bằng: sudo apt install conntrack${NC}"
    fi
}

# =====================================
# FUNCTION: Flush kernel network buffers
# =====================================
flush_network_buffers() {
    echo -e "${YELLOW}[4/6]${NC} Đang flush network buffers..."
    
    # Flush routing cache
    ip route flush cache 2>/dev/null
    
    # Flush ARP cache
    ip -s -s neigh flush all 2>/dev/null
    
    echo -e "${GREEN}  ✓ Đã flush network buffers${NC}"
}

# =====================================
# FUNCTION: Reset NFQUEUE kernel module
# =====================================
reset_nfqueue_module() {
    echo -e "${YELLOW}[5/6]${NC} Đang reset NFQUEUE kernel module..."
    
    # Unload nfnetlink_queue module
    modprobe -r nfnetlink_queue 2>/dev/null
    sleep 1
    
    # Reload module
    modprobe nfnetlink_queue 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}  ✓ Đã reset NFQUEUE module${NC}"
    else
        echo -e "${YELLOW}  ⚠ Không thể reload module (không ảnh hưởng)${NC}"
    fi
}

# =====================================
# FUNCTION: Show final status
# =====================================
show_status() {
    echo -e "${YELLOW}[6/6]${NC} Trạng thái hiện tại..."
    echo ""
    
    echo -e "${BLUE}--- NFQUEUE Rules ---${NC}"
    nfqueue_count=$(iptables -t filter -L FORWARD -n | grep -c NFQUEUE)
    if [ $nfqueue_count -eq 0 ]; then
        echo -e "${GREEN}✓ Không còn NFQUEUE rules${NC}"
    else
        echo -e "${YELLOW}⚠ Còn $nfqueue_count NFQUEUE rules:${NC}"
        iptables -t filter -L FORWARD -n | grep NFQUEUE
    fi
    echo ""
    
    echo -e "${BLUE}--- Firewall Process ---${NC}"
    fw_count=$(ps aux | grep -E "python.*f[wi]rewall.py" | wc -l)
    if [ $fw_count -eq 0 ]; then
        echo -e "${GREEN}✓ Không có firewall process${NC}"
    else
        echo -e "${YELLOW}⚠ Còn firewall process đang chạy:${NC}"
        ps aux | grep -E "python.*f[wi]rewall.py" | grep -v grep
    fi
    echo ""
    
    echo -e "${BLUE}--- Connection Tracking ---${NC}"
    if command -v conntrack &> /dev/null; then
        conn_count=$(conntrack -C 2>/dev/null)
        echo -e "Tracked connections: ${YELLOW}${conn_count}${NC}"
    else
        echo -e "${YELLOW}conntrack-tools chưa cài${NC}"
    fi
    echo ""
}

# =====================================
# FUNCTION: Setup clean iptables
# =====================================
setup_clean_iptables() {
    echo -e "${BLUE}--- Thiết lập lại iptables (optional) ---${NC}"
    read -p "Bạn có muốn setup lại iptables rules? (y/n): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Đang setup iptables...${NC}"
        
        # Enable IP forwarding
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        echo -e "${GREEN}✓ Enabled IP forwarding${NC}"
        
        # Setup NAT
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        if [ -n "$INTERFACE" ]; then
            iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
            echo -e "${GREEN}✓ Setup NAT trên interface: $INTERFACE${NC}"
        fi
        
        # Setup NFQUEUE
        iptables -I FORWARD -j NFQUEUE --queue-num 0
        echo -e "${GREEN}✓ Setup NFQUEUE queue-num 0${NC}"
        
        echo ""
        echo -e "${GREEN}✓ Hoàn tất setup iptables${NC}"
        echo -e "${YELLOW}Bây giờ có thể chạy: sudo /home/trinhlam/fwenv/bin/python3 firewall.py${NC}"
    fi
}

# =====================================
# MAIN
# =====================================

echo -e "${BLUE}Bắt đầu cleanup...${NC}"
echo ""

stop_firewall
flush_nfqueue
clear_conntrack
flush_network_buffers
reset_nfqueue_module
show_status

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   ✓ CLEANUP HOÀN TẤT${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

setup_clean_iptables

echo ""
echo -e "${BLUE}Lưu ý:${NC}"
echo "- Tất cả packets trong queue đã bị xóa"
echo "- Connection tracking đã reset"
echo "- Firewall process đã dừng"
echo "- Network buffers đã flush"
echo ""
echo -e "${YELLOW}Để khởi động lại firewall:${NC}"
echo "  sudo /home/trinhlam/fwenv/bin/python3 firewall.py "
echo ""
