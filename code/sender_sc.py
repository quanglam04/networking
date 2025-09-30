#!/usr/bin/env python3
# sender_sc.py -- gửi packet mẫu bằng Scapy (chạy với sudo)
from scapy.all import IP, TCP, send
import sys

def send_syn(src_ip, dst_ip, src_port, dst_port):
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=int(src_port), dport=int(dst_port), flags='S')
    send(pkt, verbose=True)

def send_http_get(src_ip, dst_ip, src_port, dst_port):
    payload = b"GET / HTTP/1.1\r\nHost: demo\r\n\r\n"
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=int(src_port), dport=int(dst_port), flags='PA')/payload
    send(pkt, verbose=True)

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: sender_sc.py <syn|http> <src_ip> <dst_ip> <src_port> <dst_port>")
        sys.exit(1)
    mode = sys.argv[1]
    src_ip = sys.argv[2]
    dst_ip = sys.argv[3]
    src_port = sys.argv[4]
    dst_port = sys.argv[5]
    if mode == "syn":
        send_syn(src_ip, dst_ip, src_port, dst_port)
    else:
        send_http_get(src_ip, dst_ip, src_port, dst_port)
