from collections import defaultdict
import time
# Import log từ core
# from core.logger import log # Có thể không cần log ở đây vì nó chỉ là logic đếm

class RateLimiter:
    """Class quản lý tính năng Rate Limiting (chống flood)."""
    def __init__(self):
        # ... (Toàn bộ RateLimiter.__init__ từ code gốc) ...
        self.packet_counter = defaultdict(list)
        self.connection_counter = defaultdict(int)
        self.dns_queries = defaultdict(list)
        self.cleanup_interval = 60
        self.last_cleanup = time.time()
    
    def cleanup_old_data(self):
        # ... (Toàn bộ RateLimiter.cleanup_old_data từ code gốc) ...
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
        # ... (Toàn bộ RateLimiter.check_packet_rate từ code gốc) ...
        current_time = time.time()
        self.packet_counter[ip] = [t for t in self.packet_counter[ip] if current_time - t < 1]
        self.packet_counter[ip].append(current_time)
        return len(self.packet_counter[ip]) > max_pps
    
    def check_dns_rate(self, ip, max_queries_per_minute):
        # ... (Toàn bộ RateLimiter.check_dns_rate từ code gốc) ...
        current_time = time.time()
        self.dns_queries[ip] = [t for t in self.dns_queries[ip] if current_time - t < 60]
        self.dns_queries[ip].append(current_time)
        return len(self.dns_queries[ip]) > max_queries_per_minute
    
    def increment_connection(self, ip):
        # ... (Toàn bộ RateLimiter.increment_connection từ code gốc) ...
        self.connection_counter[ip] += 1
    
    def check_connection_limit(self, ip, max_connections):
        # ... (Toàn bộ RateLimiter.check_connection_limit từ code gốc) ...
        return self.connection_counter[ip] > max_connections
    
    def get_stats(self, ip):
        # ... (Toàn bộ RateLimiter.get_stats từ code gốc) ...
        current_time = time.time()
        recent_packets = [t for t in self.packet_counter.get(ip, []) if current_time - t < 1]
        recent_dns = [t for t in self.dns_queries.get(ip, []) if current_time - t < 60]
        return {
            'pps': len(recent_packets),
            'qpm': len(recent_dns),
            'connections': self.connection_counter.get(ip, 0)
        }