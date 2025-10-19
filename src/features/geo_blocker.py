import os
import geoip2.database
import geoip2.errors
from core.logger import log

class GeoBlocker:
    def __init__(self, db_path):
        self.reader = None
        self.db_path = db_path
        self.cache = {}  # IP -> Country code cache
        self.cache_size_limit = 10000
        
        try:
            if not os.path.exists(db_path):
                log(f"[!] GeoIP database không tồn tại: {db_path}")
                log("[!] Geo-blocking sẽ bị tắt")
                return
            
            self.reader = geoip2.database.Reader(db_path)
            log(f"[✓] Đã load GeoIP database: {db_path}")
        except Exception as e:
            log(f"[!] Lỗi load GeoIP database: {e}")
            log("[!] Geo-blocking sẽ bị tắt")
    
    def get_country(self, ip):
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
            log(f"[!] Lỗi lookup GeoIP cho {ip}: {e}")
            return None
    
    def should_block(self, ip, config):
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
        if self.reader:
            self.reader.close()

def init_geo_blocker(rules):
    geo_config = rules.get('geo_blocking', {})
    
    if not geo_config.get('enabled'):
        return None
    
    db_path = geo_config.get('geoip_database')
    if not db_path:
        log("[!] GeoIP database path không được cấu hình")
        return None
    
    db_path = os.path.expanduser(db_path)
    
    return GeoBlocker(db_path)