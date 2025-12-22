import time
import re
import sqlite3
from datetime import datetime, timedelta
import threading
import ipaddress
from collections import defaultdict

class LogMonitor:
    def __init__(self, log_paths=None):
        if log_paths is None:
            self.log_paths = [
                "/var/log/auth.log",      # SSH/authentication
                "/var/log/syslog",        # System logs
                "/var/log/apache2/access.log",  # Web server
                "/var/log/nginx/access.log",    # Nginx
            ]
        else:
            self.log_paths = log_paths
            
        self.conn = sqlite3.connect("database/forensic.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()
        
        # Attack tracking for rate limiting
        self.ip_attempts = defaultdict(list)    # For brute force
        self.request_tracker = defaultdict(list) # For DDoS tracking
        
        # Thresholds
        self.BRUTE_FORCE_THRESHOLD = 5  # attempts per minute
        self.DDOS_THRESHOLD = 100       # requests per minute
        self.PORT_SCAN_THRESHOLD = 20   # ports per minute
        
        print(f"[+] Monitoring {len(self.log_paths)} log files")
        print(f"[+] DDoS Threshold: {self.DDOS_THRESHOLD} requests/minute")

    def create_tables(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS brute_force (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            attack_type TEXT,
            attempts INTEGER,
            message TEXT
        )""")
        
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS ddos_attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            request_count INTEGER,
            duration_seconds INTEGER,
            target_port INTEGER,
            attack_type TEXT,
            log_source TEXT
        )""")
        
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            ports_scanned INTEGER,
            target_ports TEXT,
            message TEXT
        )""")
        
        # Create blocked_ips table if it doesn't exist
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            reason TEXT,
            duration TEXT,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            status TEXT DEFAULT 'active',
            UNIQUE(ip)
        )""")
        
        self.conn.commit()

    def detect_bruteforce(self, line, log_source):
        patterns = {
            'ssh': r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
            'web': r"POST .*login.* 401.* (\d+\.\d+\.\d+\.\d+)",
            'ftp': r"FTP login failed.* (\d+\.\d+\.\d+\.\d+)",
        }
        
        detected_ip = None
        attack_type = "Unknown"
        
        for atype, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                detected_ip = match.group(1)
                attack_type = f"{atype.upper()} Brute Force"
                break
        
        if detected_ip:
            current_time = datetime.now()
            
            # Track attempts
            self.ip_attempts[detected_ip].append(current_time)
            
            # Clean old attempts (older than 1 minute)
            one_min_ago = current_time - timedelta(minutes=1)
            self.ip_attempts[detected_ip] = [
                t for t in self.ip_attempts[detected_ip] if t > one_min_ago
            ]
            
            attempts = len(self.ip_attempts[detected_ip])
            
            # Check threshold
            if attempts >= self.BRUTE_FORCE_THRESHOLD:
                timestamp = current_time.isoformat()
                self.cursor.execute("""
                INSERT INTO brute_force(timestamp, ip, attack_type, attempts, message) 
                VALUES(?, ?, ?, ?, ?)
                """, (timestamp, detected_ip, attack_type, attempts, line))
                self.conn.commit()
                
                # Auto-block if high attempts
                if attempts >= 10:
                    self.auto_block_ip(detected_ip, "Brute Force Attack", "10min")
                
                print(f"[ALERT] {attack_type} from {detected_ip} ({attempts} attempts)")

    def detect_ddos(self, line, log_source):
        """Detect DDoS attacks from log entries"""
        try:
            # Try to extract IP from various log formats
            ip = None
            
            # Pattern 1: Standard web log format (Apache/Nginx)
            web_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] "(GET|POST|HEAD|PUT|DELETE)'
            match = re.search(web_pattern, line)
            if match:
                ip = match.group(1)
            
            # Pattern 2: IP at start of line
            if not ip:
                ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
            
            # Pattern 3: IP anywhere in line (fallback)
            if not ip:
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                if ip_match:
                    ip = ip_match.group(1)
            
            if ip:
                # Validate IP
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    return
                
                current_time = datetime.now()
                
                # Track requests for this IP
                self.request_tracker[ip].append(current_time)
                
                # Clean old requests (older than 1 minute)
                one_min_ago = current_time - timedelta(minutes=1)
                self.request_tracker[ip] = [
                    t for t in self.request_tracker[ip] if t > one_min_ago
                ]
                
                request_count = len(self.request_tracker[ip])
                
                # Check DDoS threshold
                if request_count >= self.DDOS_THRESHOLD:
                    timestamp = current_time.isoformat()
                    
                    # Determine attack type and port
                    attack_type = "HTTP Flood"
                    target_port = 80
                    
                    if 'ssh' in log_source or '22' in line:
                        target_port = 22
                        attack_type = "SSH Flood"
                    elif '443' in line or 'HTTPS' in line.upper():
                        target_port = 443
                        attack_type = "HTTPS Flood"
                    elif 'mysql' in line.lower() or '3306' in line:
                        target_port = 3306
                        attack_type = "MySQL Flood"
                    
                    # Check if this attack was already logged recently (last 5 minutes)
                    self.cursor.execute("""
                    SELECT COUNT(*) FROM ddos_attacks 
                    WHERE ip = ? AND timestamp > datetime('now', '-5 minutes')
                    """, (ip,))
                    
                    recent_logs = self.cursor.fetchone()[0]
                    
                    # Only log if not already logged recently
                    if recent_logs == 0:
                        self.cursor.execute("""
                        INSERT INTO ddos_attacks
                        (timestamp, ip, request_count, duration_seconds, target_port, attack_type, log_source)
                        VALUES(?, ?, ?, ?, ?, ?, ?)
                        """, (timestamp, ip, request_count, 60, target_port, attack_type, log_source))
                        self.conn.commit()
                        
                        print(f"[CRITICAL] {attack_type} from {ip} ({request_count} requests/min)")
                        
                        # Auto-block if extreme (200+ requests/min)
                        if request_count >= 200:
                            self.auto_block_ip(
                                ip, 
                                f"DDoS Attack ({request_count} requests/min)", 
                                "1hour"
                            )
                    
        except Exception as e:
            print(f"[ERROR] DDoS detection error: {e}")

    def detect_port_scan(self, line):
        # Detect port scanning attempts
        port_scan_patterns = [
            r"Connection from (\d+\.\d+\.\d+\.\d+) to port (\d+)",
            r"Port scan detected from (\d+\.\d+\.\d+\.\d+)",
            r"(\d+\.\d+\.\d+\.\d+).*SYN.* to port (\d+)",
        ]
        
        for pattern in port_scan_patterns:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                port = match.group(2) if len(match.groups()) > 1 else "multiple"
                
                current_time = datetime.now()
                timestamp = current_time.isoformat()
                
                self.cursor.execute("""
                INSERT INTO port_scans(timestamp, ip, ports_scanned, target_ports, message)
                VALUES(?, ?, ?, ?, ?)
                """, (timestamp, ip, 1, str(port), line))
                self.conn.commit()
                
                print(f"[ALERT] Port scan from {ip} on port {port}")

    def auto_block_ip(self, ip, reason, duration="30min"):
        """Automatically block malicious IPs"""
        try:
            # Add to blocked IPs table
            expires_at = None
            if duration == "10min":
                expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()
            elif duration == "1hour":
                expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
            elif duration == "permanent":
                expires_at = None
            
            self.cursor.execute("""
            INSERT OR REPLACE INTO blocked_ips (ip, reason, duration, expires_at, status)
            VALUES (?, ?, ?, ?, 'active')
            """, (ip, reason, duration, expires_at))
            self.conn.commit()
            
            # Execute actual firewall block (iptables)
            self.execute_firewall_block(ip)
            
            print(f"[ACTION] Auto-blocked {ip} for {duration} - {reason}")
            
        except Exception as e:
            print(f"[ERROR] Failed to auto-block {ip}: {e}")

    def execute_firewall_block(self, ip):
        """Execute actual firewall blocking commands"""
        try:
            # Check if iptables command exists
            import subprocess
            
            # Block with iptables (requires sudo)
            commands = [
                f"sudo iptables -A INPUT -s {ip} -j DROP",
                f"sudo ip6tables -A INPUT -s {ip} -j DROP"  # IPv6
            ]
            
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd, 
                        shell=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=5
                    )
                    if result.returncode == 0:
                        print(f"[FIREWALL] Successfully blocked {ip}")
                    else:
                        print(f"[FIREWALL WARNING] Command failed: {result.stderr}")
                except:
                    pass  # Ignore if command fails (might not have sudo)
            
        except Exception as e:
            print(f"[WARNING] Could not execute firewall commands: {e}")

    def cleanup_old_blocks(self):
        """Remove expired IP blocks"""
        try:
            current_time = datetime.now().isoformat()
            
            # Update expired blocks
            self.cursor.execute("""
            UPDATE blocked_ips 
            SET status = 'expired' 
            WHERE expires_at IS NOT NULL 
            AND expires_at < ?
            AND status = 'active'
            """, (current_time,))
            
            self.conn.commit()
            
            # Unblock expired IPs from firewall
            expired_ips = self.cursor.execute("""
            SELECT ip FROM blocked_ips WHERE status = 'expired'
            """).fetchall()
            
            for (ip,) in expired_ips:
                self.execute_firewall_unblock(ip)
            
        except Exception as e:
            print(f"[ERROR] Cleanup failed: {e}")

    def execute_firewall_unblock(self, ip):
        """Remove IP from firewall block list"""
        try:
            import subprocess
            commands = [
                f"sudo iptables -D INPUT -s {ip} -j DROP",
                f"sudo ip6tables -D INPUT -s {ip} -j DROP"
            ]
            
            for cmd in commands:
                try:
                    subprocess.run(cmd, shell=True, check=False, timeout=5)
                except:
                    pass
            
        except Exception as e:
            print(f"[WARNING] Could not unblock {ip}: {e}")

    def analyze_log_line(self, line, log_source):
        """Analyze a single log line for multiple attack types"""
        line = line.strip()
        
        if not line:
            return
        
        # Check for various attack types
        self.detect_bruteforce(line, log_source)
        self.detect_ddos(line, log_source)
        self.detect_port_scan(line)
        
        # Additional detection patterns
        self.detect_sqli(line, log_source)
        self.detect_xss(line, log_source)

    def detect_sqli(self, line, log_source):
        """Detect SQL injection attempts"""
        sqli_patterns = [
            r"union.*select",
            r"' OR '1'='1",
            r"';.*--",
            r"sleep\(.*\)",
            r"benchmark\(.*\)",
        ]
        
        for pattern in sqli_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    self.record_attack("SQL Injection", ip, line)
                    print(f"[ALERT] SQL Injection attempt from {ip}")

    def detect_xss(self, line, log_source):
        """Detect XSS attempts"""
        xss_patterns = [
            r"<script>",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"alert\(.*\)",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    self.record_attack("XSS Attack", ip, line)
                    print(f"[ALERT] XSS attempt from {ip}")

    def record_attack(self, attack_type, ip, message):
        """Generic attack recording"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute("""
        INSERT INTO brute_force(timestamp, ip, attack_type, attempts, message)
        VALUES(?, ?, ?, ?, ?)
        """, (timestamp, ip, attack_type, 1, message))
        self.conn.commit()

    def tail_log(self, log_path):
        """Tail a log file continuously"""
        try:
            with open(log_path, 'r') as file:
                # Go to end of file
                file.seek(0, 2)
                
                while True:
                    line = file.readline()
                    if line:
                        self.analyze_log_line(line, log_path)
                    else:
                        time.sleep(0.1)
                        
        except FileNotFoundError:
            print(f"[WARNING] Log file not found: {log_path}")
        except Exception as e:
            print(f"[ERROR] Failed to monitor {log_path}: {e}")

    def start_monitoring(self):
        """Start monitoring all log files"""
        print("[+] Starting comprehensive log monitoring...")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.periodic_cleanup, daemon=True)
        cleanup_thread.start()
        
        # Start DDoS tracker cleanup thread
        ddos_cleanup_thread = threading.Thread(target=self.periodic_ddos_cleanup, daemon=True)
        ddos_cleanup_thread.start()
        
        # Start monitoring threads for each log file
        threads = []
        for log_path in self.log_paths:
            thread = threading.Thread(
                target=self.tail_log, 
                args=(log_path,),
                daemon=True
            )
            thread.start()
            threads.append(thread)
            print(f"[+] Monitoring: {log_path}")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(60)  # Check every minute
                self.cleanup_old_blocks()
        except KeyboardInterrupt:
            print("\n[+] Stopping monitoring...")
            self.conn.close()

    def periodic_cleanup(self):
        """Periodic cleanup of old data"""
        while True:
            time.sleep(300)  # Clean every 5 minutes
            self.cleanup_old_data()
    
    def periodic_ddos_cleanup(self):
        """Clean up old DDoS tracker entries"""
        while True:
            time.sleep(60)  # Clean every minute
            self.cleanup_ddos_tracker()
    
    def cleanup_ddos_tracker(self):
        """Clean old entries from DDoS tracker"""
        try:
            current_time = datetime.now()
            five_min_ago = current_time - timedelta(minutes=5)
            
            ips_to_remove = []
            for ip, timestamps in list(self.request_tracker.items()):
                # Keep only recent timestamps
                self.request_tracker[ip] = [
                    t for t in timestamps if t > five_min_ago
                ]
                
                # Remove IP if no recent timestamps
                if not self.request_tracker[ip]:
                    ips_to_remove.append(ip)
            
            # Remove empty entries
            for ip in ips_to_remove:
                del self.request_tracker[ip]
                
        except Exception as e:
            print(f"[ERROR] DDoS tracker cleanup failed: {e}")

    def cleanup_old_data(self):
        """Remove old attack records"""
        try:
            cutoff = (datetime.now() - timedelta(days=7)).isoformat()
            
            # Delete old records
            self.cursor.execute("""
            DELETE FROM brute_force WHERE timestamp < ?
            """, (cutoff,))
            
            self.cursor.execute("""
            DELETE FROM ddos_attacks WHERE timestamp < ?
            """, (cutoff,))
            
            self.cursor.execute("""
            DELETE FROM port_scans WHERE timestamp < ?
            """, (cutoff,))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"[ERROR] Data cleanup failed: {e}")

if __name__ == "__main__":
    monitor = LogMonitor()
    monitor.start_monitoring()
