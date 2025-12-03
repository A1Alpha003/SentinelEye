import time
import re
import sqlite3
from datetime import datetime

class LogMonitor:
    def __init__(self, log_path):
        self.log_path = log_path
        self.conn = sqlite3.connect("database/forensic.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS brute_force (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            message TEXT
        )""")

    def detect_bruteforce(self, line):
        pattern = r"Failed password for.*from (\d+\.\d+\.\d+\.\d+)"
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            timestamp = str(datetime.now())
            self.cursor.execute("INSERT INTO brute_force(timestamp,ip,message) VALUES(?,?,?)",
                                (timestamp, ip, line))
            self.conn.commit()
            print(f"[ALERT] Brute Force Attempt Detected! IP: {ip}")

    def start_monitoring(self):
        print("[+] Monitoring logs for brute-force attempts...")
        with open(self.log_path, "r") as file:
            file.seek(0, 2)
            while True:
                line = file.readline()
                if line:
                    self.detect_bruteforce(line)
                time.sleep(0.2)
