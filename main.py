import os
import json
import time
import threading
import sqlite3
import hashlib
import requests
import subprocess
import re
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox

# ===================== DATABASE SETUP =====================

DB_PATH = "database/forensic.db"

def ensure_database():
    if not os.path.exists("database"):
        os.makedirs("database")
    conn = sqlite3.connect(DB_PATH)
    conn.close()

# ===================== HASHING =====================

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# ===================== METADATA =====================

def get_metadata(file_path):
    stat = os.stat(file_path)
    return {
        "size": stat.st_size,
        "last_modified": time.ctime(stat.st_mtime),
        "created": time.ctime(stat.st_ctime),
        "permissions": oct(stat.st_mode)[-3:]
    }

# ===================== FILESYSTEM INFO =====================

def get_filesystems():
    filesystems = []
    with open("/proc/filesystems", "r") as f:
        for line in f:
            fs = line.strip().split("\t")[-1]
            filesystems.append(fs)
    return filesystems

# ===================== SYSTEM SCAN =====================

def scan_system(directory="/home"):
    suspicious = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith((".exe", ".bat", ".sh", ".py")):
                suspicious.append(os.path.join(root, file))
    return suspicious

# ===================== DELETED CONTENT =====================

def search_deleted_files():
    try:
        result = subprocess.check_output(
            "sudo grep -a -R '' /proc/*/fd/* 2>/dev/null",
            shell=True
        )
        return result.decode(errors="ignore")[:5000]
    except:
        return "Error accessing deleted file content"

# ===================== INTEGRATIONS =====================

def snort_status():
    try:
        result = subprocess.check_output("systemctl status snort", shell=True)
        return result.decode()
    except:
        return "Snort not installed"

def wazuh_status():
    try:
        result = subprocess.check_output("systemctl status wazuh-agent", shell=True)
        return result.decode()
    except:
        return "Wazuh Agent not installed"

# ===================== VIRUSTOTAL =====================

API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

def scan_with_virustotal(file_path):
    file_hash = calculate_hash(file_path)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "hash": file_hash,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"]
        }
    return {"error": "File not found in VirusTotal database"}

# ===================== LOG MONITOR =====================

class LogMonitor:
    def __init__(self, log_path):
        self.log_path = log_path
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.cursor = self.conn.cursor()
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
            self.cursor.execute(
                "INSERT INTO brute_force(timestamp,ip,message) VALUES(?,?,?)",
                (timestamp, ip, line)
            )
            self.conn.commit()
            print(f"[ALERT] Brute Force Attempt Detected! IP: {ip}")

    def start_monitoring(self):
        with open(self.log_path, "r") as file:
            file.seek(0, 2)
            while True:
                line = file.readline()
                if line:
                    self.detect_bruteforce(line)
                time.sleep(0.2)

# ===================== WAZUH MONITOR =====================

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

class WazuhMonitor:
    def __init__(self, alert_file=ALERT_FILE):
        self.alert_file = alert_file
        self.stop_flag = False

    def save_alert(self, alert):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS wazuh_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT,
            description TEXT,
            agent TEXT,
            src_ip TEXT,
            timestamp TEXT
        )""")
        cursor.execute("""
        INSERT INTO wazuh_alerts (rule_id, description, agent, src_ip, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """, (
            alert.get("rule", {}).get("id"),
            alert.get("rule", {}).get("description"),
            alert.get("agent", {}).get("name"),
            alert.get("data", {}).get("srcip")
            or alert.get("data", {}).get("srcip_ipv4")
            or alert.get("data", {}).get("remote_ip"),
            alert.get("timestamp")
        ))
        conn.commit()
        conn.close()

    def start_monitoring(self):
        print("[WAZUH] Monitoring started")
        while not os.path.exists(self.alert_file):
            time.sleep(1)

        with open(self.alert_file, "r") as f:
            f.seek(0, 2)
            while not self.stop_flag:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue

                desc = (alert.get("rule", {}).get("description") or "").lower()
                if any(k in desc for k in ("brute", "ssh", "login", "failed")):
                    self.save_alert(alert)

# ===================== GUI =====================

def launch_gui():
    window = tk.Tk()
    window.title("SentinelEye Dashboard")
    window.geometry("600x500")

    def pick_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        result = (
            f"Hash:\n{calculate_hash(file_path)}\n\n"
            f"Metadata:\n{get_metadata(file_path)}\n\n"
            f"VirusTotal:\n{scan_with_virustotal(file_path)}"
        )
        messagebox.showinfo("File Analysis", result)

    tk.Button(window, text="Scan File with VirusTotal", command=pick_file, width=40).pack(pady=8)
    tk.Button(window, text="List File Systems", command=lambda: messagebox.showinfo("Filesystems", get_filesystems())).pack(pady=8)
    tk.Button(window, text="Search Deleted Content", command=lambda: messagebox.showinfo("Deleted Content", search_deleted_files())).pack(pady=8)
    tk.Button(window, text="System Scan", command=lambda: messagebox.showinfo("System Scan", scan_system())).pack(pady=8)
    tk.Button(window, text="Snort Status", command=lambda: messagebox.showinfo("Snort", snort_status())).pack(pady=8)
    tk.Button(window, text="Wazuh Status", command=lambda: messagebox.showinfo("Wazuh", wazuh_status())).pack(pady=8)

    window.mainloop()

# ===================== MAIN =====================

if __name__ == "__main__":
    ensure_database()

    wazuh = WazuhMonitor()
    threading.Thread(target=wazuh.start_monitoring, daemon=True).start()

    launch_gui()
