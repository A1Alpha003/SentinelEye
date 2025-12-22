import subprocess
import sqlite3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from modules.malware_scan import scan_with_virustotal
from modules.hashing import calculate_hash
from modules.metadata import get_metadata
from modules.filesystem_info import get_filesystems
from modules.system_scan import scan_system
from modules.deleted_content import search_deleted_files

DB = "database/forensic.db"

class AlertsFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.tree = ttk.Treeview(self, columns=("type","description","source","timestamp"), show="headings")
        self.tree.heading("type", text="Alert Type")
        self.tree.heading("description", text="Description")
        self.tree.heading("source", text="Source")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.pack(expand=True, fill="both")
        self.refresh()
        self.after(2000, self.periodic_refresh)  # auto-refresh every 2 sec

    def refresh(self):
        # Clear existing rows
        for row in self.tree.get_children():
            self.tree.delete(row)
        # Fetch last 50 alerts from all alert tables
        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        
        # Get brute force alerts
        cur.execute("SELECT 'Brute Force' as type, message as description, ip as source, timestamp FROM brute_force ORDER BY id DESC LIMIT 50")
        
        for r in cur.fetchall():
            self.tree.insert("", "end", values=r)
        conn.close()

    def periodic_refresh(self):
        self.refresh()
        self.after(2000, self.periodic_refresh)


def launch_gui():
    window = tk.Tk()
    window.title("SentinelEye Dashboard")
    window.geometry("600x500")

    def pick_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        hash_val = calculate_hash(file_path)
        meta = get_metadata(file_path)
        vt = scan_with_virustotal(file_path)

        result = f"Hash: {hash_val}\n\nMetadata: {meta}\n\nVirusTotal: {vt}"
        messagebox.showinfo("File Analysis", result)

    btn1 = tk.Button(window, text="Scan File with VirusTotal", command=pick_file, width=40)
    btn1.pack(pady=10)

    btn2 = tk.Button(window, text="List File Systems", command=lambda: messagebox.showinfo("File Systems", get_filesystems()))
    btn2.pack(pady=10)

    btn3 = tk.Button(window, text="Search Deleted Content", command=lambda: messagebox.showinfo("Deleted Content", search_deleted_files()))
    btn3.pack(pady=10)

    btn4 = tk.Button(window, text="System Scan", command=lambda: messagebox.showinfo("System Scan", scan_system()))
    btn4.pack(pady=10)

    alerts_frame = AlertsFrame(window)
    alerts_frame.pack(expand=True, fill="both", pady=10)

    window.mainloop()
