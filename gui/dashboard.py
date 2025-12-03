import tkinter as tk
from tkinter import filedialog, messagebox
from modules.malware_scan import scan_with_virustotal
from modules.hashing import calculate_hash
from modules.metadata import get_metadata
from modules.filesystem_info import get_filesystems
from modules.system_scan import scan_system
from modules.deleted_content import search_deleted_files
from modules.integrations import snort_status, wazuh_status

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

    btn5 = tk.Button(window, text="Snort Status", command=lambda: messagebox.showinfo("Snort", snort_status()))
    btn5.pack(pady=10)

    btn6 = tk.Button(window, text="Wazuh Status", command=lambda: messagebox.showinfo("Wazuh", wazuh_status()))
    btn6.pack(pady=10)

    window.mainloop()
