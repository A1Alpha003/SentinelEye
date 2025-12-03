import os
import threading
from gui.dashboard import launch_gui
from modules.log_monitor import LogMonitor
import sqlite3

def ensure_database():
    if not os.path.exists("database"):
        os.makedirs("database")

    # Create empty forensic.db if missing
    conn = sqlite3.connect("database/forensic.db")
    conn.close()

if __name__ == "__main__":
    ensure_database()

    log_monitor = LogMonitor("/var/log/auth.log")

    t1 = threading.Thread(target=log_monitor.start_monitoring)
    t1.daemon = True
    t1.start()

    launch_gui()
