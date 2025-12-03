import threading
from gui.dashboard import launch_gui
from modules.log_monitor import LogMonitor

if __name__ == "__main__":
    log_monitor = LogMonitor("/var/log/auth.log")

    t1 = threading.Thread(target=log_monitor.start_monitoring)
    t1.daemon = True
    t1.start()

    launch_gui()
