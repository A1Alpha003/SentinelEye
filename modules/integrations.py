def snort_status():
    try:
        import subprocess
        result = subprocess.check_output("systemctl status snort", shell=True)
        return result.decode()
    except:
        return "Snort not installed"

def wazuh_status():
    try:
        import subprocess
        result = subprocess.check_output("systemctl status wazuh-agent", shell=True)
        return result.decode()
    except:
        return "Wazuh Agent not installed"
