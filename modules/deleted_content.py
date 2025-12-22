import subprocess

def search_deleted_files():
    try:
        result = subprocess.check_output("sudo grep -a -R '' /proc/*/fd/* 2>/dev/null", shell=True)
        return result.decode(errors="ignore")[:5000]  # limit output
    except:
        return "Error accessing deleted file content"
