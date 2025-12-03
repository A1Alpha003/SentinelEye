import os

def scan_system(directory="/home"):
    suspicious = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith((".exe", ".bat", ".sh", ".py")):
                suspicious.append(os.path.join(root, file))
    return suspicious
