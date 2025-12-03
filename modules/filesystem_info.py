import os

def get_filesystems():
    filesystems = []
    with open("/proc/filesystems", "r") as f:
        for line in f:
            fs = line.strip().split("\t")[-1]
            filesystems.append(fs)
    return filesystems
