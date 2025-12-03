import os
import time

def get_metadata(file_path):
    stat = os.stat(file_path)

    return {
        "size": stat.st_size,
        "last_modified": time.ctime(stat.st_mtime),
        "created": time.ctime(stat.st_ctime),
        "permissions": oct(stat.st_mode)[-3:]
    }
