# utils/helpers.py
import os
import hashlib
import time
import platform
import subprocess

def compute_file_hash(file_path, hash_type='sha256'):
    """Compute the hash of a file"""
    if not os.path.exists(file_path):
        return None
    
    try:
        if hash_type == 'md5':
            hash_obj = hashlib.md5()
        elif hash_type == 'sha1':
            hash_obj = hashlib.sha1()
        else:
            hash_obj = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    except Exception as e:
        print(f"Error computing hash for {file_path}: {e}")
        return None

def get_file_info(file_path):
    """Get detailed information about a file"""
    if not os.path.exists(file_path):
        return None
    
    try:
        file_stat = os.stat(file_path)
        
        info = {
            'path': file_path,
            'name': os.path.basename(file_path),
            'size': file_stat.st_size,
            'created': file_stat.st_ctime,
            'modified': file_stat.st_mtime,
            'accessed': file_stat.st_atime,
            'extension': os.path.splitext(file_path)[1].lower(),
            'is_hidden': is_hidden_file(file_path)
        }
        
        # Compute hash
        info['sha256'] = compute_file_hash(file_path)
        
        return info
    except Exception as e:
        print(f"Error getting file info for {file_path}: {e}")
        return None

def is_hidden_file(file_path):
    """Check if a file is hidden"""
    if platform.system() == "Windows":
        import win32api
        import win32con
        
        try:
            attrs = win32api.GetFileAttributes(file_path)
            return bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN)
        except:
            return False
    else:
        return os.path.basename(file_path).startswith('.')

def open_folder(folder_path):
    """Open a folder in the file explorer"""
    if not os.path.exists(folder_path):
        return False
    
    try:
        if platform.system() == "Windows":
            os.startfile(folder_path)
        elif platform.system() == "Darwin":  # macOS
            subprocess.call(["open", folder_path])
        else:  # Linux
            subprocess.call(["xdg-open", folder_path])
        return True
    except Exception as e:
        print(f"Error opening folder {folder_path}: {e}")
        return False