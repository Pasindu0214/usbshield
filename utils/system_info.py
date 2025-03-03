# utils/system_info.py
import platform
import os
import psutil
import socket
import uuid

def get_system_info():
    """Get system information"""
    info = {
        'os': {
            'name': platform.system(),
            'version': platform.version(),
            'release': platform.release(),
            'architecture': platform.architecture()[0]
        },
        'hardware': {
            'machine': platform.machine(),
            'processor': platform.processor()
        },
        'network': {
            'hostname': socket.gethostname(),
            'mac_address': ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 48, 8)][::-1])
        },
        'python': {
            'version': platform.python_version(),
            'implementation': platform.python_implementation()
        }
    }
    
    # Add memory info
    mem = psutil.virtual_memory()
    info['hardware']['memory'] = {
        'total': mem.total,
        'available': mem.available,
        'percent_used': mem.percent
    }
    
    return info

def get_drives():
    """Get information about drives/partitions"""
    drives = []
    
    if platform.system() == "Windows":
        import win32api
        
        drive_letters = win32api.GetLogicalDriveStrings().split('\000')[:-1]
        
        for drive in drive_letters:
            try:
                drive_type = win32api.GetDriveType(drive)
                drive_info = {
                    'path': drive,
                    'type': _get_drive_type_name(drive_type),
                    'removable': drive_type == win32api.DRIVE_REMOVABLE
                }
                
                # Get additional info if the drive is ready
                try:
                    sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters = win32api.GetDiskFreeSpace(drive)
                    drive_info['size'] = total_clusters * sectors_per_cluster * bytes_per_sector
                    drive_info['free'] = free_clusters * sectors_per_cluster * bytes_per_sector
                except:
                    pass
                
                drives.append(drive_info)
            except:
                pass
    else:
        # For Linux/macOS, use psutil
        partitions = psutil.disk_partitions(all=True)
        
        for partition in partitions:
            try:
                drive_info = {
                    'path': partition.mountpoint,
                    'device': partition.device,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'removable': 'removable' in partition.opts.lower() if hasattr(partition, 'opts') else False
                }
                
                # Get usage if possible
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    drive_info['size'] = usage.total
                    drive_info['free'] = usage.free
                    drive_info['percent'] = usage.percent
                except:
                    pass
                
                drives.append(drive_info)
            except:
                pass
    
    return drives

def _get_drive_type_name(drive_type):
    """Convert Windows drive type to string"""
    if platform.system() == "Windows":
        import win32api
        
        drive_types = {
            win32api.DRIVE_UNKNOWN: "Unknown",
            win32api.DRIVE_NO_ROOT_DIR: "No Root Directory",
            win32api.DRIVE_REMOVABLE: "Removable",
            win32api.DRIVE_FIXED: "Fixed",
            win32api.DRIVE_REMOTE: "Network",
            win32api.DRIVE_CDROM: "CDROM",
            win32api.DRIVE_RAMDISK: "RAM Disk"
        }
        
        return drive_types.get(drive_type, "Unknown")
    else:
        return "Unknown"