# core/file_monitor.py
import os
import logging
import threading
import time
import platform
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PyQt5.QtCore import QObject, pyqtSignal

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, file_monitor):
        self.file_monitor = file_monitor
        self.logger = logging.getLogger('usbshield')
    
    def on_created(self, event):
        if not event.is_directory:
            self.file_monitor.process_new_file(event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.file_monitor.process_modified_file(event.src_path)

class FileMonitor(QObject):
    new_file_detected = pyqtSignal(str)
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.logger = logging.getLogger('usbshield')
        self.observers = {}
        self.watch_paths = []
        self.running = False
        self.system = platform.system()
        self.refresh_thread = None

    def start_monitoring(self):
        if self.running:
            return
        
        self.running = True
        self.refresh_usb_paths()
        
        # Start a background thread to periodically check for new USB drives
        self.refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self.refresh_thread.start()
        
        self.logger.info("File monitoring started")

    def stop_monitoring(self):
        self.running = False
        
        # Stop and join the refresh thread if it's running
        if self.refresh_thread:
            self.refresh_thread.join(timeout=2)
        
        # Stop all observers
        for path, observer in self.observers.items():
            observer.stop()
            observer.join()
        
        self.observers.clear()
        self.watch_paths.clear()
        
        self.logger.info("File monitoring stopped")

    def _refresh_loop(self):
        while self.running:
            try:
                self.refresh_usb_paths()
                time.sleep(10)  # Check for new USB drives every 10 seconds
            except Exception as e:
                self.logger.error(f"Error in refresh loop: {e}")
                time.sleep(30)  # Longer delay on error

    def refresh_usb_paths(self):
        """Get the current USB drive paths and update observers"""
        current_paths = self._get_usb_drive_paths()
        
        # Stop monitoring paths that are no longer available
        for path in list(self.observers.keys()):
            if path not in current_paths:
                self.logger.info(f"USB drive removed: {path}")
                observer = self.observers.pop(path)
                observer.stop()
                observer.join()
                if path in self.watch_paths:
                    self.watch_paths.remove(path)
        
        # Start monitoring new paths
        for path in current_paths:
            if path not in self.observers:
                self.logger.info(f"Monitoring new USB drive: {path}")
                self._monitor_path(path)

    def _monitor_path(self, path):
        """Set up a file system observer for the given path"""
        try:
            event_handler = FileEventHandler(self)
            observer = Observer()
            observer.schedule(event_handler, path, recursive=True)
            observer.start()
            self.observers[path] = observer
            self.watch_paths.append(path)
            self.logger.info(f"Started monitoring: {path}")
        except Exception as e:
            self.logger.error(f"Error setting up file monitor for {path}: {e}")

    def _get_usb_drive_paths(self):
        """Get paths to connected USB drives"""
        paths = []
        
        if self.system == "Windows":
            import win32file
            import win32api
            
            try:
                drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
                for drive in drives:
                    if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                        paths.append(drive)
            except Exception as e:
                self.logger.error(f"Error getting Windows USB drives: {e}")
                
        elif self.system == "Linux":
            # Look for mounted removable drives in /media and /mnt
            for base_dir in ['/media', '/mnt']:
                if os.path.exists(base_dir):
                    for user_dir in os.listdir(base_dir):
                        user_path = os.path.join(base_dir, user_dir)
                        if os.path.isdir(user_path):
                            # For /media/username structure
                            if user_dir != 'cdrom':
                                for drive in os.listdir(user_path):
                                    drive_path = os.path.join(user_path, drive)
                                    if os.path.ismount(drive_path):
                                        paths.append(drive_path)
                            # For direct mounts in /mnt
                            else:
                                if os.path.ismount(user_path):
                                    paths.append(user_path)
            
        elif self.system == "Darwin":  # macOS
            # Look for volumes in /Volumes that are removable
            base_dir = '/Volumes'
            if os.path.exists(base_dir):
                for volume in os.listdir(base_dir):
                    volume_path = os.path.join(base_dir, volume)
                    if os.path.ismount(volume_path) and volume != 'Macintosh HD':
                        paths.append(volume_path)
        
        return paths

    def process_new_file(self, file_path):
        """Process a newly created file"""
        if self._should_scan_file(file_path):
            self.logger.info(f"New file detected: {file_path}")
            self.new_file_detected.emit(file_path)

    def process_modified_file(self, file_path):
        """Process a modified file"""
        # For simplicity, we'll treat modified files the same as new files
        if self._should_scan_file(file_path):
            self.logger.info(f"Modified file detected: {file_path}")
            self.new_file_detected.emit(file_path)

    def _should_scan_file(self, file_path):
        """Determine if a file should be scanned based on configuration"""
        # If scan_all_files is enabled, scan everything
        if self.config.config.get('scan_all_files', True):
            return True
        
        # Otherwise, check file extension against the list of extensions to scan
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        scan_extensions = self.config.config.get('scan_extensions', [])
        
        return ext in scan_extensions