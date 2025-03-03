# core/quarantine.py
import os
import logging
import shutil
import time
from PyQt5.QtCore import QObject, pyqtSignal

class Quarantine(QObject):
    file_restored = pyqtSignal(str, str)  # original_path, quarantine_path
    file_deleted = pyqtSignal(str)  # quarantine_path
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.logger = logging.getLogger('usbshield')
        self.quarantine_dir = os.path.join('data', 'quarantine')
        
        # Create quarantine directory if it doesn't exist
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def get_quarantined_files(self):
        """Get a list of files in the quarantine directory"""
        quarantined_files = []
        
        if not os.path.exists(self.quarantine_dir):
            return quarantined_files
        
        for filename in os.listdir(self.quarantine_dir):
            file_path = os.path.join(self.quarantine_dir, filename)
            if os.path.isfile(file_path):
                file_info = {
                    'path': file_path,
                    'name': filename,
                    'size': os.path.getsize(file_path),
                    'quarantine_time': os.path.getctime(file_path)
                }
                quarantined_files.append(file_info)
        
        # Sort by quarantine time (newest first)
        quarantined_files.sort(key=lambda x: x['quarantine_time'], reverse=True)
        return quarantined_files

    def restore_file(self, quarantine_path, restore_path=None):
        """Restore a file from quarantine to its original location or a specified path"""
        try:
            if not os.path.exists(quarantine_path):
                self.logger.error(f"Quarantined file not found: {quarantine_path}")
                return False
            
            # If no restore path is specified, try to determine the original path
            if not restore_path:
                filename = os.path.basename(quarantine_path)
                # Remove timestamp suffix if present
                original_name = filename.split('_')[0] if '_' in filename else filename
                restore_path = os.path.join(os.path.expanduser("~"), "Restored", original_name)
            
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)
            
            # Copy the file to the restore location
            shutil.copy2(quarantine_path, restore_path)
            self.logger.info(f"Restored file: {quarantine_path} -> {restore_path}")
            
            # Emit signal
            self.file_restored.emit(restore_path, quarantine_path)
            return True
        except Exception as e:
            self.logger.error(f"Error restoring file {quarantine_path}: {e}")
            return False

    def delete_file(self, quarantine_path):
        """Permanently delete a file from quarantine"""
        try:
            if not os.path.exists(quarantine_path):
                self.logger.error(f"Quarantined file not found: {quarantine_path}")
                return False
            
            # Delete the file
            os.remove(quarantine_path)
            self.logger.info(f"Deleted quarantined file: {quarantine_path}")
            
            # Emit signal
            self.file_deleted.emit(quarantine_path)
            return True
        except Exception as e:
            self.logger.error(f"Error deleting file {quarantine_path}: {e}")
            return False