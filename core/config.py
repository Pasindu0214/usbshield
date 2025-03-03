# core/config.py
import os
import json
import logging

class Config:
    def __init__(self):
        self.config_file = os.path.join('data', 'config.json')
        self.whitelist_file = os.path.join('data', 'whitelist.json')
        self.config = {
            'auto_scan': True,
            'block_unknown_devices': True,
            'quarantine_malicious_files': True,
            'scan_all_files': True,
            'log_level': 'INFO',
            'scan_extensions': ['.exe', '.dll', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar']
        }
        self.whitelist = []
        self.logger = logging.getLogger('usbshield')

    def load_config(self):
        # Create default config if it doesn't exist
        if not os.path.exists(self.config_file):
            self.save_config()
        
        # Load config from file
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
                self.logger.info("Configuration loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            self.save_config()  # Create a new config file with default values
        
        # Load whitelist
        self.load_whitelist()

    def save_config(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
                self.logger.info("Configuration saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")

    def load_whitelist(self):
        if not os.path.exists(self.whitelist_file):
            with open(self.whitelist_file, 'w') as f:
                json.dump([], f, indent=4)
                self.logger.info("Created empty whitelist file")
        
        try:
            with open(self.whitelist_file, 'r') as f:
                self.whitelist = json.load(f)
                self.logger.info(f"Loaded {len(self.whitelist)} whitelisted devices")
        except Exception as e:
            self.logger.error(f"Error loading whitelist: {e}")
            self.whitelist = []

    def save_whitelist(self):
        try:
            with open(self.whitelist_file, 'w') as f:
                json.dump(self.whitelist, f, indent=4)
                self.logger.info("Whitelist saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving whitelist: {e}")

    def add_to_whitelist(self, device_info):
        if device_info not in self.whitelist:
            self.whitelist.append(device_info)
            self.save_whitelist()
            return True
        return False

    def remove_from_whitelist(self, device_info):
        if device_info in self.whitelist:
            self.whitelist.remove(device_info)
            self.save_whitelist()
            return True
        return False

    def is_device_whitelisted(self, device_info):
        # Check if device details match any whitelist entry
        for entry in self.whitelist:
            if (entry.get('vendor_id') == device_info.get('vendor_id') and 
                entry.get('product_id') == device_info.get('product_id')):
                return True
        return False