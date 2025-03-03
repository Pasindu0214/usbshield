import json
import os
import logging
import time

class Whitelist:
    def __init__(self, filename=None):
        """
        Initialize the USB device whitelist.
        
        Args:
            filename: Path to the whitelist JSON file (optional)
        """
        self.filename = filename or os.path.join('data', 'whitelist.json')
        self.devices = []
        self.logger = logging.getLogger('usbshield.whitelist')
        
        if os.path.exists(self.filename):
            self.load()
            
    def load(self):
        """Load the whitelist from the JSON file."""
        try:
            with open(self.filename, 'r') as f:
                self.devices = json.load(f)
                self.logger.info(f"Loaded {len(self.devices)} devices from whitelist")
        except Exception as e:
            self.logger.error(f"Failed to load whitelist: {e}")
            self.devices = []
            
    def save(self):
        """Save the whitelist to the JSON file."""
        try:
            os.makedirs(os.path.dirname(self.filename), exist_ok=True)
            with open(self.filename, 'w') as f:
                json.dump(self.devices, f, indent=2)
                self.logger.info(f"Saved {len(self.devices)} devices to whitelist")
        except Exception as e:
            self.logger.error(f"Failed to save whitelist: {e}")
            
    def is_allowed(self, device):
        """
        Check if a device is allowed.
        
        Args:
            device: A USBDevice object
            
        Returns:
            bool: True if the device is allowed
        """
        device_id = device.get_identifier()
        
        # Check if the exact device is in the whitelist
        for entry in self.devices:
            if entry.get('id') == device_id:
                return True
                
        return False
        
    def add_device(self, device):
        """
        Add a device to the whitelist.
        
        Args:
            device: A USBDevice object
            
        Returns:
            bool: True if the device was added
        """
        device_id = device.get_identifier()
        
        # Check if already in whitelist
        for entry in self.devices:
            if entry.get('id') == device_id:
                return False
                
        # Add to whitelist
        self.devices.append({
            'id': device_id,
            'vendor_id': device.vendor_id,
            'product_id': device.product_id,
            'serial': device.serial,
            'manufacturer': device.manufacturer,
            'product': device.product,
            'added': int(time.time())
        })
        
        self.save()
        self.logger.info(f"Added device to whitelist: {device}")
        return True
        
    def remove_device(self, device_id):
        """
        Remove a device from the whitelist.
        
        Args:
            device_id: The device identifier
            
        Returns:
            bool: True if the device was removed
        """
        initial_count = len(self.devices)
        self.devices = [d for d in self.devices if d.get('id') != device_id]
        
        if len(self.devices) < initial_count:
            self.save()
            self.logger.info(f"Removed device from whitelist: {device_id}")
            return True
        return False