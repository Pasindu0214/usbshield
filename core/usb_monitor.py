import time
import threading
import logging
import win32com.client
import win32api
import win32con
import wmi
from core.device import USBDevice
from core.whitelist import Whitelist

class USBMonitor:
    def __init__(self, whitelist=None, callback=None):
        """
        Initialize the USB monitor for Windows systems.
        
        Args:
            whitelist: A Whitelist object for checking allowed devices
            callback: A function to call when USB events are detected
        """
        self.whitelist = whitelist if whitelist else Whitelist()
        self.callback = callback
        self.running = False
        self.thread = None
        self.wmi = wmi.WMI()
        self.logger = logging.getLogger('usbshield.monitor')
        
    def start(self):
        """Start monitoring USB devices."""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor_thread, daemon=True)
        self.thread.start()
        self.logger.info("USB monitoring started")
        
        # Scan existing devices
        self._scan_existing_devices()
        
    def stop(self):
        """Stop monitoring USB devices."""
        if not self.running:
            return
            
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        self.logger.info("USB monitoring stopped")
        
    def _monitor_thread(self):
        """Thread function to monitor USB device events."""
        watcher = self.wmi.watch_for(
            notification_type="Creation",
            wmi_class="Win32_USBControllerDevice",
            delay_secs=1
        )
        
        removal_watcher = self.wmi.watch_for(
            notification_type="Deletion",
            wmi_class="Win32_USBControllerDevice",
            delay_secs=1
        )
        
        while self.running:
            try:
                # Check for new devices
                usb_device = watcher(timeout_ms=500)
                if usb_device:
                    self._handle_device_added()
                    
                # Check for removed devices    
                usb_removed = removal_watcher(timeout_ms=500)
                if usb_removed:
                    self._handle_device_removed()
                    
                time.sleep(0.5)  # Small sleep to reduce CPU usage
            except wmi.x_wmi_timed_out:
                continue
            except Exception as e:
                self.logger.error(f"Error in USB monitoring thread: {e}")
                time.sleep(1)  # Sleep longer on error
        
    def _handle_device_added(self):
        """Handle a USB device being added."""
        devices = self._get_current_devices()
        for device in devices:
            # Check if we've seen this device before (simple approach)
            device_id = device.get_identifier()
            allowed = self.whitelist.is_allowed(device)
            
            self.logger.info(f"Device connected: {device}")
            
            if self.callback:
                self.callback({
                    'action': 'connected',
                    'device': device,
                    'allowed': allowed
                })
    
    def _handle_device_removed(self):
        """Handle a USB device being removed."""
        # In Windows, we don't get specific information about which device was removed
        # We can just notify that a device was removed
        if self.callback:
            self.callback({
                'action': 'disconnected',
                'device': None
            })
    
    def _scan_existing_devices(self):
        """Scan and process existing USB devices."""
        devices = self._get_current_devices()
        for device in devices:
            allowed = self.whitelist.is_allowed(device)
            
            self.logger.info(f"Existing device: {device} (Allowed: {allowed})")
            
            if self.callback:
                self.callback({
                    'action': 'existing',
                    'device': device,
                    'allowed': allowed
                })
    
    def _get_current_devices(self):
        """
        Get a list of current USB devices.
        
        Returns:
            list: List of USBDevice objects
        """
        devices = []
        
        # Get all USB devices
        usb_devices = self.wmi.Win32_USBHub()
        pnp_devices = self.wmi.Win32_PnPEntity()
        
        for usb in usb_devices:
            # Get more info from PnP entities
            for pnp in pnp_devices:
                if pnp.PNPDeviceID and usb.DeviceID in pnp.PNPDeviceID:
                    # Extract VID and PID from the PNP ID
                    vid, pid = self._extract_vid_pid(pnp.PNPDeviceID)
                    if vid and pid:
                        device = USBDevice(
                            vendor_id=vid,
                            product_id=pid,
                            serial=self._extract_serial(pnp.PNPDeviceID),
                            manufacturer=pnp.Manufacturer,
                            product=pnp.Caption
                        )
                        devices.append(device)
                        break
        
        return devices
    
    def _extract_vid_pid(self, pnp_id):
        """
        Extract Vendor ID and Product ID from a PnP Device ID.
        
        Args:
            pnp_id: PnP Device ID string
            
        Returns:
            tuple: (vid, pid) or (None, None) if not found
        """
        try:
            # Format is usually like "USB\VID_1234&PID_5678\..."
            if "VID_" in pnp_id and "PID_" in pnp_id:
                vid_start = pnp_id.find("VID_") + 4
                vid_end = pnp_id.find("&", vid_start)
                vid = pnp_id[vid_start:vid_end]
                
                pid_start = pnp_id.find("PID_") + 4
                pid_end = pnp_id.find("\\", pid_start)
                if pid_end == -1:  # End of string
                    pid_end = len(pnp_id)
                pid = pnp_id[pid_start:pid_end]
                
                return vid, pid
        except Exception as e:
            self.logger.error(f"Error extracting VID/PID: {e}")
        
        return None, None
        
    def _extract_serial(self, pnp_id):
        """
        Extract serial number from a PnP Device ID.
        
        Args:
            pnp_id: PnP Device ID string
            
        Returns:
            str: Serial number or empty string if not found
        """
        try:
            # Format is usually like "USB\VID_1234&PID_5678\1234567890"
            parts = pnp_id.split("\\")
            if len(parts) >= 3:
                return parts[2]
        except Exception:
            pass
        
        return ""