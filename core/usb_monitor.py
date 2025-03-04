import time
import threading
import logging
import wmi
from PyQt5.QtCore import QObject, pyqtSignal
from core.device import USBDevice
from core.whitelist import Whitelist

class USBMonitor(QObject):
    # Define signals
    device_connected = pyqtSignal(object)
    device_disconnected = pyqtSignal(object)
    
    def __init__(self, whitelist=None, callback=None):
        """
        Initialize the USB monitor for Windows systems.
        
        Args:
            whitelist: A Whitelist object for checking allowed devices
            callback: A function to call when USB events are detected
        """
        super().__init__()  # Initialize QObject
        self.whitelist = whitelist if whitelist else Whitelist()
        self.callback = callback
        self.running = False
        self.thread = None
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
        try:
            self._scan_existing_devices()
        except Exception as e:
            self.logger.error(f"Error scanning existing devices: {e}")
        
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
        try:
            # Create a new WMI connection in this thread
            w = wmi.WMI()
            
            # Set up device insertion event watcher
            device_creation = w.Win32_DeviceChangeEvent.watch_for(
                EventType=2  # Creation
            )
            
            # Set up device removal event watcher
            device_removal = w.Win32_DeviceChangeEvent.watch_for(
                EventType=3  # Removal
            )
            
            while self.running:
                try:
                    # Check for new devices (with timeout)
                    device_added = device_creation(timeout_ms=500)
                    if device_added:
                        # Handle device connection
                        self.logger.info("USB device connected")
                        # We need to scan for the new device
                        self._handle_device_added()
                        
                    # Check for removed devices (with timeout)
                    device_removed = device_removal(timeout_ms=500)
                    if device_removed:
                        # Handle device disconnection
                        self.logger.info("USB device disconnected")
                        self._handle_device_removed()
                    
                    time.sleep(0.5)  # Small sleep to reduce CPU usage
                except wmi.x_wmi_timed_out:
                    # Timeout is expected, just continue
                    continue
                except Exception as e:
                    self.logger.error(f"Error in monitor loop: {e}")
                    time.sleep(1)  # Sleep longer on error
                    
        except Exception as e:
            self.logger.error(f"Error in monitoring thread: {e}")
    
    def _handle_device_added(self):
        """Handle a USB device being added."""
        try:
            # Create a new WMI connection to avoid thread issues
            w = wmi.WMI()
            
            # Get current devices
            for usb_device in w.Win32_USBControllerDevice():
                try:
                    # Get the dependent device
                    dependent = usb_device.Dependent
                    
                    # Extract the device name from the path
                    device_id = dependent.DeviceID if hasattr(dependent, 'DeviceID') else ""
                    
                    if not device_id:
                        continue
                    
                    # Try to extract vendor and product ID
                    vid, pid = self._extract_vid_pid(device_id)
                    if not vid or not pid:
                        continue
                    
                    # Create a device object
                    device = USBDevice(
                        vendor_id=vid,
                        product_id=pid,
                        serial=self._extract_serial(device_id),
                        manufacturer=getattr(dependent, 'Manufacturer', 'Unknown'),
                        product=getattr(dependent, 'Name', 'Unknown Device')
                    )
                    
                    # Check if allowed
                    allowed = self.whitelist.is_allowed(device)
                    
                    # Emit the signal
                    event_data = {
                        'action': 'connected',
                        'device': device,
                        'allowed': allowed
                    }
                    self.device_connected.emit(event_data)
                    
                    if self.callback:
                        self.callback(event_data)
                        
                except Exception as e:
                    self.logger.error(f"Error processing device: {e}")
                
        except Exception as e:
            self.logger.error(f"Error handling device addition: {e}")
    
    def _handle_device_removed(self):
        """Handle a USB device being removed."""
        # In Windows, we don't get specific information about which device was removed
        # We can just notify that a device was removed
        event_data = {
            'action': 'disconnected',
            'device': None
        }
        
        # Emit the signal
        self.device_disconnected.emit(event_data)
        
        if self.callback:
            self.callback(event_data)
    
    def _scan_existing_devices(self):
        """Scan and process existing USB devices."""
        try:
            # Create a new WMI connection to avoid thread issues
            w = wmi.WMI()
            
            # Get all USB devices
            for usb_device in w.Win32_USBControllerDevice():
                try:
                    # Get the dependent device
                    dependent = usb_device.Dependent
                    
                    # Extract the device name from the path
                    device_id = dependent.DeviceID if hasattr(dependent, 'DeviceID') else ""
                    
                    if not device_id:
                        continue
                    
                    # Try to extract vendor and product ID
                    vid, pid = self._extract_vid_pid(device_id)
                    if not vid or not pid:
                        continue
                    
                    # Create a device object
                    device = USBDevice(
                        vendor_id=vid,
                        product_id=pid,
                        serial=self._extract_serial(device_id),
                        manufacturer=getattr(dependent, 'Manufacturer', 'Unknown'),
                        product=getattr(dependent, 'Name', 'Unknown Device')
                    )
                    
                    # Check if allowed
                    allowed = self.whitelist.is_allowed(device)
                    
                    self.logger.info(f"Existing device: {device} (Allowed: {allowed})")
                    
                    # Emit signal for existing devices
                    event_data = {
                        'action': 'existing',
                        'device': device,
                        'allowed': allowed
                    }
                    self.device_connected.emit(event_data)
                    
                    if self.callback:
                        self.callback(event_data)
                        
                except Exception as e:
                    self.logger.error(f"Error processing existing device: {e}")
                
        except Exception as e:
            self.logger.error(f"Error scanning existing devices: {e}")
    
    def _extract_vid_pid(self, device_id):
        """
        Extract Vendor ID and Product ID from a device ID.
        
        Args:
            device_id: Device ID string
            
        Returns:
            tuple: (vid, pid) or (None, None) if not found
        """
        try:
            # Format is usually like "USB\VID_1234&PID_5678\..."
            if "VID_" in device_id and "PID_" in device_id:
                vid_start = device_id.find("VID_") + 4
                vid_end = device_id.find("&", vid_start)
                vid = device_id[vid_start:vid_end]
                
                pid_start = device_id.find("PID_") + 4
                pid_end = device_id.find("\\", pid_start)
                if pid_end == -1:  # End of string
                    pid_end = len(device_id)
                pid = device_id[pid_start:pid_end]
                
                return vid, pid
        except Exception as e:
            self.logger.error(f"Error extracting VID/PID: {e}")
        
        return None, None
        
    def _extract_serial(self, device_id):
        """
        Extract serial number from a device ID.
        
        Args:
            device_id: Device ID string
            
        Returns:
            str: Serial number or empty string if not found
        """
        try:
            # Format is usually like "USB\VID_1234&PID_5678\1234567890"
            parts = device_id.split("\\")
            if len(parts) >= 3:
                return parts[2]
        except Exception:
            pass
        
        return ""