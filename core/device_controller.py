# core/device_controller.py
import logging
import subprocess
import platform
import re
import os
import tempfile
from PyQt5.QtCore import QObject, pyqtSignal

class DeviceController(QObject):
    device_blocked = pyqtSignal(dict)
    device_allowed = pyqtSignal(dict)
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.logger = logging.getLogger('usbshield')
        self.system = platform.system()

    def handle_device_connection(self, device_info):
        """Handle a new device connection based on whitelist status"""
        is_allowed = self.config.is_device_whitelisted(device_info)
        
        if is_allowed:
            self.logger.info(f"Device allowed: {device_info['description']}")
            self.device_allowed.emit(device_info)
            return True
        else:
            if self.config.config.get('block_unknown_devices', True):
                self.logger.warning(f"Blocking unauthorized device: {device_info['description']}")
                self.block_device(device_info)
                self.device_blocked.emit(device_info)
                return False
            else:
                self.logger.info(f"Unknown device allowed (blocking disabled): {device_info['description']}")
                self.device_allowed.emit(device_info)
                return True

    def block_device(self, device_info):
        """Attempt to block the USB device"""
        if self.system == "Windows":
            # On Windows, use PowerShell to disable the device
            try:
                if 'id' in device_info and device_info['id']:
                    # Create a temporary script file
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.ps1') as script_file:
                        script_path = script_file.name
                        script_content = f"""
                        $deviceId = "{device_info['id']}"
                        $device = Get-PnpDevice -InstanceId $deviceId
                        if ($device) {{
                            Disable-PnpDevice -InstanceId $deviceId -Confirm:$false
                            Write-Host "Device disabled successfully"
                        }} else {{
                            Write-Host "Device not found"
                        }}
                        """
                        script_file.write(script_content.encode('utf-8'))
                    
                    # Run the PowerShell script with elevated privileges
                    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    # Clean up the temporary file
                    try:
                        os.unlink(script_path)
                    except:
                        pass
                    
                    if "Device disabled successfully" in result.stdout:
                        self.logger.info(f"Successfully blocked device: {device_info['description']}")
                        return True
                    else:
                        self.logger.warning(f"Failed to block device: {result.stdout} {result.stderr}")
                        return False
            except Exception as e:
                self.logger.error(f"Error blocking Windows device: {e}")
                return False
                
        elif self.system == "Linux":
            # On Linux, this would typically involve udev rules
            # For simulation purposes, we'll just log the attempt
            self.logger.info(f"Simulating blocking device on Linux: {device_info['description']}")
            self.logger.info("Note: Actual blocking requires udev rules configuration with sudo access")
            return True
            
        elif self.system == "Darwin":  # macOS
            # On macOS, this would typically involve system extensions
            # For simulation purposes, we'll just log the attempt
            self.logger.info(f"Simulating blocking device on macOS: {device_info['description']}")
            self.logger.info("Note: Actual blocking requires system extensions with admin privileges")
            return True
            
        return False

    def allow_device(self, device_info):
        """Add a device to the whitelist and enable it if it was blocked"""
        self.config.add_to_whitelist(device_info)
        self.logger.info(f"Added device to whitelist: {device_info['description']}")
        
        # Try to enable the device if it was previously blocked
        if self.system == "Windows" and 'id' in device_info and device_info['id']:
            try:
                # Create a temporary script file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.ps1') as script_file:
                    script_path = script_file.name
                    script_content = f"""
                    $deviceId = "{device_info['id']}"
                    $device = Get-PnpDevice -InstanceId $deviceId
                    if ($device) {{
                        Enable-PnpDevice -InstanceId $deviceId -Confirm:$false
                        Write-Host "Device enabled successfully"
                    }} else {{
                        Write-Host "Device not found"
                    }}
                    """
                    script_file.write(script_content.encode('utf-8'))
                
                # Run the PowerShell script with elevated privileges
                cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Clean up the temporary file
                try:
                    os.unlink(script_path)
                except:
                    pass
                
                if "Device enabled successfully" in result.stdout:
                    self.logger.info(f"Successfully enabled device: {device_info['description']}")
                    return True
                else:
                    self.logger.warning(f"Failed to enable device: {result.stdout} {result.stderr}")
                    return False
            except Exception as e:
                self.logger.error(f"Error enabling Windows device: {e}")
                return False
                
        return True