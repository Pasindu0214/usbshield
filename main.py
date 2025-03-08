import sys
import time
import os
import psutil
import win32api
import win32con
import win32gui
import win32file
import wmi
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

class USBShield:
    def __init__(self, root):
        self.root = root
        self.root.title("USBShield - USB Security")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Initialize variables
        self.allowed_devices = set()
        self.device_log = []
        self.current_drives = set()
        self.autoblock = True  # Define autoblock attribute here, before setup_settings_tab is called
        
        # Set icon if available
        try:
            self.root.iconbitmap("usb_icon.ico")
        except:
            pass
            
        # Create menu
        self.menu_bar = tk.Menu(root)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        
        self.root.config(menu=self.menu_bar)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Device Management Tab
        self.device_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.device_frame, text="Device Management")
        
        # Settings Tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        
        # Logs Tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Logs")
        
        # Set up each tab
        self.setup_device_tab()
        self.setup_settings_tab()
        self.setup_logs_tab()
        
        # Start monitoring
        self.update_device_list()
        self.start_usb_monitoring()
    
    def setup_device_tab(self):
        # Label
        label_frame = ttk.LabelFrame(self.device_frame, text="USB Device Management")
        label_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        info_label = ttk.Label(label_frame, 
                              text="This tab shows all removable USB storage devices. You can whitelist devices to allow them to be used.")
        info_label.pack(anchor=tk.W, padx=5, pady=5)
        
        # Treeview for devices
        columns = ("Device", "Vendor ID", "Product ID", "Serial", "Status", "Actions")
        self.device_tree = ttk.Treeview(label_frame, columns=columns, show="headings", height=15)
        
        # Define column headings
        for col in columns:
            self.device_tree.heading(col, text=col)
        
        # Set column widths
        self.device_tree.column("Device", width=300)
        self.device_tree.column("Vendor ID", width=100)
        self.device_tree.column("Product ID", width=100)
        self.device_tree.column("Serial", width=150)
        self.device_tree.column("Status", width=100)
        self.device_tree.column("Actions", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(label_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscroll=scrollbar.set)
        
        # Pack tree and scrollbar
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button frame
        button_frame = ttk.Frame(self.device_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Buttons
        refresh_button = ttk.Button(button_frame, text="Refresh Devices", command=self.update_device_list)
        refresh_button.pack(side=tk.LEFT, padx=5)
        
        whitelist_all_button = ttk.Button(button_frame, text="Whitelist All", command=self.whitelist_all_devices)
        whitelist_all_button.pack(side=tk.LEFT, padx=5)
        
        remove_all_button = ttk.Button(button_frame, text="Remove All", command=self.remove_all_devices)
        remove_all_button.pack(side=tk.LEFT, padx=5)
        
        # Auto-approve checkbox
        self.auto_approve_var = tk.BooleanVar(value=False)
        auto_approve_check = ttk.Checkbutton(button_frame, text="Automatically approve devices from trusted manufacturers",
                                            variable=self.auto_approve_var)
        auto_approve_check.pack(side=tk.LEFT, padx=20)
    
    def setup_settings_tab(self):
        # Settings Frame
        settings_inner_frame = ttk.LabelFrame(self.settings_frame, text="Security Settings")
        settings_inner_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Auto-block option
        self.autoblock_var = tk.BooleanVar(value=self.autoblock)
        autoblock_check = ttk.Checkbutton(settings_inner_frame, 
                                         text="Automatically block all new USB storage devices",
                                         variable=self.autoblock_var,
                                         command=self.toggle_autoblock)
        autoblock_check.pack(anchor=tk.W, padx=10, pady=10)
        
        # Notification settings
        notification_frame = ttk.LabelFrame(settings_inner_frame, text="Notifications")
        notification_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.notify_connect_var = tk.BooleanVar(value=True)
        notify_connect_check = ttk.Checkbutton(notification_frame, 
                                              text="Show notification when USB device is connected",
                                              variable=self.notify_connect_var)
        notify_connect_check.pack(anchor=tk.W, padx=10, pady=5)
        
        self.notify_block_var = tk.BooleanVar(value=True)
        notify_block_check = ttk.Checkbutton(notification_frame, 
                                            text="Show notification when USB device is blocked",
                                            variable=self.notify_block_var)
        notify_block_check.pack(anchor=tk.W, padx=10, pady=5)
        
        # Save settings button
        save_button = ttk.Button(settings_inner_frame, text="Save Settings", command=self.save_settings)
        save_button.pack(anchor=tk.E, padx=10, pady=10)
    
    def setup_logs_tab(self):
        # Logs Frame
        logs_inner_frame = ttk.LabelFrame(self.logs_frame, text="USB Activity Logs")
        logs_inner_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for logs
        columns = ("Timestamp", "Event", "Device", "Status")
        self.logs_tree = ttk.Treeview(logs_inner_frame, columns=columns, show="headings", height=20)
        
        # Define column headings
        for col in columns:
            self.logs_tree.heading(col, text=col)
        
        # Set column widths
        self.logs_tree.column("Timestamp", width=150)
        self.logs_tree.column("Event", width=150)
        self.logs_tree.column("Device", width=300)
        self.logs_tree.column("Status", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(logs_inner_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscroll=scrollbar.set)
        
        # Pack tree and scrollbar
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button frame
        button_frame = ttk.Frame(self.logs_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Buttons
        clear_logs_button = ttk.Button(button_frame, text="Clear Logs", command=self.clear_logs)
        clear_logs_button.pack(side=tk.LEFT, padx=5)
        
        export_logs_button = ttk.Button(button_frame, text="Export Logs", command=self.export_logs)
        export_logs_button.pack(side=tk.LEFT, padx=5)
    
    def show_about(self):
        messagebox.showinfo("About USB Shield", 
                           "USB Shield v1.0\n\nA security application to monitor and control USB storage devices.\n\n"
                           "Developed by Security Team")
    
    def save_settings(self):
        # Here you would save settings to a config file
        self.autoblock = self.autoblock_var.get()
        messagebox.showinfo("Settings", "Settings saved successfully.")
    
    def toggle_autoblock(self):
        self.autoblock = self.autoblock_var.get()
    
    def update_device_list(self):
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Get all USB storage devices
        self.detect_usb_drives()
    
    def detect_usb_drives(self):
        """Detect only removable USB storage devices (flash drives)"""
        wmi_obj = wmi.WMI()
        
        # Get all disk drives
        for drive in wmi_obj.Win32_DiskDrive():
            # Check if it's a USB drive (removable media)
            if drive.InterfaceType == "USB" and drive.MediaType and "Removable" in drive.MediaType:
                # Get associated partitions and logical disks
                for partition in wmi_obj.Win32_DiskDriveToDiskPartition():
                    if partition.Antecedent.DeviceID == drive.DeviceID:
                        for logical_disk in wmi_obj.Win32_LogicalDiskToPartition():
                            if logical_disk.Antecedent == partition.Dependent:
                                # Get the drive letter
                                for disk in wmi_obj.Win32_LogicalDisk():
                                    if disk.DeviceID == logical_disk.Dependent.DeviceID:
                                        # This is a USB removable storage device
                                        device_name = f"{drive.Model} ({disk.DeviceID})"
                                        vendor_id = drive.PNPDeviceID.split("\\")[1].split("&")[0] if "VID_" in drive.PNPDeviceID else "N/A"
                                        product_id = drive.PNPDeviceID.split("\\")[1].split("&")[1] if "PID_" in drive.PNPDeviceID else "N/A"
                                        serial = drive.SerialNumber.strip() if drive.SerialNumber else "N/A"
                                        
                                        # Clean up vendor and product IDs
                                        if vendor_id != "N/A":
                                            vendor_id = vendor_id.replace("VID_", "")
                                        if product_id != "N/A":
                                            product_id = product_id.replace("PID_", "")
                                        
                                        # Determine status
                                        status = "Allowed" if serial in self.allowed_devices else "Blocked"
                                        
                                        # Add to tree
                                        item_id = self.device_tree.insert("", tk.END, values=(
                                            device_name,
                                            vendor_id,
                                            product_id,
                                            serial,
                                            status,
                                            "Remove" if status == "Allowed" else "Allow"
                                        ))
                                        
                                        # Bind double-click event to toggle status
                                        self.device_tree.tag_bind(item_id, '<Double-1>', 
                                                               lambda event, s=serial: self.toggle_device_status(s))
                                        
                                        # Log device if it's new
                                        if disk.DeviceID not in self.current_drives:
                                            self.current_drives.add(disk.DeviceID)
                                            self.log_event("Connected", device_name, status)
                                            
                                            # Notify if needed
                                            if self.notify_connect_var.get():
                                                title = "USB Device Connected"
                                                message = f"USB device connected: {device_name}\nStatus: {status}"
                                                self.show_notification(title, message)
                                            
                                            # Block if autoblock is enabled and not already allowed
                                            if self.autoblock and status == "Blocked":
                                                self.block_usb_drive(disk.DeviceID)
                                                
                                                # Notify if needed
                                                if self.notify_block_var.get():
                                                    title = "USB Device Blocked"
                                                    message = f"USB device blocked: {device_name}"
                                                    self.show_notification(title, message)
        
        # Schedule the next update
        self.root.after(1000, self.update_device_list)
    
    def toggle_device_status(self, serial):
        if serial in self.allowed_devices:
            self.allowed_devices.remove(serial)
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item, "values")
                if values[3] == serial:  # Serial is at index 3
                    self.device_tree.item(item, values=(
                        values[0], values[1], values[2], values[3], "Blocked", "Allow"
                    ))
                    self.log_event("Status Changed", values[0], "Blocked")
                    
                    # If this is a connected drive, block it
                    drive_letter = values[0].split("(")[1].split(")")[0]
                    self.block_usb_drive(drive_letter)
        else:
            self.allowed_devices.add(serial)
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item, "values")
                if values[3] == serial:  # Serial is at index 3
                    self.device_tree.item(item, values=(
                        values[0], values[1], values[2], values[3], "Allowed", "Remove"
                    ))
                    self.log_event("Status Changed", values[0], "Allowed")
                    
                    # If this is a connected drive, allow it
                    drive_letter = values[0].split("(")[1].split(")")[0]
                    self.allow_usb_drive(drive_letter)
    
    def whitelist_all_devices(self):
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item, "values")
            serial = values[3]  # Serial is at index 3
            if serial not in self.allowed_devices and serial != "N/A":
                self.allowed_devices.add(serial)
                self.device_tree.item(item, values=(
                    values[0], values[1], values[2], values[3], "Allowed", "Remove"
                ))
                self.log_event("Status Changed", values[0], "Allowed")
                
                # If this is a connected drive, allow it
                if "(" in values[0] and ")" in values[0]:
                    drive_letter = values[0].split("(")[1].split(")")[0]
                    self.allow_usb_drive(drive_letter)
    
    def remove_all_devices(self):
        self.allowed_devices.clear()
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item, "values")
            self.device_tree.item(item, values=(
                values[0], values[1], values[2], values[3], "Blocked", "Allow"
            ))
            self.log_event("Status Changed", values[0], "Blocked")
            
            # If this is a connected drive, block it
            if "(" in values[0] and ")" in values[0]:
                drive_letter = values[0].split("(")[1].split(")")[0]
                self.block_usb_drive(drive_letter)
    
    def start_usb_monitoring(self):
        """Start monitoring for new USB devices"""
        # This is handled by the update_device_list method which is called periodically
        pass
    
    def block_usb_drive(self, drive_letter):
        """Block access to the USB drive"""
        try:
            # This is a simplified implementation
            # In a real application, you would use low-level Windows API or third-party tools
            # to actually block access to the drive
            
            # For demonstration, we'll just simulate blocking by showing a message
            print(f"Blocking drive {drive_letter}")
            
            # In a real implementation, you might:
            # 1. Use DeviceIoControl API to lock the drive
            # 2. Use Group Policy to block access
            # 3. Unmount or eject the drive
            # 4. Use a kernel-level driver to intercept access
            
            # For this demo, we'll just log the action
            self.log_event("Blocked", f"Drive {drive_letter}", "Blocked")
        except Exception as e:
            print(f"Error blocking drive {drive_letter}: {e}")
    
    def allow_usb_drive(self, drive_letter):
        """Allow access to the USB drive"""
        try:
            # This is a simplified implementation
            print(f"Allowing drive {drive_letter}")
            
            # In a real implementation, you would reverse whatever blocking method was used
            
            # For this demo, we'll just log the action
            self.log_event("Allowed", f"Drive {drive_letter}", "Allowed")
        except Exception as e:
            print(f"Error allowing drive {drive_letter}: {e}")
    
    def log_event(self, event, device, status):
        """Add an event to the logs"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logs_tree.insert("", 0, values=(timestamp, event, device, status))
        
        # Also add to our internal log
        self.device_log.append({
            "timestamp": timestamp,
            "event": event,
            "device": device,
            "status": status
        })
    
    def clear_logs(self):
        """Clear all logs"""
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        self.device_log.clear()
    
    def export_logs(self):
        """Export logs to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"usb_shield_logs_{timestamp}.csv"
        
        try:
            with open(filename, "w") as f:
                f.write("Timestamp,Event,Device,Status\n")
                for log in self.device_log:
                    f.write(f"{log['timestamp']},{log['event']},{log['device']},{log['status']}\n")
            
            messagebox.showinfo("Export Logs", f"Logs exported successfully to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting logs: {e}")
    
    def show_notification(self, title, message):
        """Show a notification to the user"""
        # In a real application, you might use win10toast or another notification library
        # For this demo, we'll use a simple messagebox
        # This would be better implemented with non-blocking notifications
        print(f"NOTIFICATION: {title} - {message}")
        # Commented out to prevent blocking the application
        # messagebox.showinfo(title, message)

def main():
    root = tk.Tk()
    app = USBShield(root)
    root.mainloop()

if __name__ == "__main__":
    main()