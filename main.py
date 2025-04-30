import sys
import os
import win32api
import win32con
import win32file
import wmi
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QLabel
from PyQt5.QtWidgets import QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QMessageBox
from PyQt5.QtWidgets import QDialog, QGroupBox, QFormLayout, QLineEdit, QTextEdit, QProgressBar, QMenu
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QFont, QColor
from datetime import datetime
from usb_scanner import USBScanner



# Trusted manufacturers for HID devices
TRUSTED_MANUFACTURERS = [
    "microsoft", "logitech", "apple", "dell", "hp", "lenovo", "asus", 
    "acer", "razer", "corsair", "steelseries", "cooler master", "cherry",
    "gigabyte", "lg", "samsung", "benq", "kingston", "western digital",
    "toshiba", "intel", "amd", "nvidia", "broadcom", "realtek", "crucial",
    "seagate", "sandisk", "dlink", "tplink", "netgear", "belkin", "linksys"
]

# Known malicious HID device signatures
HID_ATTACK_SIGNATURES = {
    # USB Rubber Ducky (Various versions)
    "VID_03EB&PID_2401": "USB Rubber Ducky (Original)",
    "VID_03EB&PID_2042": "USB Rubber Ducky (Modified)",
    "VID_03EB&PID_2403": "USB Rubber Ducky (Twin Duck)",
    
    # Bash Bunny
    "VID_1B4F&PID_9205": "Bash Bunny (Gen1)",
    "VID_1B4F&PID_9206": "Bash Bunny (Gen2)",
    
    # Malduino
    "VID_1B4F&PID_9207": "Malduino (Elite)",
    "VID_1B4F&PID_9208": "Malduino (Elite)",
    
    # LAN Turtle
    "VID_1D6B&PID_0102": "LAN Turtle",
    "VID_1D6B&PID_0103": "LAN Turtle (3.0)",
    
    # Packet Squirrel
    "VID_1D6B&PID_0105": "Packet Squirrel",
    
    # O.MG Cable variants
    "VID_1D6B&PID_0106": "O.MG Cable (Various Types)",
    "VID_1D6B&PID_0107": "O.MG Cable (Various Types)",
    
    # Generic suspicious keyboard emulators
    "VID_16C0&PID_05DF": "Generic HID Device (Suspicious)",
    "VID_16C0&PID_0483": "Generic MIDI Device (Suspicious)"
}

# Signal emitter for scan updates
class ScanSignalEmitter(QObject):
    scan_updated = pyqtSignal(dict)

# Signal emitter for HID device detection
class HIDSignalEmitter(QObject):
    hid_detected = pyqtSignal(dict)

# Main application class
class USBShield(QMainWindow):
    def __init__(self, ioc_file_path=None):
        super().__init__()
    
        # Initialize variables
        self.allowed_devices = set()
        self.allowed_hid_devices = set()
        self.trusted_hid_devices = set()  # For auto-approved trusted manufacturers
        self.device_log = []
        self.current_drives = set()
        self.current_hid_devices = set()
        self.autoblock = True  # Default to blocking all new devices
        self.hid_protection = True  # Default to enable HID protection
        
        # Initialize scanner with IOC file path
        self.scan_signal_emitter = ScanSignalEmitter()
        self.scan_signal_emitter.scan_updated.connect(self.update_scan_results)
        
        # Initialize HID detection signal
        self.hid_signal_emitter = HIDSignalEmitter()
        self.hid_signal_emitter.hid_detected.connect(self.handle_hid_detection)
        
        # Determine default IOC file path
        if ioc_file_path is None:
            # Look for IOC file in the same directory as the script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            default_ioc_paths = [
                os.path.join(script_dir, 'sha256_only.csv'),
                os.path.join(script_dir, 'ioc_hashes.csv'),
                os.path.join(script_dir, 'hashes.csv')
            ]
            
            # Find first existing IOC file
            ioc_file_path = next((path for path in default_ioc_paths if os.path.exists(path)), None)
        
        # Initialize scanner with IOC file path
        self.scanner = USBScanner(
            callback=self.scan_signal_emitter.scan_updated.emit, 
            ioc_file_path=ioc_file_path
        )
        
        self.current_scan_drive = None
        
        self.init_ui()
        
        # Start USB monitoring
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_device_list)
        self.timer.start(1000)  # Check every second
        
    def init_ui(self):
        self.setWindowTitle('USBShield - USB Security')
        self.setWindowIcon(QIcon('usbshield_icon.ico'))
        self.setGeometry(100, 100, 1000, 700)  # Increased size to accommodate more information
    
        # Create central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        main_layout = QVBoxLayout(self.central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.device_tab = QWidget()
        self.hid_tab = QWidget()  # New tab for HID devices
        self.settings_tab = QWidget()
        self.logs_tab = QWidget()
        self.scan_tab = QWidget()
        
        self.tabs.addTab(self.device_tab, "Storage Devices")
        self.tabs.addTab(self.hid_tab, "HID Devices")  # Add HID tab
        self.tabs.addTab(self.scan_tab, "Scan Results")
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.logs_tab, "Logs")
        
        # Setup tab contents
        self.setup_device_tab()
        self.setup_hid_tab()  # Setup HID tab
        self.setup_scan_tab()
        self.setup_settings_tab()
        self.setup_logs_tab()
        
        # Create menu bar
        self.create_menu()
        
        self.show()
    
    def create_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        # Exit action
        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)
        
        # Device menu
        device_menu = menubar.addMenu('Devices')
        
        # Refresh action
        refresh_action = device_menu.addAction('Refresh All Devices')
        refresh_action.triggered.connect(self.update_device_list)
        
        # HID protection toggle
        self.hid_protection_action = device_menu.addAction('HID Protection')
        self.hid_protection_action.setCheckable(True)
        self.hid_protection_action.setChecked(self.hid_protection)
        self.hid_protection_action.triggered.connect(self.toggle_hid_protection)
        
        # Scan menu
        scan_menu = menubar.addMenu('Scan')
        
        # Scan drive action
        scan_drive_action = scan_menu.addAction('Scan USB Drive')
        scan_drive_action.triggered.connect(self.scan_selected_drive)
        
        # Stop scan action
        stop_scan_action = scan_menu.addAction('Stop Scan')
        stop_scan_action.triggered.connect(self.stop_scan)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        # About action
        about_action = help_menu.addAction('About')
        about_action.triggered.connect(self.show_about_dialog)
    
    def setup_device_tab(self):
        layout = QVBoxLayout()
        
        # Add informational label
        info_label = QLabel("USB Storage Device Management")
        info_label.setFont(QFont('Arial', 12, QFont.Bold))
        layout.addWidget(info_label)
        
        description_label = QLabel("This tab shows all USB removable storage devices that have been connected to your computer. You can whitelist devices to allow them to be used.")
        layout.addWidget(description_label)
        
        # Create table for devices
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(7)
        self.device_table.setHorizontalHeaderLabels(["Device", "Vendor ID", "Product ID", "Serial", "Status", "Actions", "Scan"])
        self.device_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        # Enable right-click menu
        self.device_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self.show_device_context_menu)
        
        layout.addWidget(self.device_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Add buttons
        refresh_button = QPushButton("Refresh Devices")
        refresh_button.clicked.connect(self.update_device_list)
        button_layout.addWidget(refresh_button)
        
        whitelist_all_button = QPushButton("Whitelist All")
        whitelist_all_button.clicked.connect(self.whitelist_all_devices)
        button_layout.addWidget(whitelist_all_button)
        
        remove_all_button = QPushButton("Remove All")
        remove_all_button.clicked.connect(self.remove_all_devices)
        button_layout.addWidget(remove_all_button)
        
        layout.addLayout(button_layout)
        
        # Auto-approve checkbox
        self.auto_approve_checkbox = QCheckBox("Automatically approve devices from trusted manufacturers")
        layout.addWidget(self.auto_approve_checkbox)
        
        self.device_tab.setLayout(layout)
    
    def setup_hid_tab(self):
        layout = QVBoxLayout()
        
        # Add informational label
        info_label = QLabel("HID Device Management")
        info_label.setFont(QFont('Arial', 12, QFont.Bold))
        layout.addWidget(info_label)
        
        description_label = QLabel("This tab shows all Human Interface Devices (HIDs) that have been connected to your computer. "
                                  "Suspicious HID devices may be used for keyboard injection attacks.")
        layout.addWidget(description_label)
        
        # Create table for HID devices
        self.hid_table = QTableWidget()
        self.hid_table.setColumnCount(8)
        self.hid_table.setHorizontalHeaderLabels([
            "Device", "Vendor ID", "Product ID", "Serial", "Type", "Risk Level", "Status", "Actions"
        ])
        self.hid_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.hid_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        # Enable right-click menu
        self.hid_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hid_table.customContextMenuRequested.connect(self.show_hid_context_menu)
        
        layout.addWidget(self.hid_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Add buttons
        refresh_button = QPushButton("Refresh HID Devices")
        refresh_button.clicked.connect(self.update_hid_device_list)
        button_layout.addWidget(refresh_button)
        
        whitelist_all_button = QPushButton("Whitelist All")
        whitelist_all_button.clicked.connect(self.whitelist_all_hid_devices)
        button_layout.addWidget(whitelist_all_button)
        
        remove_all_button = QPushButton("Block All")
        remove_all_button.clicked.connect(self.block_all_hid_devices)
        button_layout.addWidget(remove_all_button)
        
        layout.addLayout(button_layout)
        
        # Auto-approve HID checkbox
        self.auto_approve_hid_checkbox = QCheckBox("Automatically approve HID devices from trusted manufacturers")
        self.auto_approve_hid_checkbox.setChecked(True)
        layout.addWidget(self.auto_approve_hid_checkbox)
        
        self.hid_tab.setLayout(layout)
    
    def setup_scan_tab(self):
        layout = QVBoxLayout()
        
        # Add informational label
        info_label = QLabel("USB Drive Scan Results")
        info_label.setFont(QFont('Arial', 12, QFont.Bold))
        layout.addWidget(info_label)
        
        # Scan status
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Current scan:"))
        self.scan_status_label = QLabel("No scan in progress")
        status_layout.addWidget(self.scan_status_label)
        status_layout.addStretch()
        
        # Progress bar
        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setTextVisible(False)
        self.scan_progress_bar.setRange(0, 0)  # Indeterminate progress
        self.scan_progress_bar.hide()
        
        layout.addLayout(status_layout)
        layout.addWidget(self.scan_progress_bar)
        
        # Create table for suspicious files
        self.suspicious_files_table = QTableWidget()
        self.suspicious_files_table.setColumnCount(3)
        self.suspicious_files_table.setHorizontalHeaderLabels(["File Path", "Reason", "SHA-256 Hash"])
        self.suspicious_files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.suspicious_files_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        
        # Enable right-click menu
        self.suspicious_files_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.suspicious_files_table.customContextMenuRequested.connect(self.show_file_context_menu)
        
        layout.addWidget(QLabel("Suspicious Files:"))
        layout.addWidget(self.suspicious_files_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Add buttons
        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.stop_scan_button.setEnabled(False)
        button_layout.addWidget(self.stop_scan_button)
        
        quarantine_all_button = QPushButton("Quarantine All")
        quarantine_all_button.clicked.connect(self.quarantine_all_files)
        button_layout.addWidget(quarantine_all_button)
        
        clear_results_button = QPushButton("Clear Results")
        clear_results_button.clicked.connect(self.clear_scan_results)
        button_layout.addWidget(clear_results_button)
        
        layout.addLayout(button_layout)
        
        self.scan_tab.setLayout(layout)
    
    def setup_settings_tab(self):
        layout = QVBoxLayout()
        
        # Create settings group for storage devices
        storage_group = QGroupBox("USB Storage Settings")
        storage_layout = QVBoxLayout()
        
        # Auto-block option
        self.autoblock_checkbox = QCheckBox("Automatically block all new USB storage devices")
        self.autoblock_checkbox.setChecked(self.autoblock)
        self.autoblock_checkbox.stateChanged.connect(self.toggle_autoblock)
        storage_layout.addWidget(self.autoblock_checkbox)
        
        # Auto-scan option
        self.autoscan_checkbox = QCheckBox("Automatically scan new USB devices")
        self.autoscan_checkbox.setChecked(True)
        storage_layout.addWidget(self.autoscan_checkbox)
        
        storage_group.setLayout(storage_layout)
        layout.addWidget(storage_group)
        
        # Create settings group for HID devices
        hid_group = QGroupBox("HID Device Settings")
        hid_layout = QVBoxLayout()
        
        # HID protection option
        self.hid_protection_checkbox = QCheckBox("Enable HID device protection")
        self.hid_protection_checkbox.setChecked(self.hid_protection)
        self.hid_protection_checkbox.stateChanged.connect(self.toggle_hid_protection_checkbox)
        hid_layout.addWidget(self.hid_protection_checkbox)
        
        # Auto-approve trusted manufacturers
        self.hid_trusted_checkbox = QCheckBox("Automatically approve HID devices from trusted manufacturers")
        self.hid_trusted_checkbox.setChecked(True)
        hid_layout.addWidget(self.hid_trusted_checkbox)
        
        # Block composite HID devices option
        self.block_composite_checkbox = QCheckBox("Block composite HID devices (devices with multiple interfaces)")
        self.block_composite_checkbox.setChecked(True)
        hid_layout.addWidget(self.block_composite_checkbox)
        
        # Block generic HID devices option
        self.block_generic_checkbox = QCheckBox("Block generic unnamed HID devices")
        self.block_generic_checkbox.setChecked(True)
        hid_layout.addWidget(self.block_generic_checkbox)
        
        hid_group.setLayout(hid_layout)
        layout.addWidget(hid_group)
        
        # Notification settings
        notification_group = QGroupBox("Notifications")
        notification_layout = QVBoxLayout()
        
        self.notify_connect_checkbox = QCheckBox("Show notification when USB device is connected")
        self.notify_connect_checkbox.setChecked(True)
        notification_layout.addWidget(self.notify_connect_checkbox)
        
        self.notify_block_checkbox = QCheckBox("Show notification when USB device is blocked")
        self.notify_block_checkbox.setChecked(True)
        notification_layout.addWidget(self.notify_block_checkbox)
        
        self.notify_scan_checkbox = QCheckBox("Show notification when scan completes")
        self.notify_scan_checkbox.setChecked(True)
        notification_layout.addWidget(self.notify_scan_checkbox)
        
        self.notify_hid_checkbox = QCheckBox("Show notification for suspicious HID devices")
        self.notify_hid_checkbox.setChecked(True)
        notification_layout.addWidget(self.notify_hid_checkbox)
        
        notification_group.setLayout(notification_layout)
        layout.addWidget(notification_group)
        
        # Save button
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_settings)
        layout.addWidget(save_button, 0, Qt.AlignRight)
        
        self.settings_tab.setLayout(layout)
    
    def setup_logs_tab(self):
        layout = QVBoxLayout()
        
        # Add informational label
        info_label = QLabel("USB Activity Logs")
        info_label.setFont(QFont('Arial', 12, QFont.Bold))
        layout.addWidget(info_label)
        
        # Create table for logs
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(4)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "Event", "Device", "Status"])
        self.logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        
        layout.addWidget(self.logs_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Add buttons
        clear_button = QPushButton("Clear Logs")
        clear_button.clicked.connect(self.clear_logs)
        button_layout.addWidget(clear_button)
        
        export_button = QPushButton("Export Logs")
        export_button.clicked.connect(self.export_logs)
        button_layout.addWidget(export_button)
        
        layout.addLayout(button_layout)
        
        self.logs_tab.setLayout(layout)
    
    def update_device_list(self):
        # Clear existing items
        self.device_table.setRowCount(0)
        
        # Get USB removable storage devices
        self.detect_usb_drives()
        
        # Get HID devices
        self.update_hid_device_list()
    
    def detect_usb_drives(self):
        """Detect only removable USB storage devices (flash drives)"""
        wmi_obj = wmi.WMI()
        
        # Get all removable drives
        try:
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
                                            
                                            # Add to table
                                            row_position = self.device_table.rowCount()
                                            self.device_table.insertRow(row_position)
                                            
                                            self.device_table.setItem(row_position, 0, QTableWidgetItem(device_name))
                                            self.device_table.setItem(row_position, 1, QTableWidgetItem(vendor_id))
                                            self.device_table.setItem(row_position, 2, QTableWidgetItem(product_id))
                                            self.device_table.setItem(row_position, 3, QTableWidgetItem(serial))
                                            self.device_table.setItem(row_position, 4, QTableWidgetItem(status))
                                            
                                            # Add action button
                                            action_button = QPushButton("Remove" if status == "Allowed" else "Allow")
                                            action_button.clicked.connect(lambda checked, s=serial: self.toggle_device_status(s))
                                            self.device_table.setCellWidget(row_position, 5, action_button)
                                            
                                            # Add scan button
                                            scan_button = QPushButton("Scan")
                                            scan_button.clicked.connect(lambda checked, d=disk.DeviceID: self.start_scan(d))
                                            self.device_table.setCellWidget(row_position, 6, scan_button)
                                            
                                            # Log device if it's new
                                            if disk.DeviceID not in self.current_drives:
                                                self.current_drives.add(disk.DeviceID)
                                                self.log_event("Connected", device_name, status)
                                                
                                                # Notify if needed
                                                if self.notify_connect_checkbox.isChecked():
                                                    self.show_notification("USB Device Connected", 
                                                                          f"USB device connected: {device_name}\nStatus: {status}")
                                                
                                                # Auto-scan if enabled
                                                if self.autoscan_checkbox.isChecked():
                                                    self.start_scan(disk.DeviceID)
                                                
                                                # Block if autoblock is enabled and not already allowed
                                                if self.autoblock and status == "Blocked":
                                                    self.block_usb_drive(disk.DeviceID)
                                                    
                                                    # Notify if needed
                                                    if self.notify_block_checkbox.isChecked():
                                                        self.show_notification("USB Device Blocked", 
                                                                              f"USB device blocked: {device_name}")
        except Exception as e:
            print(f"Error detecting USB drives: {e}")
    
    def update_hid_device_list(self):
        """Detect and show HID devices"""
        try:
            # Clear existing HID devices list
            self.hid_table.setRowCount(0)
            
            # Get all USB HID devices using WMI
            wmi_obj = wmi.WMI()
            
            # Track current set of device IDs to detect new devices
            current_device_ids = set()
            
            # Get all HID devices
            for device in wmi_obj.Win32_USBControllerDevice():
                try:
                    # Get dependent device
                    dependent_device = device.Dependent
                    device_id = dependent_device.DeviceID
                except AttributeError as e:
                    print(f"Error processing device: {e}")
                    continue
                
                # Skip non-HID devices
                if "HID" not in device_id.upper():
                    continue
                
                # Add to current set
                current_device_ids.add(device_id)
                
                # Rest of the method continues here... (everything below should be indented to this level)
                # Check if this is a new device
                is_new_device = device_id not in self.current_hid_devices
                
                # Extract device information
                device_name = dependent_device.Caption if hasattr(dependent_device, 'Caption') else "Unknown Device"
                
                # ... (rest of the method remains the same, just ensure consistent indentation)
            
            # Check for disconnected devices
            disconnected_devices = self.current_hid_devices - current_device_ids
            for device_id in disconnected_devices:
                # Log disconnected device
                self.log_event("HID Disconnected", device_id, "Removed")
                
                # Remove from current devices
                self.current_hid_devices.remove(device_id)
        
        except Exception as e:
            print(f"Error detecting HID devices: {e}")
    
    def determine_hid_type(self, device_name, device_id):
        """Determine the type of HID device based on its name and ID"""
        device_name_lower = device_name.lower()
        device_id_lower = device_id.lower()
        
        # Check for keyboard
        if "keyboard" in device_name_lower or "kbd" in device_id_lower:
            return "Keyboard"
        # Check for mouse
        elif "mouse" in device_name_lower:
            return "Mouse"
        # Check for touchpad
        elif "touchpad" in device_name_lower or "pointing" in device_name_lower:
            return "Touchpad"
        # Check for gamepad/joystick
        elif "gamepad" in device_name_lower or "joystick" in device_name_lower or "game" in device_name_lower:
            return "Game Controller"
        # Check for composite device
        elif "composite" in device_name_lower or "collection" in device_name_lower:
            return "Composite Device"
        # Default to Generic HID
        else:
            return "Generic HID"
    
    def is_trusted_manufacturer(self, device_name):
        """Check if the device is from a trusted manufacturer"""
        device_name_lower = device_name.lower()
        
        for manufacturer in TRUSTED_MANUFACTURERS:
            if manufacturer.lower() in device_name_lower:
                return True
        
        return False
    
    def assess_hid_risk(self, device_name, vid_pid, device_id, device_type):
        """Assess the risk level of an HID device"""
        device_name_lower = device_name.lower()
        device_id_lower = device_id.lower()
        
        # Check against known attack tool signatures
        if vid_pid in HID_ATTACK_SIGNATURES:
            return "High", f"Matches known attack tool: {HID_ATTACK_SIGNATURES[vid_pid]}"
        
        # Check for suspicious names
        suspicious_terms = ["rubber ducky", "malduino", "bash bunny", "payload", "hak5", 
                           "teensy", "digispark", "badusb", "evil", "hack", "attack"]
        
        for term in suspicious_terms:
            if term in device_name_lower or term in device_id_lower:
                return "High", f"Suspicious keyword detected: {term}"
        
        # Check for generic unnamed devices
        if "hid" in device_name_lower and len(device_name_lower) < 20:
            return "Medium", "Generic unnamed HID device"
            
        if ("usb" in device_name_lower and "device" in device_name_lower and 
            "keyboard" not in device_name_lower and "mouse" not in device_name_lower):
            return "Medium", "Generic USB device with minimal identification"
        
        # Check for composite devices
        if device_type == "Composite Device":
            return "Medium", "Composite HID device with multiple interfaces"
        
        # Check if from trusted manufacturer
        if self.is_trusted_manufacturer(device_name):
            return "Low", "Device from trusted manufacturer"
        
        # Default risk level
        return "Low", "Standard HID device"
    
    def get_risk_color(self, risk_level):
        """Get the QColor for a risk level"""
        if risk_level == "High":
            return QColor(255, 200, 200)  # Light red
        elif risk_level == "Medium":
            return QColor(255, 235, 156)  # Light yellow
        else:
            return QColor(255, 255, 255)  # White
    
    def toggle_hid_device_status(self, device_id):
        """Toggle the status of an HID device between allowed and blocked"""
        if device_id in self.allowed_hid_devices:
            self.allowed_hid_devices.remove(device_id)
            status = "Blocked"
            action = "Allow"
            
            # Find device name from the table
            device_name = self.find_hid_device_name(device_id)
            
            # Block the device
            self.block_hid_device(device_id, device_name)
        else:
            self.allowed_hid_devices.add(device_id)
            status = "Allowed"
            action = "Block"
            
            # Find device name from the table
            device_name = self.find_hid_device_name(device_id)
            
            # Allow the device
            self.allow_hid_device(device_id, device_name)
        
        # Update table
        for row in range(self.hid_table.rowCount()):
            name_item = self.hid_table.item(row, 0)
            if name_item and name_item.toolTip() == device_id:
                # Update status
                self.hid_table.item(row, 6).setText(status)
                
                # Update action button
                action_button = QPushButton(action)
                action_button.clicked.connect(lambda checked, d=device_id: self.toggle_hid_device_status(d))
                self.hid_table.setCellWidget(row, 7, action_button)
                
                # Get device name
                device_name = name_item.text()
                
                # Log event
                self.log_event("HID Status Changed", device_name, status)
                break
    
    def find_hid_device_name(self, device_id):
        """Find device name from device ID in the HID table"""
        for row in range(self.hid_table.rowCount()):
            name_item = self.hid_table.item(row, 0)
            if name_item and name_item.toolTip() == device_id:
                return name_item.text()
        return device_id  # Return the device ID if name not found
    
    def block_hid_device(self, device_id, device_name):
        """Block an HID device"""
        try:
            print(f"Blocking HID device: {device_name} ({device_id})")
            # This is a simplified implementation
            # In a real implementation, you would use the Windows API or driver to block the device
            
            # Log the action
            self.log_event("HID Blocked", device_name, "Blocked")
            
            # Show notification if needed
            if self.notify_block_checkbox.isChecked():
                self.show_notification("HID Device Blocked", 
                                      f"HID device blocked: {device_name}")
        except Exception as e:
            print(f"Error blocking HID device {device_name}: {e}")
    
    def allow_hid_device(self, device_id, device_name):
        """Allow an HID device"""
        try:
            print(f"Allowing HID device: {device_name} ({device_id})")
            # This is a simplified implementation
            # In a real implementation, you would use the Windows API or driver to allow the device
            
            # Log the action
            self.log_event("HID Allowed", device_name, "Allowed")
        except Exception as e:
            print(f"Error allowing HID device {device_name}: {e}")
    
    def whitelist_all_hid_devices(self):
        """Whitelist all HID devices"""
        for row in range(self.hid_table.rowCount()):
            name_item = self.hid_table.item(row, 0)
            device_id = name_item.toolTip() if name_item else None
            
            if device_id and device_id not in self.allowed_hid_devices:
                self.allowed_hid_devices.add(device_id)
                
                # Update status
                self.hid_table.item(row, 6).setText("Allowed")
                
                # Update action button
                action_button = QPushButton("Block")
                action_button.clicked.connect(lambda checked, d=device_id: self.toggle_hid_device_status(d))
                self.hid_table.setCellWidget(row, 7, action_button)
                
                # Log event
                device_name = name_item.text() if name_item else device_id
                self.log_event("HID Status Changed", device_name, "Allowed")
                
                # Allow the device
                self.allow_hid_device(device_id, device_name)
    
    def block_all_hid_devices(self):
        """Block all HID devices"""
        # Clear allowed HID devices list
        self.allowed_hid_devices.clear()
        
        # Update all rows
        for row in range(self.hid_table.rowCount()):
            name_item = self.hid_table.item(row, 0)
            device_id = name_item.toolTip() if name_item else None
            
            if device_id:
                # Update status
                self.hid_table.item(row, 6).setText("Blocked")
                
                # Update action button
                action_button = QPushButton("Allow")
                action_button.clicked.connect(lambda checked, d=device_id: self.toggle_hid_device_status(d))
                self.hid_table.setCellWidget(row, 7, action_button)
                
                # Log event
                device_name = name_item.text() if name_item else device_id
                self.log_event("HID Status Changed", device_name, "Blocked")
                
                # Block the device
                self.block_hid_device(device_id, device_name)
    
    def toggle_hid_protection(self, state):
        """Toggle HID protection"""
        self.hid_protection = state
        self.hid_protection_checkbox.setChecked(state)
        
        # Log the change
        status = "Enabled" if state else "Disabled"
        self.log_event("HID Protection", status, "Setting Changed")
        
        # Show notification
        self.show_notification("HID Protection", f"HID protection {status.lower()}")
    
    def toggle_hid_protection_checkbox(self, state):
        """Toggle HID protection from checkbox"""
        checked = state == Qt.Checked
        self.hid_protection = checked
        self.hid_protection_action.setChecked(checked)
        
        # Log the change
        status = "Enabled" if checked else "Disabled"
        self.log_event("HID Protection", status, "Setting Changed")
    
    def handle_hid_detection(self, data):
        """Handle HID detection signals"""
        if not data:
            return
        
        device_id = data.get('device_id', '')
        device_name = data.get('device_name', '')
        risk_level = data.get('risk_level', 'Low')
        risk_reason = data.get('risk_reason', '')
        
        # For high-risk devices, show notification and block
        if risk_level == "High" and self.hid_protection:
            self.show_notification("Suspicious HID Device Detected", 
                                 f"High-risk HID device detected: {device_name}\n"
                                 f"Reason: {risk_reason}")
            
            # Block the device
            self.block_hid_device(device_id, device_name)
    
    def toggle_device_status(self, serial):
        if serial in self.allowed_devices:
            self.allowed_devices.remove(serial)
            status = "Blocked"
            action = "Allow"
        else:
            self.allowed_devices.add(serial)
            status = "Allowed"
            action = "Remove"
        
        # Update table
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 3).text() == serial:
                # Update status
                self.device_table.item(row, 4).setText(status)
                
                # Update action button
                action_button = QPushButton(action)
                action_button.clicked.connect(lambda checked, s=serial: self.toggle_device_status(s))
                self.device_table.setCellWidget(row, 5, action_button)
                
                # Get device name
                device_name = self.device_table.item(row, 0).text()
                
                # Log event
                self.log_event("Status Changed", device_name, status)
                
                # Get drive letter and update device status
                drive_letter = device_name.split("(")[1].split(")")[0]
                if status == "Blocked":
                    self.block_usb_drive(drive_letter)
                else:
                    self.allow_usb_drive(drive_letter)
    
    def whitelist_all_devices(self):
        # Add all devices to allowed list
        for row in range(self.device_table.rowCount()):
            serial = self.device_table.item(row, 3).text()
            if serial != "N/A" and serial not in self.allowed_devices:
                self.allowed_devices.add(serial)
                
                # Update status
                self.device_table.item(row, 4).setText("Allowed")
                
                # Update action button
                action_button = QPushButton("Remove")
                action_button.clicked.connect(lambda checked, s=serial: self.toggle_device_status(s))
                self.device_table.setCellWidget(row, 5, action_button)
                
                # Get device name and drive letter
                device_name = self.device_table.item(row, 0).text()
                
                # Log event
                self.log_event("Status Changed", device_name, "Allowed")
                
                # Allow the drive
                if "(" in device_name and ")" in device_name:
                    drive_letter = device_name.split("(")[1].split(")")[0]
                    self.allow_usb_drive(drive_letter)
    
    def remove_all_devices(self):
        # Clear allowed devices list
        self.allowed_devices.clear()
        
        # Update all rows
        for row in range(self.device_table.rowCount()):
            serial = self.device_table.item(row, 3).text()
            
            # Update status
            self.device_table.item(row, 4).setText("Blocked")
            
            # Update action button
            action_button = QPushButton("Allow")
            action_button.clicked.connect(lambda checked, s=serial: self.toggle_device_status(s))
            self.device_table.setCellWidget(row, 5, action_button)
            
            # Get device name
            device_name = self.device_table.item(row, 0).text()
            
            # Log event
            self.log_event("Status Changed", device_name, "Blocked")
            
            # Block the drive
            if "(" in device_name and ")" in device_name:
                drive_letter = device_name.split("(")[1].split(")")[0]
                self.block_usb_drive(drive_letter)
    
    def toggle_autoblock(self, state):
        self.autoblock = state == Qt.Checked
    
    def save_settings(self):
        # Update storage settings
        self.autoblock = self.autoblock_checkbox.isChecked()
        
        # Update HID settings
        self.hid_protection = self.hid_protection_checkbox.isChecked()
        self.hid_protection_action.setChecked(self.hid_protection)
        
        QMessageBox.information(self, "Settings", "Settings saved successfully!")
    
    def block_usb_drive(self, drive_letter):
        try:
            print(f"Blocking drive {drive_letter}")
            # This is a simplified implementation
            # In a real implementation, you would use the Windows API to block access
            
            # Example of how you might do this (commented out for safety):
            # win32file.DeviceIoControl(handle, control_code, input_buffer, output_buffer_size)
            
            # Log the action
            self.log_event("Blocked", f"Drive {drive_letter}", "Blocked")
        except Exception as e:
            print(f"Error blocking drive {drive_letter}: {e}")
    
    def allow_usb_drive(self, drive_letter):
        try:
            print(f"Allowing drive {drive_letter}")
            # This is a simplified implementation
            # In a real implementation, you would use the Windows API to allow access
            
            # Log the action
            self.log_event("Allowed", f"Drive {drive_letter}", "Allowed")
        except Exception as e:
            print(f"Error allowing drive {drive_letter}: {e}")
    
    def log_event(self, event, device, status):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add to table
        row_position = self.logs_table.rowCount()
        self.logs_table.insertRow(row_position)
        
        self.logs_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
        self.logs_table.setItem(row_position, 1, QTableWidgetItem(event))
        self.logs_table.setItem(row_position, 2, QTableWidgetItem(device))
        self.logs_table.setItem(row_position, 3, QTableWidgetItem(status))
        
        # Color code high-risk events
        if "High-risk" in status or "suspicious" in status.lower():
            for col in range(4):
                self.logs_table.item(row_position, col).setBackground(QColor(255, 200, 200))
        
        # Also add to internal log
        self.device_log.append({
            "timestamp": timestamp,
            "event": event,
            "device": device,
            "status": status
        })
    
    def clear_logs(self):
        self.logs_table.setRowCount(0)
        self.device_log.clear()
    
    def export_logs(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"usb_shield_logs_{timestamp}.csv"
        
        try:
            with open(filename, "w") as f:
                f.write("Timestamp,Event,Device,Status\n")
                for log in self.device_log:
                    f.write(f"{log['timestamp']},{log['event']},{log['device']},{log['status']}\n")
            
            QMessageBox.information(self, "Export Logs", f"Logs exported successfully to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting logs: {e}")
    
    def show_notification(self, title, message):
        print(f"NOTIFICATION: {title} - {message}")
        # In a real application, you might use a system notification
        # For this demo, we'll use a simple message box, but set it to non-modal
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setWindowModality(Qt.NonModal)
        msg.show()
    
    def show_about_dialog(self):
        QMessageBox.about(self, "About USB Shield", 
                         "USB Shield v1.0\n\nA security application to monitor and control USB storage devices "
                         "and protect against HID-based attacks.\n\n"
                         "Developed by Pasindu & Chathurka.")
    
    def show_device_context_menu(self, position):
        menu = QMenu()
        
        # Get selected row
        indexes = self.device_table.selectedIndexes()
        if indexes:
            row = indexes[0].row()
            
            # Get device info
            device_name = self.device_table.item(row, 0).text()
            serial = self.device_table.item(row, 3).text()
            status = self.device_table.item(row, 4).text()
            
            # Add menu items
            if status == "Blocked":
                allow_action = menu.addAction("Allow Device")
                allow_action.triggered.connect(lambda: self.toggle_device_status(serial))
            else:
                block_action = menu.addAction("Block Device")
                block_action.triggered.connect(lambda: self.toggle_device_status(serial))
            
            # Add scan option
            scan_action = menu.addAction("Scan Device")
            drive_letter = device_name.split("(")[1].split(")")[0]
            scan_action.triggered.connect(lambda: self.start_scan(drive_letter))
            
            # Execute the menu
            menu.exec_(self.device_table.viewport().mapToGlobal(position))
    
    def show_hid_context_menu(self, position):
        menu = QMenu()
        
        # Get selected row
        indexes = self.hid_table.selectedIndexes()
        if indexes:
            row = indexes[0].row()
            
            # Get device info
            name_item = self.hid_table.item(row, 0)
            device_id = name_item.toolTip() if name_item else None
            status = self.hid_table.item(row, 6).text()
            
            if device_id:
                # Add menu items
                if status == "Blocked":
                    allow_action = menu.addAction("Allow Device")
                    allow_action.triggered.connect(lambda: self.toggle_hid_device_status(device_id))
                else:
                    block_action = menu.addAction("Block Device")
                    block_action.triggered.connect(lambda: self.toggle_hid_device_status(device_id))
                
                # Execute the menu
                menu.exec_(self.hid_table.viewport().mapToGlobal(position))
    
    def show_file_context_menu(self, position):
        menu = QMenu()
        
        # Get selected row
        indexes = self.suspicious_files_table.selectedIndexes()
        if indexes:
            row = indexes[0].row()
            
            # Get file path
            file_path = self.suspicious_files_table.item(row, 0).text()
            
            # Add menu items
            quarantine_action = menu.addAction("Quarantine File")
            quarantine_action.triggered.connect(lambda: self.quarantine_file(file_path))
            
            delete_action = menu.addAction("Delete File")
            delete_action.triggered.connect(lambda: self.delete_file(file_path))
            
            open_folder_action = menu.addAction("Open Containing Folder")
            open_folder_action.triggered.connect(lambda: self.open_containing_folder(file_path))
            
            # Execute the menu
            menu.exec_(self.suspicious_files_table.viewport().mapToGlobal(position))
    
    def start_scan(self, drive_letter):
        """Start scanning a USB drive."""
        if self.scanner.is_scanning:
            QMessageBox.warning(self, "Scan in Progress", "Another scan is already in progress. Please wait for it to complete.")
            return
        
        # Update UI
        self.scan_status_label.setText(f"Scanning drive {drive_letter}...")
        self.scan_progress_bar.show()
        self.stop_scan_button.setEnabled(True)
        self.current_scan_drive = drive_letter
        
        # Show scan tab
        self.tabs.setCurrentWidget(self.scan_tab)
        
        # Start scan
        result = self.scanner.scan_drive(drive_letter)
        
        # Log event
        self.log_event("Scan Started", f"Drive {drive_letter}", result["status"])
    
    def scan_selected_drive(self):
        """Scan the currently selected drive in the device table."""
        selected_rows = self.device_table.selectedIndexes()
        if not selected_rows:
            QMessageBox.warning(self, "No Drive Selected", "Please select a USB drive to scan.")
            return
        
        # Get the drive letter
        row = selected_rows[0].row()
        device_name = self.device_table.item(row, 0).text()
        drive_letter = device_name.split("(")[1].split(")")[0]
        
        # Start scan
        self.start_scan(drive_letter)
    
    def stop_scan(self):
        """Stop the current scan."""
        if not self.scanner.is_scanning:
            return
        
        result = self.scanner.stop_scanning()
        self.scan_status_label.setText(result["message"])
        
        # Log event
        self.log_event("Scan Stopped", f"Drive {self.current_scan_drive}", result["status"])
    
    def update_scan_results(self, results):
        """Update the scan results UI with the latest scan results."""
        # For debugging
        print(f"Received scan update: {results}")
        
        # Update status for in-progress scan
        if results["status"] == "in_progress":
            # Get scan info
            scan_info = results.get('scan_info', {})
            
            files_scanned = scan_info.get('files_scanned', 0)
            total_files = scan_info.get('total_files', 0)
            elapsed_time = scan_info.get('elapsed_time', 0)
            estimated_remaining_time = scan_info.get('estimated_remaining_time', 0)
            start_time = scan_info.get('start_time', time.time())

            # Format times
            elapsed_str = f"{elapsed_time:.2f} seconds"
            remaining_str = f"{estimated_remaining_time:.2f} seconds"
            start_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

            # Update status label
            status_msg = (f"Scanning: {files_scanned}/{total_files} files "
                        f"| Started: {start_time_str} "
                        f"| Elapsed: {elapsed_str} "
                        f"| Estimated Remaining: {remaining_str}")
            
            self.scan_status_label.setText(status_msg)
            
            # Update progress bar with proper configuration
            if total_files > 0:
                progress_value = int((files_scanned / total_files) * 100)
                
                # Make progress bar determinate (with a range)
                self.scan_progress_bar.setRange(0, 100)
                self.scan_progress_bar.setValue(progress_value)
                self.scan_progress_bar.setFormat(f"{progress_value}%")
                self.scan_progress_bar.setTextVisible(True)
                self.scan_progress_bar.show()
            else:
                # If total_files is 0, use indeterminate progress bar
                self.scan_progress_bar.setRange(0, 0)
                self.scan_progress_bar.show()

        # Update status for completed scan
        elif results["status"] == "completed":
            files_scanned = results.get('files_scanned', 0)
            ioc_file_count = len(results.get('suspicious_files', []))
            yara_match_count = len(results.get('yara_matches', []))
            scan_time = results.get('scan_time', 0)
            
            # Create status message with red highlighting
            status_msg = (f"<font color='red'>Scan completed: {files_scanned} files scanned in {scan_time:.2f} seconds, "
                        f"{ioc_file_count} IOC matched files, {yara_match_count} YARA rule matches found</font>")
            
            self.scan_status_label.setText(status_msg)
            self.scan_progress_bar.hide()
            self.stop_scan_button.setEnabled(False)
            
            # Show notification if needed
            if self.notify_scan_checkbox.isChecked():
                if ioc_file_count > 0 or yara_match_count > 0:
                    self.show_notification("Scan Completed", 
                                        f"USB drive {results['drive']} scan completed.\n"
                                        f"{ioc_file_count} IOC matched files\n"
                                        f"{yara_match_count} YARA rule matches found!")
                else:
                    self.show_notification("Scan Completed", 
                                        f"USB drive {results['drive']} scan completed.\n"
                                        f"No suspicious files found.")
            
            # Update suspicious files table
            self.suspicious_files_table.setRowCount(0)
            
            # Add IOC matches first
            for file_info in results.get('suspicious_files', []):
                row_position = self.suspicious_files_table.rowCount()
                self.suspicious_files_table.insertRow(row_position)
                
                self.suspicious_files_table.setItem(row_position, 0, QTableWidgetItem(file_info["path"]))
                self.suspicious_files_table.setItem(row_position, 1, QTableWidgetItem("IOC Hash Match"))
                self.suspicious_files_table.setItem(row_position, 2, QTableWidgetItem(file_info["hash"]))
            
            # Then add YARA matches
            for yara_match in results.get('yara_matches', []):
                row_position = self.suspicious_files_table.rowCount()
                self.suspicious_files_table.insertRow(row_position)
                
                self.suspicious_files_table.setItem(row_position, 0, QTableWidgetItem(yara_match["file_path"]))
                self.suspicious_files_table.setItem(row_position, 1, QTableWidgetItem(f"YARA Rule: {yara_match['rule']}"))
                self.suspicious_files_table.setItem(row_position, 2, QTableWidgetItem(yara_match.get('details', 'No additional details')))
            
            # Log event
            self.log_event("Scan Completed", f"Drive {results['drive']}", 
                        f"{ioc_file_count} IOC files, {yara_match_count} YARA matches found")

        # Handle error or stopped status
        elif results["status"] in ["error", "stopped"]:
            self.scan_status_label.setText(f"Scan {results['status']}: {results.get('error', results.get('message', 'Unknown error'))}")
            self.scan_progress_bar.hide()
            self.stop_scan_button.setEnabled(False)
        
    def clear_scan_results(self):
        """Clear scan results."""
        self.suspicious_files_table.setRowCount(0)
        self.scan_status_label.setText("No scan in progress")

    
    def quarantine_all_files(self):
        """Quarantine all suspicious files in the table."""
        if self.suspicious_files_table.rowCount() == 0:
            QMessageBox.information(self, "No Files", "No suspicious files to quarantine.")
            return
        
        # Create quarantine directory if it doesn't exist
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        
        # Quarantine each file
        quarantined_count = 0
        for row in range(self.suspicious_files_table.rowCount()):
            file_path = self.suspicious_files_table.item(row, 0).text()
            if self.quarantine_file(file_path):
                quarantined_count += 1
        
        QMessageBox.information(self, "Quarantine Complete", f"{quarantined_count} files quarantined successfully.")
    
    def quarantine_file(self, file_path):
        """Quarantine a suspicious file by moving it to the quarantine directory."""
        try:
            # Create quarantine directory if it doesn't exist
            quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)
            
            # Get file name and create quarantine path
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, file_name)
            
            # If file already exists in quarantine, add timestamp to name
            if os.path.exists(quarantine_path):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                name, ext = os.path.splitext(file_name)
                quarantine_path = os.path.join(quarantine_dir, f"{name}_{timestamp}{ext}")
            
            # Move file to quarantine
            os.rename(file_path, quarantine_path)
            
            # Log event
            self.log_event("Quarantined", file_path, "Moved to quarantine")
            
            return True
            
        except Exception as e:
            print(f"Error quarantining file {file_path}: {e}")
            QMessageBox.critical(self, "Quarantine Error", f"Error quarantining file: {e}")
            return False
    
    def delete_file(self, file_path):
        """Delete a suspicious file."""
        try:
            # Confirm deletion
            confirm = QMessageBox.question(self, "Confirm Delete", 
                                          f"Are you sure you want to delete '{file_path}'?", 
                                          QMessageBox.Yes | QMessageBox.No)
            
            if confirm == QMessageBox.No:
                return False
            
            # Delete file
            os.remove(file_path)
            
            # Log event
            self.log_event("Deleted", file_path, "Permanently deleted")
            
            # Remove from table
            for row in range(self.suspicious_files_table.rowCount()):
                if self.suspicious_files_table.item(row, 0).text() == file_path:
                    self.suspicious_files_table.removeRow(row)
                    break
            
            return True
            
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")
            QMessageBox.critical(self, "Delete Error", f"Error deleting file: {e}")
            return False
    
    def open_containing_folder(self, file_path):
        """Open the folder containing a file."""
        try:
            folder_path = os.path.dirname(file_path)
            os.startfile(folder_path)
        except Exception as e:
            print(f"Error opening folder for {file_path}: {e}")
            QMessageBox.critical(self, "Error", f"Error opening folder: {e}")


def main():
    # Create the application
    app = QApplication(sys.argv)
    
    # Set application icon (this affects the window icon)
    app_icon = QIcon('usbshield_icon.ico')
    app.setWindowIcon(app_icon)
    
    # Set the app ID to help Windows properly identify the application in the taskbar
    import ctypes
    myappid = 'USBShield.Application.1.0'  # arbitrary string
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    
    # Create and show the main window
    window = USBShield()
    
    # Exit when the app is closed
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

        