from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                            QTableWidgetItem, QPushButton, QLabel, QHeaderView, 
                            QMessageBox, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QColor

from core.device import USBDevice

class WhitelistTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices = {}  # Dictionary to track devices
        self.init_ui()
        
    def init_ui(self):
        # Main layout
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("USB Device Management")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Description
        description = QLabel("This tab shows all USB devices that have been connected to your computer. "
                           "You can whitelist devices to allow them to be used.")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Table for devices
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(["Device", "Vendor ID", "Product ID", "Serial", "Status", "Actions"])
        self.device_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.device_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.device_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.device_table.verticalHeader().setVisible(False)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.device_table)
        
        # Buttons layout
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh Devices")
        self.refresh_button.clicked.connect(self.refresh_devices)
        button_layout.addWidget(self.refresh_button)
        
        self.whitelist_all_button = QPushButton("Whitelist All")
        self.whitelist_all_button.clicked.connect(self.whitelist_all_devices)
        button_layout.addWidget(self.whitelist_all_button)
        
        self.remove_all_button = QPushButton("Remove All")
        self.remove_all_button.clicked.connect(self.remove_all_devices)
        button_layout.addWidget(self.remove_all_button)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # Auto-approval checkbox
        self.auto_approve = QCheckBox("Automatically approve devices from trusted manufacturers")
        layout.addWidget(self.auto_approve)
        
    def add_device(self, device, allowed=False):
        """Add or update a device in the table."""
        device_id = device.get_identifier()
        
        # Check if device is already in table
        if device_id in self.devices:
            # Update existing entry
            row = self.devices[device_id]['row']
            self.update_device_status(row, allowed)
            return
            
        # Add new entry
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        # Device name/description
        self.device_table.setItem(row, 0, QTableWidgetItem(str(device)))
        
        # Vendor ID
        self.device_table.setItem(row, 1, QTableWidgetItem(device.vendor_id))
        
        # Product ID
        self.device_table.setItem(row, 2, QTableWidgetItem(device.product_id))
        
        # Serial number
        self.device_table.setItem(row, 3, QTableWidgetItem(device.serial or "N/A"))
        
        # Set status
        self.update_device_status(row, allowed)
        
        # Add action buttons
        self.add_action_buttons(row, device_id, allowed)
        
        # Store the device
        self.devices[device_id] = {
            'device': device,
            'row': row,
            'allowed': allowed
        }
        
    def update_device_status(self, row, allowed):
        """Update the status cell for a device."""
        status_item = QTableWidgetItem("Allowed" if allowed else "Blocked")
        status_item.setTextAlignment(Qt.AlignCenter)
        
        if allowed:
            status_item.setBackground(QColor(200, 255, 200))  # Light green
        else:
            status_item.setBackground(QColor(255, 200, 200))  # Light red
            
        self.device_table.setItem(row, 4, status_item)
        
    def add_action_buttons(self, row, device_id, allowed):
        """Add action buttons to the table."""
        # Create a widget to hold the buttons
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(2, 2, 2, 2)
        
        # Toggle button
        toggle_button = QPushButton("Block" if allowed else "Allow")
        toggle_button.clicked.connect(lambda: self.toggle_device(device_id))
        layout.addWidget(toggle_button)
        
        # Remove button
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(lambda: self.remove_device(device_id))
        layout.addWidget(remove_button)
        
        # Add to table
        self.device_table.setCellWidget(row, 5, widget)
        
    def toggle_device(self, device_id):
        """Toggle a device between allowed and blocked."""
        if device_id not in self.devices:
            return
            
        device_info = self.devices[device_id]
        new_status = not device_info['allowed']
        
        # Update the device status
        self.devices[device_id]['allowed'] = new_status
        self.update_device_status(device_info['row'], new_status)
        
        # Update the action buttons
        self.add_action_buttons(device_info['row'], device_id, new_status)
        
        # TODO: Update the whitelist in the backend
        
    def remove_device(self, device_id):
        """Remove a device from the list."""
        if device_id not in self.devices:
            return
            
        # Get the row index
        row = self.devices[device_id]['row']
        
        # Remove from table
        self.device_table.removeRow(row)
        
        # Remove from devices dictionary
        del self.devices[device_id]
        
        # Update row indices for remaining devices
        for device_info in self.devices.values():
            if device_info['row'] > row:
                device_info['row'] -= 1
                
        # TODO: Update the whitelist in the backend
        
    def refresh_devices(self):
        """Refresh the device list."""
        # TODO: Implement a full refresh from the backend
        QMessageBox.information(self, "Refresh Devices", "Device list refreshed.")
        
    def whitelist_all_devices(self):
        """Whitelist all devices."""
        # Ask for confirmation
        reply = QMessageBox.question(
            self, 
            "Whitelist All Devices",
            "Are you sure you want to whitelist all devices?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        # Update all devices
        for device_id, device_info in self.devices.items():
            if not device_info['allowed']:
                self.toggle_device(device_id)
                
    def remove_all_devices(self):
        """Remove all devices."""
        # Ask for confirmation
        reply = QMessageBox.question(
            self, 
            "Remove All Devices",
            "Are you sure you want to remove all devices from the list?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        # Clear the table
        self.device_table.setRowCount(0)
        
        # Clear the devices dictionary
        self.devices = {}
        
        # TODO: Update the whitelist in the backend