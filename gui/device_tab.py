# gui/device_tab.py
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                           QTableWidgetItem, QPushButton, QLabel, QHeaderView,
                           QMessageBox, QMenu)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QIcon, QColor

class DeviceTab(QWidget):
    def __init__(self, config, device_controller):
        super().__init__()
        self.config = config
        self.device_controller = device_controller
        self.setup_ui()
        self.devices = {}  # Store device info by ID

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("USB Device Manager")
        header_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(header_label)
        
        description_label = QLabel("Monitor and control USB devices connected to your system.")
        layout.addWidget(description_label)
        
        # Device table
        self.device_table = QTableWidget(0, 5)
        self.device_table.setHorizontalHeaderLabels(["Status", "Description", "Vendor ID", "Product ID", "Actions"])
        self.device_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.device_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.device_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.device_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh Devices")
        self.refresh_button.clicked.connect(self.refresh_devices)
        button_layout.addWidget(self.refresh_button)
        
        button_layout.addStretch()
        
        self.whitelist_all_button = QPushButton("Whitelist All Devices")
        self.whitelist_all_button.clicked.connect(self.whitelist_all_devices)
        button_layout.addWidget(self.whitelist_all_button)
        
        layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("No USB devices detected")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)

    def add_device(self, device_info):
        device_id = device_info['id']
        
        # Store the device info
        self.devices[device_id] = device_info
        
        # Check if the device is already in the table
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 0).data(Qt.UserRole) == device_id:
                self.update_device_row(row, device_info)
                return
        
        # Add a new row for the device
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        self.update_device_row(row, device_info)
        
        # Update status label
        self.status_label.setText(f"{len(self.devices)} USB device(s) connected")

    def update_device_row(self, row, device_info):
        device_id = device_info['id']
        
        # Determine the status
        is_whitelisted = self.config.is_device_whitelisted(device_info)
        if is_whitelisted:
            status_text = "Allowed"
            status_color = QColor("green")
        else:
            if self.config.config.get('block_unknown_devices', True):
                status_text = "Blocked"
                status_color = QColor("red")
            else:
                status_text = "Unknown"
                status_color = QColor("orange")
        
        # Status column
        status_item = QTableWidgetItem(status_text)
        status_item.setForeground(status_color)
        status_item.setData(Qt.UserRole, device_id)
        self.device_table.setItem(row, 0, status_item)
        
        # Description column
        desc_item = QTableWidgetItem(device_info.get('description', 'Unknown Device'))
        self.device_table.setItem(row, 1, desc_item)
        
        # Vendor ID column
        vendor_item = QTableWidgetItem(device_info.get('vendor_id', 'Unknown'))
        self.device_table.setItem(row, 2, vendor_item)
        
        # Product ID column
        product_item = QTableWidgetItem(device_info.get('product_id', 'Unknown'))
        self.device_table.setItem(row, 3, product_item)
        
        # Actions column - add a button to whitelist/remove from whitelist
        action_widget = QWidget()
        action_layout = QHBoxLayout(action_widget)
        action_layout.setContentsMargins(5, 2, 5, 2)
        
        if is_whitelisted:
            action_button = QPushButton("Remove from Whitelist")
            action_button.clicked.connect(lambda: self.remove_from_whitelist(device_id))
        else:
            action_button = QPushButton("Add to Whitelist")
            action_button.clicked.connect(lambda: self.add_to_whitelist(device_id))
        
        action_layout.addWidget(action_button)
        self.device_table.setCellWidget(row, 4, action_widget)

    def remove_device(self, device_info):
        device_id = device_info['id']
        
        # Remove the device from our dictionary
        if device_id in self.devices:
            del self.devices[device_id]
        
        # Find and remove the device from the table
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 0).data(Qt.UserRole) == device_id:
                self.device_table.removeRow(row)
                break
        
        # Update status label
        if len(self.devices) == 0:
            self.status_label.setText("No USB devices detected")
        else:
            self.status_label.setText(f"{len(self.devices)} USB device(s) connected")

    @pyqtSlot()
    def refresh_devices(self):
        # Clear the table
        self.device_table.setRowCount(0)
        
        # Re-add all known devices
        for device_id, device_info in self.devices.items():
            self.add_device(device_info)

    @pyqtSlot()
    def whitelist_all_devices(self):
        # Ask for confirmation
        reply = QMessageBox.question(self, 'Whitelist All Devices',
                                    'Are you sure you want to whitelist all currently connected USB devices?',
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Add all devices to whitelist
            for device_id, device_info in self.devices.items():
                self.add_to_whitelist(device_id)

    def add_to_whitelist(self, device_id):
        # Get the device info
        device_info = self.devices.get(device_id)
        if not device_info:
            return
        
        # Add to whitelist and allow the device
        if self.config.add_to_whitelist(device_info):
            self.device_controller.allow_device(device_info)
            
            # Refresh the table to update the status
            self.refresh_devices()
            
            # Show success message
            QMessageBox.information(self, "Device Whitelisted", 
                                  f"Device '{device_info['description']}' has been added to the whitelist.")

    def remove_from_whitelist(self, device_id):
        # Get the device info
        device_info = self.devices.get(device_id)
        if not device_info:
            return
        
        # Ask for confirmation
        reply = QMessageBox.question(self, 'Remove from Whitelist',
                                    f"Are you sure you want to remove '{device_info['description']}' from the whitelist?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Remove from whitelist
            if self.config.remove_from_whitelist(device_info):
                # Refresh the table to update the status
                self.refresh_devices()
                
                # Show success message
                QMessageBox.information(self, "Device Removed", 
                                      f"Device '{device_info['description']}' has been removed from the whitelist.")

    def show_context_menu(self, position):
        """Show context menu for right-clicked device"""
        row = self.device_table.rowAt(position.y())
        if row >= 0:
            device_id = self.device_table.item(row, 0).data(Qt.UserRole)
            device_info = self.devices.get(device_id)
            
            if device_info:
                menu = QMenu()
                
                # Add whitelist/remove option
                is_whitelisted = self.config.is_device_whitelisted(device_info)
                if is_whitelisted:
                    remove_action = menu.addAction("Remove from Whitelist")
                    remove_action.triggered.connect(lambda: self.remove_from_whitelist(device_id))
                else:
                    add_action = menu.addAction("Add to Whitelist")
                    add_action.triggered.connect(lambda: self.add_to_whitelist(device_id))
                
                # Add device details option
                details_action = menu.addAction("View Device Details")
                details_action.triggered.connect(lambda: self.show_device_details(device_info))
                
                menu.exec_(self.device_table.mapToGlobal(position))

    def show_device_details(self, device_info):
        """Show detailed information about a device"""
        details = f"Device: {device_info.get('description', 'Unknown')}\n\n"
        details += f"Vendor ID: {device_info.get('vendor_id', 'Unknown')}\n"
        details += f"Product ID: {device_info.get('product_id', 'Unknown')}\n"
        details += f"Status: {device_info.get('status', 'Unknown')}\n"
        details += f"Class: {device_info.get('class', 'Unknown')}\n"
        details += f"ID: {device_info.get('id', 'Unknown')}\n"
        
        QMessageBox.information(self, "Device Details", details)