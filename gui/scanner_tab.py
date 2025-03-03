from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox, QComboBox, QSpinBox

class SettingsTab(QWidget):
    def __init__(self, config, parent=None):
        super().__init__(parent)  # Pass only parent to QWidget
        self.config = config  # Store config as a separate attribute
        self.init_ui()
        
    def init_ui(self):
        # Main layout
        layout = QVBoxLayout(self)
        
        # USB Protection Settings
        protection_group = QtWidgets.QGroupBox("USB Protection Settings")
        protection_layout = QVBoxLayout()
        
        # Enable USB Protection
        self.enable_protection = QCheckBox("Enable USB Protection")
        self.enable_protection.setChecked(True)
        protection_layout.addWidget(self.enable_protection)
        
        # Block unauthorized devices
        self.block_unauthorized = QCheckBox("Block Unauthorized Devices")
        self.block_unauthorized.setChecked(True)
        protection_layout.addWidget(self.block_unauthorized)
        
        # Notification settings
        notification_layout = QHBoxLayout()
        notification_layout.addWidget(QLabel("Notification Type:"))
        self.notification_type = QComboBox()
        self.notification_type.addItems(["Silent", "Toast", "Dialog"])
        notification_layout.addWidget(self.notification_type)
        protection_layout.addLayout(notification_layout)
        
        protection_group.setLayout(protection_layout)
        layout.addWidget(protection_group)
        
        # Whitelist Settings
        whitelist_group = QtWidgets.QGroupBox("Whitelist Settings")
        whitelist_layout = QVBoxLayout()
        
        # Auto-approve settings
        self.auto_approve = QCheckBox("Auto-approve devices from same manufacturer")
        whitelist_layout.addWidget(self.auto_approve)
        
        # History settings
        history_layout = QHBoxLayout()
        history_layout.addWidget(QLabel("Keep device history (days):"))
        self.history_days = QSpinBox()
        self.history_days.setRange(1, 365)
        self.history_days.setValue(30)
        history_layout.addWidget(self.history_days)
        whitelist_layout.addLayout(history_layout)
        
        whitelist_group.setLayout(whitelist_layout)
        layout.addWidget(whitelist_group)
        
        # Advanced settings
        advanced_group = QtWidgets.QGroupBox("Advanced Settings")
        advanced_layout = QVBoxLayout()
        
        # Logging settings
        self.enable_logging = QCheckBox("Enable detailed logging")
        self.enable_logging.setChecked(True)
        advanced_layout.addWidget(self.enable_logging)
        
        # Startup settings
        self.start_with_windows = QCheckBox("Start with Windows")
        self.start_with_windows.setChecked(True)
        advanced_layout.addWidget(self.start_with_windows)
        
        # Silent mode
        self.silent_mode = QCheckBox("Silent Mode (no notifications)")
        advanced_layout.addWidget(self.silent_mode)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Add spacer
        layout.addStretch()
        
        # Save/Cancel buttons
        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save Settings")
        self.cancel_button = QPushButton("Cancel")
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        # Connect signals
        self.save_button.clicked.connect(self.save_settings)
        self.cancel_button.clicked.connect(self.cancel_changes)
        
        # Load settings from config
        self.load_settings()
        
    def load_settings(self):
        """Load settings from config"""
        try:
            # Here you would load settings from self.config
            # For example:
            # self.enable_protection.setChecked(self.config.get('enable_protection', True))
            pass
        except Exception as e:
            print(f"Error loading settings: {e}")
        
    def save_settings(self):
        """Save settings to config"""
        try:
            # Here you would save settings to self.config
            # For example:
            # self.config.set('enable_protection', self.enable_protection.isChecked())
            # self.config.save()
            print("Settings saved")
        except Exception as e:
            print(f"Error saving settings: {e}")
        
    def cancel_changes(self):
        # Here you would revert any changes
        self.load_settings()
        print("Changes canceled")