# gui/main_window.py
import os
import sys
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QSystemTrayIcon, 
                           QMenu, QAction, QMessageBox, QStyle)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon

from gui.device_tab import DeviceTab
from gui.logs_tab import LogsTab
from gui.scanner_tab import ScannerTab
from gui.settings_tab import SettingsTab

from core.usb_monitor import USBMonitor
from core.device_controller import DeviceController
from core.file_monitor import FileMonitor
from core.scanner import Scanner
from core.quarantine import Quarantine

class MainWindow(QMainWindow):
    def __init__(self, config, logger):
        super().__init__()
        self.config = config
        self.logger = logger
        
        # Initialize core components
        self.usb_monitor = USBMonitor(config)
        self.device_controller = DeviceController(config)
        self.file_monitor = FileMonitor(config)
        self.scanner = Scanner(config)
        self.quarantine = Quarantine(config)
        
        # Set up the UI
        self.setup_ui()
        
        # Connect signals
        self.connect_signals()
        
        # Start monitoring
        self.start_monitors()

    def setup_ui(self):
        self.setWindowTitle("USBShield - USB Security System")
        self.setMinimumSize(800, 600)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        
        # Create tabs
        self.device_tab = DeviceTab(self.config, self.device_controller)
        self.logs_tab = LogsTab()
        self.scanner_tab = ScannerTab(self.config, self.scanner, self.quarantine)
        self.settings_tab = SettingsTab(self.config)
        
        # Add tabs to widget
        self.tab_widget.addTab(self.device_tab, "USB Devices")
        self.tab_widget.addTab(self.scanner_tab, "Malware Scanner")
        self.tab_widget.addTab(self.logs_tab, "Security Logs")
        self.tab_widget.addTab(self.settings_tab, "Settings")
        
        # Set up system tray icon
        self.setup_tray_icon()

    def setup_tray_icon(self):
        # Create system tray icon
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_DriveHDIcon))
        
        # Create tray menu
        tray_menu = QMenu()
        
        # Add actions to the tray menu
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        tray_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close_application)
        tray_menu.addAction(exit_action)
        
        # Set the tray menu
        self.tray_icon.setContextMenu(tray_menu)
        
        # Show the tray icon
        self.tray_icon.show()
        
        # Connect tray icon signals
        self.tray_icon.activated.connect(self.tray_icon_activated)

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isVisible():
                self.hide()
            else:
                self.show()
                self.activateWindow()

    def connect_signals(self):
        # Connect USB monitor signals
        self.usb_monitor.device_connected.connect(self.on_device_connected)
        self.usb_monitor.device_disconnected.connect(self.on_device_disconnected)
        
        # Connect device controller signals
        self.device_controller.device_blocked.connect(self.on_device_blocked)
        self.device_controller.device_allowed.connect(self.on_device_allowed)
        
        # Connect file monitor signals
        self.file_monitor.new_file_detected.connect(self.on_new_file_detected)
        
        # Connect scanner signals
        self.scanner.scan_started.connect(self.on_scan_started)
        self.scanner.scan_completed.connect(self.on_scan_completed)
        
        # Connect quarantine signals
        self.quarantine.file_restored.connect(self.on_file_restored)
        self.quarantine.file_deleted.connect(self.on_file_deleted)

    def start_monitors(self):
        self.usb_monitor.start_monitoring()
        self.file_monitor.start_monitoring()

    def stop_monitors(self):
        self.usb_monitor.stop_monitoring()
        self.file_monitor.stop_monitoring()

    def on_device_connected(self, device_info):
        self.logger.info(f"Device connected: {device_info['description']}")
        self.device_tab.add_device(device_info)
        self.logs_tab.add_log_entry(f"USB device connected: {device_info['description']}", "info")
        
        # Check if the device is allowed
        is_allowed = self.device_controller.handle_device_connection(device_info)
        
        # Show notification for device connection
        if is_allowed:
            self.show_notification("USB Device Connected", 
                                  f"Allowed device: {device_info['description']}")
        else:
            self.show_notification("USB Device Blocked", 
                                  f"Unauthorized device: {device_info['description']}")

    def on_device_disconnected(self, device_info):
        self.logger.info(f"Device disconnected: {device_info['description']}")
        self.device_tab.remove_device(device_info)
        self.logs_tab.add_log_entry(f"USB device disconnected: {device_info['description']}", "info")

    def on_device_blocked(self, device_info):
        self.logger.warning(f"Device blocked: {device_info['description']}")
        self.logs_tab.add_log_entry(f"Blocked unauthorized USB device: {device_info['description']}", "warning")

    def on_device_allowed(self, device_info):
        self.logger.info(f"Device allowed: {device_info['description']}")
        self.logs_tab.add_log_entry(f"Allowed USB device: {device_info['description']}", "info")

    def on_new_file_detected(self, file_path):
        self.logger.info(f"New file detected: {file_path}")
        self.logs_tab.add_log_entry(f"Detected new file: {file_path}", "info")
        
        # If auto-scan is enabled, scan the file
        if self.config.config.get('auto_scan', True):
            self.scanner.scan_file(file_path)

    def on_scan_started(self, file_path):
        self.logger.info(f"Scan started: {file_path}")
        self.logs_tab.add_log_entry(f"Started scanning file: {file_path}", "info")
        self.scanner_tab.update_scan_status(file_path, "Scanning...")

    def on_scan_completed(self, file_path, is_malicious, scan_info):
        if is_malicious:
            self.logger.warning(f"Malware detected: {file_path}")
            self.logs_tab.add_log_entry(f"MALWARE DETECTED: {file_path}", "critical")
            self.scanner_tab.update_scan_result(file_path, "Malicious", scan_info)
            
            # Show notification for malware detection
            self.show_notification("Malware Detected!", 
                                 f"Malicious file detected and quarantined: {os.path.basename(file_path)}")
        else:
            self.logger.info(f"File scan completed (clean): {file_path}")
            self.logs_tab.add_log_entry(f"File scan completed (clean): {file_path}", "info")
            self.scanner_tab.update_scan_result(file_path, "Clean", scan_info)

    def on_file_restored(self, restore_path, quarantine_path):
        self.logger.info(f"File restored: {quarantine_path} -> {restore_path}")
        self.logs_tab.add_log_entry(f"Restored file from quarantine: {os.path.basename(quarantine_path)}", "info")

    def on_file_deleted(self, quarantine_path):
        self.logger.info(f"File deleted from quarantine: {quarantine_path}")
        self.logs_tab.add_log_entry(f"Deleted file from quarantine: {os.path.basename(quarantine_path)}", "info")

    def show_notification(self, title, message):
        if QSystemTrayIcon.supportsMessages():
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 5000)

    def closeEvent(self, event):
        # Ask if the user really wants to exit
        reply = QMessageBox.question(self, 'Exit Confirmation',
                                    'Are you sure you want to exit USBShield? The application will continue to run in the system tray.',
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Check if we want to really exit or just hide
            if event.spontaneous():
                # If closed from window controls, just hide
                event.ignore()
                self.hide()
                self.show_notification("USBShield", "Application minimized to system tray")
            else:
                # If closed programmatically, really exit
                self.close_application()
        else:
            event.ignore()

    def close_application(self):
        # Stop monitoring before exit
        self.stop_monitors()
        
        # Save configuration
        self.config.save_config()
        self.config.save_whitelist()
        
        # Hide tray icon
        self.tray_icon.hide()
        
        # Exit application
        QTimer.singleShot(0, lambda: sys.exit(0))