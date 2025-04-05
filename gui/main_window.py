from PyQt5.QtWidgets import QMainWindow, QTabWidget, QAction, QMessageBox, QSystemTrayIcon, QMenu
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon, QPixmap
import os

from core.usb_monitor import USBMonitor
from gui.settings_tab import SettingsTab
from gui.whitelist_tab import WhitelistTab
from gui.logs_tab import LogsTab

class MainWindow(QMainWindow):
    def __init__(self, config, logger):
        super().__init__()
        self.config = config
        self.logger = logger
        self.usb_monitor = USBMonitor()
        
        # Set up UI
        self.setup_ui()
        
        # Set up system tray icon
        self.setup_tray_icon()
        
        # Connect signals
        self.connect_signals()
        
        # Start USB monitoring
        self.usb_monitor.start()
        
    def setup_ui(self):
        # Set window properties
        self.setWindowTitle("USBShield - USB Security")
        self.setGeometry(100, 100, 800, 600)
        
        # Set the icon
        self.set_icon()
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.settings_tab = SettingsTab(self.config)
        self.whitelist_tab = WhitelistTab()
        self.logs_tab = LogsTab()
        
        # Add tabs to widget
        self.tabs.addTab(self.whitelist_tab, "Device Management")
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.logs_tab, "Logs")
        
        # Create menu bar
        self.setup_menu()
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
    
    def set_icon(self):
        """Set window icon from file"""
        try:
            # Try multiple possible paths for the icon file
            icon_paths = [
                "usbshield_icon.ico",  # Try ICO first in current directory
                "usbshield_icon.png",  # Try PNG in current directory
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "usbshield_icon.ico"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "usbshield_icon.png"),
                os.path.join("gui", "usbshield_icon.ico"),
                os.path.join("gui", "usbshield_icon.png"),
                os.path.join("resources", "icons", "usbshield_icon.ico"),
                os.path.join("resources", "icons", "usbshield_icon.png")
            ]
            
            # Try each path until we find one that exists
            icon_path = None
            for path in icon_paths:
                if os.path.exists(path):
                    icon_path = path
                    print(f"Found icon at: {path}")
                    break
            
            if icon_path:
                icon = QIcon(icon_path)
                if not icon.isNull():
                    self.setWindowIcon(icon)
                    print(f"Successfully set window icon from: {icon_path}")
                else:
                    print(f"Icon loaded but is null: {icon_path}")
            else:
                print("Could not find icon file in any of the expected locations")
                
        except Exception as e:
            print(f"Error setting icon: {str(e)}")
        
    def setup_menu(self):
        # File menu
        file_menu = self.menuBar().addMenu("&File")
        
        # Exit action
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setStatusTip("Exit application")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = self.menuBar().addMenu("&Help")
        
        # About action
        about_action = QAction("&About", self)
        about_action.setStatusTip("About USBShield")
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_tray_icon(self):
        # Try multiple possible paths for the icon file
        icon_paths = [
            "usbshield_icon.ico",  # Try ICO first in current directory
            "usbshield_icon.png",  # Try PNG in current directory
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "usbshield_icon.ico"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "usbshield_icon.png"),
            os.path.join("gui", "usbshield_icon.ico"),
            os.path.join("gui", "usbshield_icon.png"),
            os.path.join("resources", "icons", "usbshield_icon.ico"),
            os.path.join("resources", "icons", "usbshield_icon.png")
        ]
        
        # Try each path until we find one that exists
        icon_path = None
        for path in icon_paths:
            if os.path.exists(path):
                icon_path = path
                print(f"Found tray icon at: {path}")
                break
        
        # Create tray icon
        if icon_path:
            icon = QIcon(icon_path)
            if not icon.isNull():
                self.tray_icon = QSystemTrayIcon(icon, self)
                print(f"Successfully set tray icon from: {icon_path}")
            else:
                print(f"Tray icon loaded but is null: {icon_path}")
                self.tray_icon = QSystemTrayIcon(self)
        else:
            print("Could not find icon file for tray icon")
            self.tray_icon = QSystemTrayIcon(self)
        
        # Create tray menu
        tray_menu = QMenu()
        
        # Show/hide action
        show_action = QAction("Show USBShield", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        # Exit action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)
        
        # Set tray menu
        self.tray_icon.setContextMenu(tray_menu)
        
        # Show tray icon
        self.tray_icon.show()
        
        # Connect signals
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
    def connect_signals(self):
        # Connect USB monitor signals
        self.usb_monitor.device_connected.connect(self.on_device_connected)
        self.usb_monitor.device_disconnected.connect(self.on_device_disconnected)
        
    def on_device_connected(self, event):
        device = event.get('device')
        allowed = event.get('allowed', False)
        
        # Update device list
        self.whitelist_tab.add_device(device, allowed)
        
        # Log the event
        self.logs_tab.add_log_entry(f"Device connected: {device} (Allowed: {allowed})")
        
        # Update status bar
        self.status_bar.showMessage(f"Device connected: {device}")
        
        # Show notification if not allowed
        if not allowed:
            self.tray_icon.showMessage(
                "USBShield Alert",
                f"Unauthorized USB device connected: {device}",
                QSystemTrayIcon.Warning,
                5000
            )
            
    def on_device_disconnected(self, event):
        # Update status bar
        self.status_bar.showMessage("USB device disconnected")
        
        # Log the event
        self.logs_tab.add_log_entry("USB device disconnected")
        
    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isVisible():
                self.hide()
            else:
                self.show()
                self.activateWindow()
                
    def closeEvent(self, event):
        # Ask for confirmation
        reply = QMessageBox.question(
            self, 
            "Exit USBShield",
            "Are you sure you want to exit USBShield? USB protection will be disabled.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Stop USB monitoring
            self.usb_monitor.stop()
            
            # Close the application
            event.accept()
        else:
            event.ignore()
            
    def show_about(self):
        QMessageBox.about(
            self,
            "About USBShield",
            "USBShield - USB Security\n\n"
            "Version 1.0\n\n"
            "A tool to protect your computer from unauthorized USB devices."
        )