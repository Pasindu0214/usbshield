# gui/scanner_tab.py
import os
import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                           QTableWidgetItem, QPushButton, QLabel, QHeaderView,
                           QFileDialog, QTabWidget, QTextEdit, QMessageBox,
                           QMenu)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QColor

class ScannerTab(QWidget):
    def __init__(self, config, scanner, quarantine):
        super().__init__()
        self.config = config
        self.scanner = scanner
        self.quarantine = quarantine
        self.setup_ui()
        self.scan_results = {}  # Store scan results by file path

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Create tab widget for scanner sections
        self.scanner_tabs = QTabWidget()
        
        # Scanner tab
        self.file_scanner_tab = QWidget()
        self.setup_file_scanner_tab()
        self.scanner_tabs.addTab(self.file_scanner_tab, "File Scanner")
        
        # Quarantine tab
        self.quarantine_tab = QWidget()
        self.setup_quarantine_tab()
        self.scanner_tabs.addTab(self.quarantine_tab, "Quarantine")
        
        # YARA Rules tab
        self.yara_rules_tab = QWidget()
        self.setup_yara_rules_tab()
        self.scanner_tabs.addTab(self.yara_rules_tab, "YARA Rules")
        
        layout.addWidget(self.scanner_tabs)
        self.setLayout(layout)

    def setup_file_scanner_tab(self):
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("USB File Scanner")
        header_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(header_label)
        
        description_label = QLabel("Scan files for malware using YARA rules. Files copied from USB devices are automatically scanned.")
        layout.addWidget(description_label)
        
        # Scan button layout
        scan_layout = QHBoxLayout()
        
        self.scan_file_button = QPushButton("Scan File")
        self.scan_file_button.clicked.connect(self.scan_file)
        scan_layout.addWidget(self.scan_file_button)
        
        self.scan_folder_button = QPushButton("Scan Folder")
        self.scan_folder_button.clicked.connect(self.scan_folder)
        scan_layout.addWidget(self.scan_folder_button)
        
        scan_layout.addStretch()
        
        layout.addLayout(scan_layout)
        
        # Results table
        self.results_table = QTableWidget(0, 4)
        self.results_table.setHorizontalHeaderLabels(["File Name", "Status", "Size", "Scan Time"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.results_table)
        
        # Status label
        self.status_label = QLabel("Ready to scan files")
        layout.addWidget(self.status_label)
        
        self.file_scanner_tab.setLayout(layout)

    def setup_quarantine_tab(self):
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Quarantined Files")
        header_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(header_label)
        
        description_label = QLabel("Manage files that have been quarantined due to suspected malware content.")
        layout.addWidget(description_label)
        
        # Quarantine table
        self.quarantine_table = QTableWidget(0, 4)
        self.quarantine_table.setHorizontalHeaderLabels(["File Name", "Size", "Quarantine Time", "Actions"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(self.quarantine_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        self.refresh_quarantine_button = QPushButton("Refresh")
        self.refresh_quarantine_button.clicked.connect(self.refresh_quarantine)
        button_layout.addWidget(self.refresh_quarantine_button)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Status label
        self.quarantine_status_label = QLabel("No quarantined files")
        layout.addWidget(self.quarantine_status_label)
        
        self.quarantine_tab.setLayout(layout)
        
        # Populate quarantine table
        self.refresh_quarantine()

    def setup_yara_rules_tab(self):
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("YARA Rules")
        header_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(header_label)
        
        description_label = QLabel("View and manage YARA rules used for malware detection.")
        layout.addWidget(description_label)
        
        # Rules editor
        self.rules_editor = QTextEdit()
        self.rules_editor.setReadOnly(True)  # Read-only for now
        layout.addWidget(self.rules_editor)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        self.load_rule_button = QPushButton("Load Rule File")
        self.load_rule_button.clicked.connect(self.load_rule_file)
        button_layout.addWidget(self.load_rule_button)
        
        self.reload_rules_button = QPushButton("Reload Rules")
        self.reload_rules_button.clicked.connect(self.reload_rules)
        button_layout.addWidget(self.reload_rules_button)
        
        layout.addLayout(button_layout)
        
        self.yara_rules_tab.setLayout(layout)
        
        # Load initial rules
        self.load_default_rule()

    def scan_file(self):
        """Open file dialog and scan selected file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Scan", "", "All Files (*)")
        
        if file_path:
            self.scanner.scan_file(file_path)
            self.status_label.setText(f"Scanning file: {file_path}")

    def scan_folder(self):
        """Open folder dialog and scan all files in selected folder"""
        folder_path = QFileDialog.getExistingDirectory(
            self, "Select Folder to Scan", "")
        
        if folder_path:
            # Count files to scan
            files_to_scan = []
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_scan_file(file_path):
                        files_to_scan.append(file_path)
            
            if files_to_scan:
                self.status_label.setText(f"Scanning {len(files_to_scan)} files in: {folder_path}")
                
                # Start scanning each file
                for file_path in files_to_scan:
                    self.scanner.scan_file(file_path)
            else:
                self.status_label.setText(f"No scannable files found in: {folder_path}")

    def _should_scan_file(self, file_path):
        """Determine if a file should be scanned based on configuration"""
        # If scan_all_files is enabled, scan everything
        if self.config.config.get('scan_all_files', True):
            return True
        
        # Otherwise, check file extension against the list of extensions to scan
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        scan_extensions = self.config.config.get('scan_extensions', [])
        
        return ext in scan_extensions

    def update_scan_status(self, file_path, status):
        """Update the scan status for a file"""
        # Check if file is already in the table
        file_name = os.path.basename(file_path)
        
        for row in range(self.results_table.rowCount()):
            if self.results_table.item(row, 0).data(Qt.UserRole) == file_path:
                # Update status
                status_item = QTableWidgetItem(status)
                self.results_table.setItem(row, 1, status_item)
                return
        
        # Add new row
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # File name column
        name_item = QTableWidgetItem(file_name)
        name_item.setData(Qt.UserRole, file_path)
        self.results_table.setItem(row, 0, name_item)
        
        # Status column
        status_item = QTableWidgetItem(status)
        self.results_table.setItem(row, 1, status_item)
        
        # Size column
        try:
            size = os.path.getsize(file_path)
            size_str = self._format_size(size)
        except:
            size_str = "Unknown"
        
        size_item = QTableWidgetItem(size_str)
        self.results_table.setItem(row, 2, size_item)
        
        # Time column
        time_item = QTableWidgetItem(time.strftime("%H:%M:%S"))
        self.results_table.setItem(row, 3, time_item)

    def update_scan_result(self, file_path, result, scan_info):
        """Update scan result in the table"""
        file_name = os.path.basename(file_path)
        
        # Store scan result
        self.scan_results[file_path] = scan_info
        
        # Find row in table
        for row in range(self.results_table.rowCount()):
            if self.results_table.item(row, 0).data(Qt.UserRole) == file_path:
                # Update status with color
                status_item = QTableWidgetItem(result)
                if result == "Malicious":
                    status_item.setForeground(QColor("red"))
                elif result == "Clean":
                    status_item.setForeground(QColor("green"))
                self.results_table.setItem(row, 1, status_item)
                
                # Update scan time
                time_item = QTableWidgetItem(time.strftime("%H:%M:%S"))
                self.results_table.setItem(row, 3, time_item)
                
                # Update status label
                if result == "Malicious":
                    self.status_label.setText(f"Malware detected in file: {file_name}")
                else:
                    self.status_label.setText(f"Scan completed: {file_name} is clean")
                
                return
        
        # If not found, add a new row (shouldn't happen normally)
        self.update_scan_status(file_path, result)

    def show_context_menu(self, position):
        """Show context menu for scan results"""
        row = self.results_table.rowAt(position.y())
        if row >= 0:
            file_path = self.results_table.item(row, 0).data(Qt.UserRole)
            
            menu = QMenu()
            
            # View details option
            details_action = menu.addAction("View Scan Details")
            details_action.triggered.connect(lambda: self.show_scan_details(file_path))
            
            # Open folder option
            folder_action = menu.addAction("Open Containing Folder")
            folder_action.triggered.connect(lambda: self.open_containing_folder(file_path))
            
            menu.exec_(self.results_table.mapToGlobal(position))

    def show_scan_details(self, file_path):
        """Show detailed scan information"""
        scan_info = self.scan_results.get(file_path)
        if not scan_info:
            QMessageBox.information(self, "Scan Details", "No detailed scan information available.")
            return
        
        # Create details text
        details = f"File: {scan_info.get('file_name', 'Unknown')}\n"
        details += f"Path: {scan_info.get('file_path', 'Unknown')}\n"
        details += f"Size: {self._format_size(scan_info.get('file_size', 0))}\n"
        details += f"Hash: {scan_info.get('file_hash', 'Unknown')}\n"
        details += f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_info.get('timestamp', 0)))}\n\n"
        
        # Add matches if any
        matches = scan_info.get('matches', [])
        if matches:
            details += f"Detected {len(matches)} malicious pattern(s):\n\n"
            for match in matches:
                details += f"Rule: {match.get('rule', 'Unknown')}\n"
                if 'meta' in match and isinstance(match['meta'], dict):
                    for key, value in match['meta'].items():
                        details += f"  {key}: {value}\n"
                details += "\n"
        else:
            if 'error' in scan_info:
                details += f"Error: {scan_info['error']}\n"
            else:
                details += "No malicious patterns detected.\n"
        
        # Show details in message box
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Scan Details")
        msg_box.setText(details)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.setDetailedText(str(scan_info))
        msg_box.exec_()

    def open_containing_folder(self, file_path):
        """Open the folder containing the file"""
        import subprocess
        import os
        import platform
        
        folder_path = os.path.dirname(file_path)
        
        if os.path.exists(folder_path):
            if platform.system() == "Windows":
                os.startfile(folder_path)
            elif platform.system() == "Darwin":  # macOS
                subprocess.call(["open", folder_path])
            else:  # Linux
                subprocess.call(["xdg-open", folder_path])

    def refresh_quarantine(self):
        """Refresh the quarantine table"""
        self.quarantine_table.setRowCount(0)
        
        quarantined_files = self.quarantine.get_quarantined_files()
        
        if not quarantined_files:
            self.quarantine_status_label.setText("No quarantined files")
            return
        
        # Add files to table
        for file_info in quarantined_files:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            
            # File name column
            name_item = QTableWidgetItem(file_info['name'])
            name_item.setData(Qt.UserRole, file_info['path'])
            self.quarantine_table.setItem(row, 0, name_item)
            
            # Size column
            size_item = QTableWidgetItem(self._format_size(file_info['size']))
            self.quarantine_table.setItem(row, 1, size_item)
            
            # Time column
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file_info['quarantine_time']))
            time_item = QTableWidgetItem(time_str)
            self.quarantine_table.setItem(row, 2, time_item)
            
            # Actions column - add buttons to restore or delete
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(5, 2, 5, 2)
            
            restore_button = QPushButton("Restore")
            restore_button.clicked.connect(lambda checked, path=file_info['path']: self.restore_file(path))
            action_layout.addWidget(restore_button)
            
            delete_button = QPushButton("Delete")
            delete_button.clicked.connect(lambda checked, path=file_info['path']: self.delete_file(path))
            action_layout.addWidget(delete_button)
            
            self.quarantine_table.setCellWidget(row, 3, action_widget)
        
        self.quarantine_status_label.setText(f"{len(quarantined_files)} quarantined file(s)")

    def restore_file(self, quarantine_path):
        """Restore a file from quarantine"""
        # Ask where to restore the file
        file_name = os.path.basename(quarantine_path).split('_')[0]  # Remove timestamp
        restore_path, _ = QFileDialog.getSaveFileName(
            self, "Restore File", file_name, "All Files (*)")
        
        if restore_path:
            # Show warning before restoring
            reply = QMessageBox.warning(
                self, "Restore Malicious File", 
                "This file was quarantined because it may contain malware. Are you sure you want to restore it?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                if self.quarantine.restore_file(quarantine_path, restore_path):
                    QMessageBox.information(self, "File Restored", 
                                          f"The file has been restored to:\n{restore_path}")
                    self.refresh_quarantine()
                else:
                    QMessageBox.warning(self, "Restore Failed", 
                                       "Failed to restore the file. Please check permissions and try again.")

    def delete_file(self, quarantine_path):
        """Delete a file from quarantine"""
        # Ask for confirmation
        reply = QMessageBox.question(
            self, "Delete Quarantined File", 
            "Are you sure you want to permanently delete this file?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            if self.quarantine.delete_file(quarantine_path):
                self.refresh_quarantine()
            else:
                QMessageBox.warning(self, "Delete Failed", 
                                   "Failed to delete the file. Please check permissions and try again.")

    def load_rule_file(self):
        """Load and display a YARA rule file"""
        rule_path, _ = QFileDialog.getOpenFileName(
            self, "Select YARA Rule File", self.scanner.rules_path, "YARA Rules (*.yar *.yara)")
        
        if rule_path and os.path.exists(rule_path):
            try:
                with open(rule_path, 'r') as f:
                    self.rules_editor.setText(f.read())
            except Exception as e:
                QMessageBox.warning(self, "Error Loading Rule", 
                                   f"Failed to load YARA rule file: {str(e)}")

    def load_default_rule(self):
        """Load and display the first available YARA rule file"""
        try:
            # Find the first .yar file in the rules directory
            if os.path.exists(self.scanner.rules_path):
                for filename in os.listdir(self.scanner.rules_path):
                    if filename.endswith('.yar') or filename.endswith('.yara'):
                        rule_path = os.path.join(self.scanner.rules_path, filename)
                        with open(rule_path, 'r') as f:
                            self.rules_editor.setText(f.read())
                        return
            
            # If no rule file found, show a message
            self.rules_editor.setText("No YARA rule files found in the rules directory.")
        except Exception as e:
            self.rules_editor.setText(f"Error loading YARA rules: {str(e)}")

    def reload_rules(self):
        """Reload all YARA rules"""
        self.scanner.load_yara_rules()
        QMessageBox.information(self, "Rules Reloaded", "YARA rules have been reloaded successfully.")
        self.load_default_rule()

    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"