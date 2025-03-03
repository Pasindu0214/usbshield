# gui/logs_tab.py
import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                           QTableWidgetItem, QPushButton, QLabel, QHeaderView,
                           QFileDialog)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

class LogsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.logs = []  # Store log entries

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Security Logs")
        header_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(header_label)
        
        description_label = QLabel("View security events and alerts related to USB devices and malware detection.")
        layout.addWidget(description_label)
        
        # Log table
        self.log_table = QTableWidget(0, 3)
        self.log_table.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(self.log_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        self.clear_button = QPushButton("Clear Logs")
        self.clear_button.clicked.connect(self.clear_logs)
        button_layout.addWidget(self.clear_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("Export Logs")
        self.export_button.clicked.connect(self.export_logs)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("No log entries")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)

    def add_log_entry(self, message, severity="info"):
        """Add a new log entry to the table"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Create a log entry
        log_entry = {
            "timestamp": timestamp,
            "severity": severity,
            "message": message
        }
        
        # Add to the log list
        self.logs.insert(0, log_entry)  # Add to the beginning to show newest first
        
        # Add a new row to the table
        row = 0
        self.log_table.insertRow(row)
        
        # Time column
        time_item = QTableWidgetItem(timestamp)
        self.log_table.setItem(row, 0, time_item)
        
        # Severity column with appropriate color
        severity_item = QTableWidgetItem(severity.upper())
        if severity == "critical":
            severity_item.setForeground(QColor("red"))
        elif severity == "warning":
            severity_item.setForeground(QColor("orange"))
        elif severity == "info":
            severity_item.setForeground(QColor("blue"))
        self.log_table.setItem(row, 1, severity_item)
        
        # Message column
        message_item = QTableWidgetItem(message)
        self.log_table.setItem(row, 2, message_item)
        
        # Limit to the latest 1000 entries to prevent memory issues
        if self.log_table.rowCount() > 1000:
            self.log_table.removeRow(1000)
            if len(self.logs) > 1000:
                self.logs = self.logs[:1000]
        
        # Update status label
        self.status_label.setText(f"{self.log_table.rowCount()} log entries")

    def clear_logs(self):
        """Clear all log entries"""
        self.log_table.setRowCount(0)
        self.logs = []
        self.status_label.setText("No log entries")

    def export_logs(self):
        """Export logs to a CSV file"""
        if not self.logs:
            return
        
        # Open file dialog to get save location
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "usbshield_logs.csv", "CSV Files (*.csv)")
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    # Write header
                    f.write("Timestamp,Severity,Message\n")
                    
                    # Write log entries
                    for log in self.logs:
                        # Escape quotes in message
                        message = log["message"].replace('"', '""')
                        f.write(f'{log["timestamp"]},{log["severity"]},"{message}"\n')
                
                self.status_label.setText(f"Logs exported to {file_path}")
            except Exception as e:
                self.status_label.setText(f"Error exporting logs: {str(e)}")