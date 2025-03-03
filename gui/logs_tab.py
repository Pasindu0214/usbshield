from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, 
                             QPushButton, QLabel, QComboBox, QFileDialog)
from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtGui import QColor, QTextCursor

class LogsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        # Main layout
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("Event Logs")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(header_label)
        
        # Filter dropdown
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Events", "Connections Only", "Alerts Only"])
        self.filter_combo.currentIndexChanged.connect(self.apply_filter)
        header_layout.addWidget(QLabel("Filter:"))
        header_layout.addWidget(self.filter_combo)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Log view
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QTextEdit.NoWrap)
        layout.addWidget(self.log_view)
        
        # Buttons layout
        button_layout = QHBoxLayout()
        
        self.clear_button = QPushButton("Clear Logs")
        self.clear_button.clicked.connect(self.clear_logs)
        button_layout.addWidget(self.clear_button)
        
        self.save_button = QPushButton("Save Logs")
        self.save_button.clicked.connect(self.save_logs)
        button_layout.addWidget(self.save_button)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
    def add_log_entry(self, message, level="INFO"):
        """Add a log entry to the log view."""
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        
        # Set color based on log level
        color = QColor(0, 0, 0)  # Default black
        if level == "WARNING":
            color = QColor(255, 165, 0)  # Orange
        elif level == "ERROR":
            color = QColor(255, 0, 0)  # Red
        elif level == "SUCCESS":
            color = QColor(0, 128, 0)  # Green
            
        # Format the log entry
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Add to log view with color
        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        format = cursor.charFormat()
        format.setForeground(color)
        cursor.setCharFormat(format)
        
        cursor.insertText(log_entry + "\n")
        
        # Scroll to bottom
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()
        
    def clear_logs(self):
        """Clear all logs."""
        self.log_view.clear()
        
    def save_logs(self):
        """Save logs to a file."""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Logs",
            "logs.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as file:
                    file.write(self.log_view.toPlainText())
                self.add_log_entry(f"Logs saved to {filename}", "SUCCESS")
            except Exception as e:
                self.add_log_entry(f"Error saving logs: {e}", "ERROR")
                
    def apply_filter(self):
        """Apply filter to logs."""
        # TODO: Implement filtering based on self.filter_combo.currentText()
        pass