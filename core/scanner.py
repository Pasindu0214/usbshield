# core/scanner.py
import os
import logging
import threading
import time
import yara
import hashlib
import shutil
from PyQt5.QtCore import QObject, pyqtSignal

class Scanner(QObject):
    scan_started = pyqtSignal(str)
    scan_completed = pyqtSignal(str, bool, dict)  # file_path, is_malicious, scan_info
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.logger = logging.getLogger('usbshield')
        self.rules = None
        self.rules_path = os.path.join('yara_rules')
        self.quarantine_dir = os.path.join('data', 'quarantine')
        self.load_yara_rules()

    def load_yara_rules(self):
        """Load YARA rules from the rules directory"""
        try:
            # Check if rules directory exists
            if not os.path.exists(self.rules_path):
                os.makedirs(self.rules_path)
                self._create_default_rules()
            
            # Compile all .yar files in the rules directory
            filepaths = {}
            for filename in os.listdir(self.rules_path):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    filepath = os.path.join(self.rules_path, filename)
                    filepaths[os.path.splitext(filename)[0]] = filepath
            
            if filepaths:
                self.rules = yara.compile(filepaths=filepaths)
                self.logger.info(f"Loaded {len(filepaths)} YARA rule files")
            else:
                self.logger.warning("No YARA rules found, creating default rules")
                self._create_default_rules()
                self.load_yara_rules()  # Try loading again
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {e}")
            self.rules = None

    def _create_default_rules(self):
        """Create some default YARA rules if none exist"""
        try:
            # Create the rules directory if it doesn't exist
            if not os.path.exists(self.rules_path):
                os.makedirs(self.rules_path)
            
            # Sample rule for USB malware
            usb_malware_rule = """
rule USB_Malware {
    meta:
        description = "Detects common USB malware patterns"
        severity = "high"
    strings:
        $autorun = "autorun.inf" nocase
        $usb_spread1 = "\\autorun.inf" nocase
        $usb_spread2 = "copy /y \"%s\" + \"%s\"" nocase
        $usb_spread3 = "copy /b /y \"%s\" + \"%s\"" nocase
        $executable_ext = ".exe" nocase
    condition:
        $autorun or any of ($usb_spread*) or $executable_ext
}
"""
            # Sample rule for trojans
            trojan_rule = """
rule Generic_Trojan {
    meta:
        description = "Detects generic trojan patterns"
        severity = "high"
    strings:
        $str1 = "GetWindowsDirectory" ascii
        $str2 = "GetSystemDirectory" ascii
        $str3 = "CreateRemoteThread" ascii
        $str4 = "WriteProcessMemory" ascii
        $str5 = "CreateProcess" ascii
        $str6 = "TEMPORARY DIRECTORY" nocase
        $str7 = "RECYCLER" nocase
        $str8 = "cmd.exe /c" nocase
    condition:
        3 of them
}
"""
            # Sample rule for ransomware
            ransomware_rule = """
rule Generic_Ransomware {
    meta:
        description = "Detects generic ransomware patterns"
        severity = "critical"
    strings:
        $str1 = "Your files have been encrypted" nocase
        $str2 = "bitcoin" nocase
        $str3 = "decrypt" nocase
        $str4 = "ransom" nocase
        $str5 = "encrypted files" nocase
        $str6 = ".crypted" nocase
        $str7 = ".locked" nocase
        $str8 = ".crypt" nocase
    condition:
        2 of them
}
"""
            # Write the rules to files
            with open(os.path.join(self.rules_path, 'usb_malware.yar'), 'w') as f:
                f.write(usb_malware_rule)
            
            with open(os.path.join(self.rules_path, 'trojans.yar'), 'w') as f:
                f.write(trojan_rule)
            
            with open(os.path.join(self.rules_path, 'ransomware.yar'), 'w') as f:
                f.write(ransomware_rule)
            
            self.logger.info("Created default YARA rules")
        except Exception as e:
            self.logger.error(f"Error creating default YARA rules: {e}")

    def scan_file(self, file_path):
        """Scan a file for malware using YARA rules"""
        self.scan_started.emit(file_path)
        
        # Start a new thread for scanning to avoid blocking the UI
        scan_thread = threading.Thread(target=self._scan_file_thread, args=(file_path,), daemon=True)
        scan_thread.start()

    def _scan_file_thread(self, file_path):
        """Thread function to scan a file and emit results"""
        try:
            is_malicious, scan_info = self._perform_scan(file_path)
            
            # Handle malicious files according to configuration
            if is_malicious and self.config.config.get('quarantine_malicious_files', True):
                self.quarantine_file(file_path)
            
            self.scan_completed.emit(file_path, is_malicious, scan_info)
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            scan_info = {
                'error': str(e),
                'timestamp': time.time(),
                'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
            }
            self.scan_completed.emit(file_path, False, scan_info)

    def _perform_scan(self, file_path):
        """Perform the actual file scan"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not self.rules:
            self.load_yara_rules()
            if not self.rules:
                raise Exception("No YARA rules available")
        
        file_size = os.path.getsize(file_path)
        file_hash = self._compute_file_hash(file_path)
        timestamp = time.time()
        
        scan_info = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': file_size,
            'file_hash': file_hash,
            'timestamp': timestamp,
            'matches': []
        }
        
        # Skip files that are too large
        max_size = 100 * 1024 * 1024  # 100 MB
        if file_size > max_size:
            scan_info['error'] = f"File too large to scan: {file_size} bytes"
            return False, scan_info
        
        # Perform YARA scan
        try:
            matches = self.rules.match(file_path)
            is_malicious = len(matches) > 0
            
            # Add match details to scan info
            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                # Add matched strings
                for string in match.strings:
                    match_info['strings'].append({
                        'identifier': string[1],
                        'offset': string[0],
                        'data': string[2].hex() if isinstance(string[2], bytes) else string[2]
                    })
                
                scan_info['matches'].append(match_info)
            
            return is_malicious, scan_info
        except Exception as e:
            self.logger.error(f"YARA scan error for {file_path}: {e}")
            scan_info['error'] = str(e)
            return False, scan_info

    def _compute_file_hash(self, file_path):
        """Compute SHA-256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read and update hash in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error computing hash for {file_path}: {e}")
            return "error-computing-hash"

    def quarantine_file(self, file_path):
        """Move a malicious file to quarantine"""
        try:
            # Create quarantine directory if it doesn't exist
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir)
            
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"{file_name}_{int(time.time())}")
            
            # Move the file to quarantine
            shutil.move(file_path, quarantine_path)
            self.logger.info(f"Quarantined malicious file: {file_path} -> {quarantine_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error quarantining file {file_path}: {e}")
            return False