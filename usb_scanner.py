import os
import hashlib
import threading
import time

class USBScanner:
    def __init__(self, callback=None):
        """Initialize the USB scanner.
        
        Args:
            callback: Function to call when scan is complete with results
        """
        self.callback = callback
        self.scan_results = {}
        self.stop_scan = False
        self.is_scanning = False
        
    def scan_drive(self, drive_letter):
        """Scan a USB drive for potential threats.
        
        Args:
            drive_letter: The drive letter to scan (e.g., "F:")
            
        Returns:
            Dictionary with scan results
        """
        if self.is_scanning:
            return {"status": "error", "message": "Another scan is already in progress"}
        
        self.is_scanning = True
        self.stop_scan = False
        
        # Start scan in a separate thread to avoid blocking the UI
        scan_thread = threading.Thread(target=self._scan_drive_thread, args=(drive_letter,))
        scan_thread.daemon = True
        scan_thread.start()
        
        return {"status": "started", "message": f"Started scanning drive {drive_letter}"}
    
    def _scan_drive_thread(self, drive_letter):
        """Background thread for scanning a drive."""
        try:
            # Initialize scan results
            self.scan_results = {
                "drive": drive_letter,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "in_progress",
                "files_scanned": 0,
                "suspicious_files": [],
                "error": None
            }
            
            # Make sure drive letter has proper format
            if not drive_letter.endswith(":"):
                drive_letter += ":"
            
            # Check if drive exists
            if not os.path.exists(drive_letter):
                self.scan_results["status"] = "error"
                self.scan_results["error"] = f"Drive {drive_letter} does not exist"
                if self.callback:
                    self.callback(self.scan_results)
                self.is_scanning = False
                return
            
            # Scan drive
            for root, dirs, files in os.walk(drive_letter):
                # Check if scan was stopped
                if self.stop_scan:
                    self.scan_results["status"] = "stopped"
                    if self.callback:
                        self.callback(self.scan_results)
                    self.is_scanning = False
                    return
                
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Check file extension and attributes
                        if self._is_suspicious_file(file_path):
                            self.scan_results["suspicious_files"].append({
                                "path": file_path,
                                "reason": "Suspicious extension or attribute",
                                "hash": self._get_file_hash(file_path)
                            })
                        
                        # Increment files scanned count
                        self.scan_results["files_scanned"] += 1
                        
                    except Exception as e:
                        # Continue scanning other files even if one fails
                        print(f"Error scanning file {file_path}: {e}")
            
            # Scan completed
            self.scan_results["status"] = "completed"
            
            # Call callback with results
            if self.callback:
                self.callback(self.scan_results)
                
        except Exception as e:
            self.scan_results["status"] = "error"
            self.scan_results["error"] = str(e)
            
            if self.callback:
                self.callback(self.scan_results)
        
        finally:
            self.is_scanning = False
    
    def stop_scanning(self):
        """Stop the current scan."""
        self.stop_scan = True
        return {"status": "stopping", "message": "Stopping scan..."}
    
    def _is_suspicious_file(self, file_path):
        """Check if a file is suspicious based on extension or attributes.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Boolean indicating if the file is suspicious
        """
        # List of suspicious file extensions
        suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', 
            '.wsf', '.hta', '.scr', '.pif', '.reg', '.vbe', '.jse',
            '.lnk', '.com'
        ]
        
        # Check extension
        _, ext = os.path.splitext(file_path.lower())
        if ext in suspicious_extensions:
            # For executable files, we could add additional checks here
            try:
                # Check file size (small executables might be more suspicious)
                file_size = os.path.getsize(file_path)
                if file_size < 100000:  # Less than 100KB
                    return True
                
                # In a real implementation, we could add more checks:
                # - Check file entropy
                # - Check for known malicious signatures
                # - Scan with YARA rules (will be implemented later)
                
                # For now, mark all executables as suspicious for demonstration
                return True
                
            except Exception as e:
                print(f"Error checking file {file_path}: {e}")
        
        return False
    
    def _get_file_hash(self, file_path):
        """Get the SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA-256 hash of the file
        """
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                # Read and update hash in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            print(f"Error getting hash for {file_path}: {e}")
            return "error-calculating-hash" 