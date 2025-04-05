import os
import hashlib
import threading
import time
import csv

class USBScanner:
    def __init__(self, callback=None, ioc_file_path=None):
        """Initialize the USB scanner.
        
        Args:
            callback: Function to call when scan is complete with results
            ioc_file_path: Path to the CSV file containing IOC hashes
        """
        self.callback = callback
        self.scan_results = {}
        self.stop_scan = False
        self.is_scanning = False
        self.ioc_hashes = set()
        
        # Load IOC hashes if file path is provided
        if ioc_file_path and os.path.exists(ioc_file_path):
            self.load_ioc_hashes(ioc_file_path)
    
    def load_ioc_hashes(self, ioc_file_path):
        """Load IOC hashes from a CSV file.
        
        Args:
            ioc_file_path: Path to the CSV file with IOC hashes
        """
        try:
            with open(ioc_file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row:  # Ensure row is not empty
                        # Strip whitespace and convert to lowercase
                        ioc_hash = row[0].strip().lower()
                        self.ioc_hashes.add(ioc_hash)
            print(f"Loaded {len(self.ioc_hashes)} IOC hashes")
        except Exception as e:
            print(f"Error loading IOC hashes: {e}")
    
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
            # Count total files before scanning
            total_files = 0
            for root, dirs, files in os.walk(drive_letter):
                total_files += len(files)
            
            # Initialize scan results
            self.scan_results = {
                "drive": drive_letter,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "start_time": time.time(),
                "status": "in_progress",
                "files_scanned": 0,
                "total_files": total_files,
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
                        # Calculate file hash
                        file_hash = self._get_file_hash(file_path)
                        
                        # Update progress
                        current_time = time.time()
                        elapsed_time = current_time - self.scan_results["start_time"]
                        files_scanned = self.scan_results["files_scanned"] + 1
                        
                        # Estimate remaining time
                        if files_scanned > 0:
                            time_per_file = elapsed_time / files_scanned
                            remaining_files = total_files - files_scanned
                            estimated_remaining_time = remaining_files * time_per_file
                        else:
                            estimated_remaining_time = 0
                        
                        # Prepare scan info
                        scan_info = {
                            "files_scanned": files_scanned,
                            "total_files": total_files,
                            "elapsed_time": elapsed_time,
                            "estimated_remaining_time": estimated_remaining_time,
                            "start_time": self.scan_results["start_time"]
                        }
                        
                        # Update scan results
                        self.scan_results["files_scanned"] = files_scanned
                        self.scan_results["scan_info"] = scan_info
                        
                        # Check if file hash matches IOC list
                        if file_hash.lower() in self.ioc_hashes:
                            file_info = {
                                "path": file_path,
                                "hash": file_hash,
                                "reason": "Matched IOC Hash"
                            }
                            self.scan_results["suspicious_files"].append(file_info)
                        
                        # Callback to update UI
                        if self.callback:
                            self.callback(self.scan_results)
                        
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