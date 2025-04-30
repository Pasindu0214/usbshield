import os
import hashlib
import threading
import time
import csv
import concurrent.futures
from typing import List, Dict, Callable, Optional

class USBScanner:
    def __init__(self, callback=None, ioc_file_path=None, max_workers=None):
        """Initialize the USB scanner.
        
        Args:
            callback: Function to call when scan is complete with results
            ioc_file_path: Path to the CSV file containing IOC hashes
            max_workers: Maximum number of threads for parallel scanning
        """
        self.callback = callback
        self.scan_results = {}
        self.stop_scan = False
        self.is_scanning = False
        self.ioc_hashes = set()
        
        # Determine max workers (default to CPU cores or 4)
        self.max_workers = max_workers or (os.cpu_count() or 4)
        
        # Load IOC hashes if file path is provided
        if ioc_file_path and os.path.exists(ioc_file_path):
            self.load_ioc_hashes(ioc_file_path)
    
    def load_ioc_hashes(self, ioc_file_path):
        """Load IOC hashes from a CSV file with optimized loading."""
        try:
            with open(ioc_file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                
                # Try to handle cases with or without headers
                first_row = next(reader, None)
                
                # If first row looks like a header (contains words), skip it
                if first_row and any(word in ' '.join(first_row).lower() for word in ['hash', 'sha', 'ioc', 'md5']):
                    rows = reader
                else:
                    # First row is an actual hash, add it back
                    rows = [first_row] if first_row else []
                    rows.extend(reader)
                
                # Use set comprehension for faster loading
                self.ioc_hashes = {
                    row[0].strip().lower() 
                    for row in rows 
                    if row and len(row[0].strip()) == 64 and all(c in '0123456789abcdef' for c in row[0].strip().lower())
                }
            
            print(f"Loaded {len(self.ioc_hashes)} IOC hashes from {ioc_file_path}")
            print("Sample Hashes:", list(self.ioc_hashes)[:10], "..." if len(self.ioc_hashes) > 10 else "")
        except Exception as e:
            print(f"Error loading IOC hashes: {e}")
    
    def _get_file_hash(self, file_path):
        """
        Get the SHA-256 hash of a file with improved performance.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA-256 hash of the file
        """
        try:
            # Use larger chunk size for faster reading
            chunk_size = 65536  # 64kb chunks
            
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                
                # Read file in larger chunks
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    file_hash.update(chunk)
                
                return file_hash.hexdigest().lower()
        except (IOError, PermissionError) as e:
            print(f"Error hashing {file_path}: {e}")
            return "error-calculating-hash"
    
    def _scan_single_file(self, file_path):
        """
        Scan a single file for potential threats.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with file details if suspicious, else None
        """
        try:
            # Skip very large files to prevent performance issues
            if os.path.getsize(file_path) > 500_000_000:  # 500 MB limit
                return None
            
            file_hash = self._get_file_hash(file_path)
            
            # Quick hash comparison
            if file_hash.lower() in self.ioc_hashes:
                return {
                    "path": file_path,
                    "hash": file_hash,
                    "reason": "Matched IOC Hash"
                }
            
            return None
        
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            return None
    
    def scan_drive(self, drive_letter):
        """Scan a USB drive for potential threats."""
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
        """Background thread for scanning a drive with parallel processing."""
        start_time = time.time()
        
        try:
            # Validate and normalize drive letter
            if not drive_letter.endswith(":"):
                drive_letter += ":"
            
            if not os.path.exists(drive_letter):
                self._update_scan_results({
                    "drive": drive_letter,
                    "status": "error",
                    "error": f"Drive {drive_letter} does not exist"
                })
                return
            
            # Collect all files to scan
            files_to_scan = []
            for root, _, files in os.walk(drive_letter):
                if self.stop_scan:
                    break
                
                for file in files:
                    if self.stop_scan:
                        break
                    file_path = os.path.join(root, file)
                    files_to_scan.append(file_path)
            
            # Initialize scan results
            self.scan_results = {
                "drive": drive_letter,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "start_time": start_time,
                "status": "in_progress",
                "files_scanned": 0,
                "total_files": len(files_to_scan),
                "suspicious_files": [],
                "error": None
            }
            
            # Use ThreadPoolExecutor for parallel scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit scan tasks
                future_to_file = {
                    executor.submit(self._scan_single_file, file_path): file_path 
                    for file_path in files_to_scan
                }
                
                # Process results
                for future in concurrent.futures.as_completed(future_to_file):
                    if self.stop_scan:
                        break
                    
                    # Update scan progress
                    current_time = time.time()
                    files_scanned = self.scan_results["files_scanned"] + 1
                    self.scan_results["files_scanned"] = files_scanned
                    
                    # Estimate remaining time
                    elapsed_time = current_time - start_time
                    estimated_total_time = (elapsed_time / files_scanned * len(files_to_scan)) if files_scanned > 0 else 0
                    estimated_remaining_time = estimated_total_time - elapsed_time
                    
                    scan_info = {
                        "files_scanned": files_scanned,
                        "total_files": len(files_to_scan),
                        "elapsed_time": elapsed_time,
                        "estimated_remaining_time": estimated_remaining_time
                    }
                    
                    # Combine scan info
                    partial_results = dict(self.scan_results)
                    partial_results["scan_info"] = scan_info
                    
                    # Update UI periodically
                    self._update_scan_results(partial_results)
                    
                    # Check result
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        if result:
                            self.scan_results["suspicious_files"].append(result)
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
            
            # Finalize scan
            self.scan_results["status"] = "completed"
            self.scan_results["duration"] = time.time() - start_time
            
            # Final callback
            self._update_scan_results(self.scan_results)
        
        except Exception as e:
            self.scan_results["status"] = "error"
            self.scan_results["error"] = str(e)
            self._update_scan_results(self.scan_results)
        
        finally:
            self.is_scanning = False
    
    def _update_scan_results(self, results):
        """
        Update scan results and call the callback if provided.
        
        Args:
            results: Dictionary of scan results
        """
        if self.callback:
            self.callback(results)
    
    def stop_scanning(self):
        """Stop the current scan."""
        self.stop_scan = True
        return {"status": "stopping", "message": "Stopping scan..."}