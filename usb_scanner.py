import os
import hashlib
import threading
import time
import csv
import concurrent.futures
from typing import List, Dict, Callable, Optional
from utils.yara_scanner import YARAScanner  # Using your existing YARAScanner implementation
from utils.virustotal_scanner import VirusTotalScanner  # Add VirusTotal scanner import

class USBScanner:
    def __init__(
        self, 
        callback=None, 
        ioc_file_path=None, 
        max_workers=None,
        yara_rules_path='yara_rules',
        yara_log_path='logs/yara_scan.log',
        check_virustotal=True  # Enable VirusTotal scanning by default
    ):
        """Initialize the USB scanner with YARA and VirusTotal integration.
        
        Args:
            callback: Function to call when scan is complete with results
            ioc_file_path: Path to the CSV file containing IOC hashes
            max_workers: Maximum number of threads for parallel scanning
            yara_rules_path: Path to YARA rules directory
            yara_log_path: Path to YARA scan log file
            check_virustotal: Whether to enable VirusTotal scanning
        """
        self.callback = callback
        self.scan_results = {}
        self.stop_scan = False
        self.is_scanning = False
        self.ioc_hashes = set()
        self.check_virustotal = check_virustotal
        
        # Determine max workers (default to CPU cores or 4)
        self.max_workers = max_workers or (os.cpu_count() or 4)
        
        # Initialize YARA scanner with your existing implementation
        self.yara_scanner = YARAScanner(rules_path=yara_rules_path, log_path=yara_log_path)
        
        # Initialize VirusTotal scanner
        self.vt_scanner = VirusTotalScanner() if check_virustotal else None
        
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
        Scan a single file for potential threats with VirusTotal integration.
        """
        try:
            # Skip very large files to prevent performance issues
            file_size = os.path.getsize(file_path)
            if file_size > 500_000_000:  # 500 MB limit
                return None
            
            file_hash = self._get_file_hash(file_path)
            if file_hash == "error-calculating-hash":
                return None
            
            # Initialize suspicious findings
            suspicious_findings = []
            
            # Check against IOC hashes (step 1)
            ioc_match = False
            if file_hash.lower() in self.ioc_hashes:
                suspicious_findings.append({
                    "type": "IOC_HASH",
                    "reason": "Matched Known Malicious Hash",
                    "details": f"Hash matches predefined Indicator of Compromise (IOC)"
                })
                ioc_match = True
            
            # Perform YARA scanning independently
            yara_matches = self.yara_scanner.scan_file(file_path)
            if yara_matches and file_path in yara_matches and yara_matches[file_path]:
                for match in yara_matches[file_path]:
                    yara_finding = {
                        "type": "YARA_RULE",
                        "rule": match.get('rule', 'Unknown Rule'),
                        "reason": "Matched YARA Detection Rule",
                        "details": self._format_yara_match_details(match)
                    }
                    suspicious_findings.append(yara_finding)
            
            # Check with VirusTotal if enabled and not found in IOC hashes (step 2 & 3)
            # First check if the hash is in our database
            vt_match_from_db = False
            if self.check_virustotal and self.vt_scanner and not ioc_match:
                # First check if the hash is in our database (hashesDB.db)
                db_result = self.vt_scanner.check_hash_in_db(file_hash)
                if db_result and db_result.get('scan_result') in ['malicious', 'suspicious']:
                    detection_text, is_threat, threat_level = self.vt_scanner.get_detection_info(db_result)
                    if is_threat:
                        vt_finding = {
                            "type": "VIRUSTOTAL",
                            "reason": detection_text,
                            "threat_level": threat_level,
                            "permalink": db_result.get('permalink', ''),
                            "detection_count": db_result.get('detection_count', 0),
                            "total_engines": db_result.get('total_engines', 0),
                            "from_cache": True
                        }
                        suspicious_findings.append(vt_finding)
                        vt_match_from_db = True
                
                # If not in database or not a threat in database, query VirusTotal API
                if not vt_match_from_db:
                    vt_result = self.vt_scanner.scan_file_hash(file_hash)
                    detection_text, is_threat, threat_level = self.vt_scanner.get_detection_info(vt_result)
                    
                    if is_threat:
                        vt_finding = {
                            "type": "VIRUSTOTAL",
                            "reason": detection_text,
                            "threat_level": threat_level,
                            "permalink": vt_result.get('permalink', ''),
                            "detection_count": vt_result.get('detection_count', 0),
                            "total_engines": vt_result.get('total_engines', 0),
                            "from_cache": vt_result.get('from_cache', False)
                        }
                        suspicious_findings.append(vt_finding)
            
            # Return findings if any suspicious elements found
            if suspicious_findings:
                return {
                    "path": file_path,
                    "hash": file_hash,
                    "file_size": file_size,
                    "suspicious_findings": suspicious_findings
                }
            
            return None
        
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            return None
    
    def _format_yara_match_details(self, match):
        """
        Format YARA match details for human-readable output.
        Adapted to work with your YARAScanner output format.
        
        Args:
            match: YARA match dictionary
        
        Returns:
            Formatted description of the YARA match
        """
        details = []
        
        # Add rule metadata if available
        if 'meta' in match and match['meta']:
            for key, value in match['meta'].items():
                details.append(f"{key.capitalize()}: {value}")
        
        # Add tags if available
        if 'tags' in match and match['tags']:
            details.append(f"Tags: {', '.join(match['tags'])}")
        
        # Add namespace if available
        if 'namespace' in match:
            details.append(f"Namespace: {match['namespace']}")
        
        return "; ".join(details) or "Suspicious pattern detected"
    
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
        """
        Background thread to perform drive scanning with progress updates.
        
        Args:
            drive_letter: Drive letter to scan (e.g., "C:")
        """
        try:
            scan_start_time = time.time()
            root_path = f"{drive_letter}\\"
            
            # Initialize result containers
            suspicious_files = []
            yara_matches = []
            virustotal_matches = []
            files_scanned = 0
            total_files = 0
            
            # First, count total files for progress reporting
            print(f"Counting files in {root_path}...")
            for root, _, files in os.walk(root_path):
                if self.stop_scan:
                    self._update_scan_results({
                        "status": "stopped",
                        "message": "Scan was stopped during file counting",
                        "drive": drive_letter
                    })
                    return
                
                total_files += len(files)
            
            print(f"Found {total_files} files to scan")
            
            # Create a thread pool for parallel scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                
                # Walk through all files
                for root, _, files in os.walk(root_path):
                    if self.stop_scan:
                        # Cancel all pending futures
                        for future in futures:
                            future.cancel()
                        
                        self._update_scan_results({
                            "status": "stopped",
                            "message": "Scan was stopped by user",
                            "drive": drive_letter
                        })
                        return
                    
                    # Submit files to the thread pool
                    for file in files:
                        file_path = os.path.join(root, file)
                        futures.append(executor.submit(self._scan_single_file, file_path))
                    
                    # Process completed futures
                    for future in list(concurrent.futures.as_completed(futures)):
                        futures.remove(future)
                        result = future.result()
                        files_scanned += 1
                        
                        # If file is suspicious, add to results
                        if result:
                            file_entry = {
                                "path": result["path"],
                                "hash": result["hash"],
                                "file_size": result["file_size"]
                            }
                            
                            # Process findings
                            for finding in result["suspicious_findings"]:
                                finding_type = finding["type"]
                                
                                if finding_type == "IOC_HASH":
                                    suspicious_files.append(file_entry)
                                elif finding_type == "YARA_RULE":
                                    yara_matches.append({
                                        "file_path": result["path"],
                                        "rule": finding["rule"],
                                        "details": finding["details"]
                                    })
                                elif finding_type == "VIRUSTOTAL":
                                    virustotal_matches.append({
                                        "file_path": result["path"],
                                        "hash": result["hash"],
                                        "reason": finding["reason"],
                                        "threat_level": finding["threat_level"],
                                        "permalink": finding.get("permalink", ""),
                                        "detection_count": finding.get("detection_count", 0),
                                        "total_engines": finding.get("total_engines", 0),
                                        "from_cache": finding.get("from_cache", False)
                                    })
                        
                        # Update progress every 10 files or 1 second
                        current_time = time.time()
                        elapsed_time = current_time - scan_start_time
                        
                        if files_scanned % 10 == 0 or (current_time - scan_start_time) > 1:
                            # Calculate remaining time
                            if files_scanned > 0 and elapsed_time > 0:
                                files_per_second = files_scanned / elapsed_time
                                remaining_files = total_files - files_scanned
                                estimated_remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
                            else:
                                estimated_remaining_time = 0
                            
                            # Create and send progress update
                            scan_info = {
                                'files_scanned': files_scanned,
                                'total_files': total_files,
                                'elapsed_time': elapsed_time,
                                'estimated_remaining_time': estimated_remaining_time,
                                'start_time': scan_start_time
                            }
                            
                            self._update_scan_results({
                                "status": "in_progress",
                                "scan_info": scan_info,
                                "drive": drive_letter
                            })
            
            # Scan completed, send final results
            scan_time = time.time() - scan_start_time
            
            self._update_scan_results({
                "status": "completed",
                "drive": drive_letter,
                "files_scanned": files_scanned,
                "suspicious_files": suspicious_files,
                "yara_matches": yara_matches,
                "virustotal_matches": virustotal_matches,  # Add VirusTotal matches
                "scan_time": scan_time
            })
            
            print(f"Scan completed: {files_scanned} files scanned in {scan_time:.2f} seconds")
            print(f"Found {len(suspicious_files)} IOC matches, {len(yara_matches)} YARA matches, and {len(virustotal_matches)} VirusTotal matches")
        
        except Exception as e:
            import traceback
            print(f"Error scanning drive {drive_letter}: {e}")
            print(traceback.format_exc())
            
            self._update_scan_results({
                "status": "error",
                "error": str(e),
                "drive": drive_letter
            })
        
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
    
    def enable_virustotal(self, enable=True):
        """Enable or disable VirusTotal scanning."""
        if enable and not self.vt_scanner:
            self.vt_scanner = VirusTotalScanner()
        
        self.check_virustotal = enable
        return {"status": "success", "virustotal_enabled": enable}