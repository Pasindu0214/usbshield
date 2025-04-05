#!/usr/bin/env python3
"""
USB Shield - Multi-threaded USB scanning tool
"""

import os
import sys
import time
import logging
import datetime
import concurrent.futures
import json
import hashlib
import shutil
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("usbshield.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("USBShield")

# Constants
DEFAULT_SIGNATURES_PATH = "signatures.json"
DEFAULT_THREADS = 16
MAX_THREADS = 32
SCAN_HISTORY_PATH = "scan_history.json"

class USBShield:
    def __init__(self, signatures_path=DEFAULT_SIGNATURES_PATH):
        """Initialize the USB Shield scanner"""
        self.signatures_path = signatures_path
        self.signatures = self.load_signatures()
        self.scan_history = self.load_scan_history()
        
    def load_signatures(self):
        """Load malware signatures from file"""
        try:
            with open(self.signatures_path, 'r') as f:
                signatures = json.load(f)
            logger.info(f"Loaded {len(signatures)} signatures")
            return signatures
        except Exception as e:
            logger.error(f"Error loading signatures: {str(e)}")
            return []
    
    def load_scan_history(self):
        """Load scan history from file"""
        try:
            if os.path.exists(SCAN_HISTORY_PATH):
                with open(SCAN_HISTORY_PATH, 'r') as f:
                    history = json.load(f)
                return history
            else:
                return []
        except Exception as e:
            logger.error(f"Error loading scan history: {str(e)}")
            return []
    
    def save_scan_history(self):
        """Save scan history to file"""
        try:
            with open(SCAN_HISTORY_PATH, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving scan history: {str(e)}")
    
    def generate_scan_id(self):
        """Generate a unique scan ID"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        return f"scan_{timestamp}"
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read the file in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {str(e)}")
            return None
    
    def scan_single_file(self, file_path, scan_id):
        """
        Scan a single file for IOCs
        
        Args:
            file_path: Path to the file to be scanned
            scan_id: Unique identifier for this scan session
        
        Returns:
            Dict containing scan results
        """
        try:
            # Get file information
            file_size = os.path.getsize(file_path)
            file_hash = self.calculate_file_hash(file_path)
            
            # Check file hash against signatures
            hash_match = next((sig for sig in self.signatures if sig.get('hash') == file_hash), None)
            if hash_match:
                return {
                    "file_path": file_path,
                    "file_size": file_size,
                    "file_hash": file_hash,
                    "detected": True,
                    "signature": hash_match,
                    "detection_type": "hash",
                    "scan_id": scan_id
                }
            
            # For binary files, check content patterns
            # Skip very large files to prevent memory issues
            if file_size < 10000000:  # 10MB limit
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read()
                        
                    # Check file against pattern signatures
                    for sig in self.signatures:
                        if 'pattern' in sig and isinstance(sig['pattern'], str):
                            pattern_bytes = sig['pattern'].encode('utf-8', errors='ignore')
                            if pattern_bytes in file_content:
                                return {
                                    "file_path": file_path,
                                    "file_size": file_size,
                                    "file_hash": file_hash,
                                    "detected": True,
                                    "signature": sig,
                                    "detection_type": "pattern",
                                    "scan_id": scan_id
                                }
                except Exception as read_error:
                    # Handle file read errors gracefully
                    logger.warning(f"Could not read file content for {file_path}: {str(read_error)}")
            
            # File is clean
            return {
                "file_path": file_path,
                "file_size": file_size,
                "file_hash": file_hash,
                "detected": False,
                "scan_id": scan_id
            }
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return {
                "file_path": file_path,
                "error": str(e),
                "scan_id": scan_id
            }

    def block_file(self, file_path):
        """Block/quarantine a malicious file"""
        try:
            # Create quarantine directory if it doesn't exist
            quarantine_dir = Path("quarantine")
            quarantine_dir.mkdir(exist_ok=True)
            
            # Move file to quarantine with original filename
            filename = os.path.basename(file_path)
            quarantine_path = quarantine_dir / f"{filename}.quarantine"
            
            # Copy file to quarantine
            shutil.copy2(file_path, quarantine_path)
            
            # Attempt to remove the original file
            try:
                os.remove(file_path)
                logger.info(f"File {file_path} moved to quarantine")
                return True
            except PermissionError:
                logger.warning(f"Couldn't remove original file {file_path} (permission denied)")
                return False
                
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {str(e)}")
            return False

    def scan_usb(self, usb_path, max_workers=DEFAULT_THREADS, progress_callback=None):
        """
        Scan USB drive using multiple threads
        
        Args:
            usb_path: Path to the USB drive
            max_workers: Number of threads to use
            progress_callback: Function to call with progress updates (for GUI)
        
        Returns:
            Dict containing scan results
        """
        # Ensure max_workers is within reasonable limits
        max_workers = min(max(1, max_workers), MAX_THREADS)
        
        scan_id = self.generate_scan_id()
        start_time = time.time()
        
        # Get all files from the USB drive
        files_to_scan = []
        try:
            for root, _, files in os.walk(usb_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    files_to_scan.append(file_path)
        except Exception as e:
            logger.error(f"Error walking USB directory {usb_path}: {str(e)}")
            return {
                "scan_id": scan_id,
                "start_time": start_time,
                "usb_path": usb_path,
                "error": str(e),
                "status": "failed"
            }
        
        # Log scan start
        logger.info(f"Starting scan of {usb_path} with ID {scan_id}")
        logger.info(f"Found {len(files_to_scan)} files to scan using {max_workers} threads")
        
        # Create results storage
        results = {
            "scan_id": scan_id,
            "start_time": start_time,
            "usb_path": usb_path,
            "total_files": len(files_to_scan),
            "detections": [],
            "errors": [],
            "status": "in_progress"
        }
        
        # Initialize progress tracking
        files_processed = 0
        
        # Use ThreadPoolExecutor to scan files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all file scanning tasks
            future_to_file = {
                executor.submit(self.scan_single_file, file_path, scan_id): file_path 
                for file_path in files_to_scan
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                files_processed += 1
                
                # Update progress if callback provided
                if progress_callback:
                    progress = files_processed / len(files_to_scan) * 100
                    progress_callback(progress, file_path)
                
                try:
                    result = future.result()
                    
                    # Store result
                    if "error" in result:
                        results["errors"].append(result)
                        logger.error(f"Error scanning {file_path}: {result['error']}")
                    elif result.get("detected"):
                        results["detections"].append(result)
                        logger.warning(f"Detection in {file_path}: {result['signature']['name']}")
                        
                        # Block/quarantine the file
                        if self.block_file(file_path):
                            result["blocked"] = True
                        else:
                            result["blocked"] = False
                    
                except Exception as e:
                    logger.error(f"Unexpected error processing {file_path}: {str(e)}")
                    results["errors"].append({
                        "file_path": file_path,
                        "error": str(e),
                        "scan_id": scan_id
                    })
        
        # Finalize results
        end_time = time.time()
        scan_duration = end_time - start_time
        results["end_time"] = end_time
        results["duration"] = scan_duration
        results["status"] = "completed"
        
        # Log scan completion
        logger.info(f"Scan {scan_id} completed in {scan_duration:.2f} seconds")
        logger.info(f"Found {len(results['detections'])} potential threats")
        
        # Save scan to history
        scan_summary = {
            "scan_id": scan_id,
            "usb_path": usb_path,
            "timestamp": start_time,
            "duration": scan_duration,
            "total_files": len(files_to_scan),
            "detections": len(results["detections"]),
            "errors": len(results["errors"])
        }
        self.scan_history.append(scan_summary)
        self.save_scan_history()
        
        return results

class USBShieldGUI:
    def __init__(self, root):
        """Initialize the GUI"""
        self.root = root
        self.root.title("USB Shield")
        self.root.geometry("600x400")
        
        self.scanner = USBShield()
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the GUI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # USB Drive selection
        ttk.Label(main_frame, text="USB Drive:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # Get available drives (simplified for this example)
        self.drives = self.get_available_drives()
        self.drive_var = tk.StringVar()
        if self.drives:
            self.drive_var.set(self.drives[0])
        
        drive_dropdown = ttk.Combobox(main_frame, textvariable=self.drive_var, values=self.drives)
        drive_dropdown.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Thread count selection
        ttk.Label(main_frame, text="Thread Count:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.thread_var = tk.IntVar(value=DEFAULT_THREADS)
        thread_spinbox = ttk.Spinbox(main_frame, from_=1, to=MAX_THREADS, textvariable=self.thread_var)
        thread_spinbox.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Scan button
        scan_button = ttk.Button(main_frame, text="Scan USB", command=self.start_scan)
        scan_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Progress bar
        ttk.Label(main_frame, text="Progress:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, 
                                          length=300, mode='determinate', 
                                          variable=self.progress_var)
        self.progress_bar.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results")
        results_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Results text
        self.results_text = tk.Text(results_frame, height=10, width=60)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
    
    def get_available_drives(self):
        """Get list of available drives"""
        # This is a simplified implementation
        # On Windows, you'd use something like win32api.GetLogicalDriveStrings()
        if sys.platform == 'win32':
            # Dummy implementation for Windows
            return ["F:", "G:", "H:"]
        else:
            # Dummy implementation for Unix-like systems
            return ["/media/usb0", "/media/usb1"]
    
    def update_progress(self, progress, current_file):
        """Update progress bar and status"""
        self.progress_var.set(progress)
        self.status_var.set(f"Scanning: {os.path.basename(current_file)}")
        self.root.update_idletasks()
    
    def start_scan(self):
        """Start USB scanning process"""
        drive = self.drive_var.get()
        if not drive:
            messagebox.showerror("Error", "No USB drive selected")
            return
        
        if not os.path.exists(drive):
            messagebox.showerror("Error", f"Drive {drive} does not exist")
            return
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_var.set("Starting scan...")
        
        # Run scan in a separate thread to keep UI responsive
        def run_scan():
            try:
                thread_count = self.thread_var.get()
                results = self.scanner.scan_usb(drive, thread_count, self.update_progress)
                
                # Update UI with results
                self.root.after(0, lambda: self.show_results(results))
            except Exception as e:
                self.root.after(0, lambda: self.show_error(str(e)))
        
        import threading
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def show_results(self, results):
        """Display scan results"""
        self.progress_var.set(100)
        self.status_var.set("Scan completed")
        
        # Format results for display
        summary = f"Scan Summary:\n"
        summary += f"Drive: {results['usb_path']}\n"
        summary += f"Total Files: {results['total_files']}\n"
        summary += f"Scan Duration: {results['duration']:.2f} seconds\n"
        summary += f"Detections: {len(results['detections'])}\n"
        summary += f"Errors: {len(results['errors'])}\n\n"
        
        if results['detections']:
            summary += "Detected Threats:\n"
            for detection in results['detections']:
                summary += f"- {detection['file_path']} "
                summary += f"({detection['signature']['name']})\n"
                if detection.get('blocked', False):
                    summary += "  [Quarantined]\n"
                else:
                    summary += "  [Not Quarantined]\n"
        
        self.results_text.insert(tk.END, summary)
        
        # Show message box with summary
        if results['detections']:
            messagebox.warning("Scan Complete", 
                              f"Scan completed. Found {len(results['detections'])} potential threats.")
        else:
            messagebox.showinfo("Scan Complete", "Scan completed. No threats detected.")

    def show_error(self, error_message):
        """Display error message"""
        self.status_var.set("Error during scan")
        self.results_text.insert(tk.END, f"Error: {error_message}\n")
        messagebox.showerror("Scan Error", f"An error occurred during scanning: {error_message}")

def main():
    """Main entry point"""
    # If run with GUI flag, start GUI
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        root = tk.Tk()
        app = USBShieldGUI(root)
        root.mainloop()
    else:
        # Command line mode
        scanner = USBShield()
        
        # Check arguments
        if len(sys.argv) < 2:
            print("Usage: python usbshield.py [USB_PATH] [THREAD_COUNT]")
            print("   or: python usbshield.py --gui")
            sys.exit(1)
        
        usb_path = sys.argv[1]
        thread_count = DEFAULT_THREADS
        
        if len(sys.argv) > 2:
            try:
                thread_count = int(sys.argv[2])
            except ValueError:
                print(f"Invalid thread count: {sys.argv[2]}. Using default: {DEFAULT_THREADS}")
                thread_count = DEFAULT_THREADS
        
        # Scan the USB drive
        print(f"Scanning {usb_path} with {thread_count} threads...")
        results = scanner.scan_usb(usb_path, thread_count)
        
        # Print results
        print("\nScan Results:")
        print(f"Scan ID: {results['scan_id']}")
        print(f"USB Path: {results['usb_path']}")
        print(f"Total Files: {results['total_files']}")
        print(f"Scan Duration: {results['duration']:.2f} seconds")
        print(f"Detections: {len(results['detections'])}")
        print(f"Errors: {len(results['errors'])}")
        
        if results['detections']:
            print("\nDetected Threats:")
            for detection in results['detections']:
                print(f"- {detection['file_path']} ({detection['signature']['name']})")
                if detection.get('blocked', False):
                    print("  [Quarantined]")
                else:
                    print("  [Not Quarantined]")

if __name__ == "__main__":
    main()