import os
import yara
import logging
from typing import Dict, List, Optional
import json
from datetime import datetime

class YARAScanner:
    def __init__(self, 
                 rules_path: str = 'yara_rules', 
                 log_path: str = 'logs/yara_scan.log'):
        """
        Initialize YARA scanner with enhanced logging
        
        Args:
            rules_path: Path to directory containing YARA rule files
            log_path: Path to log file for detailed scan results
        """
        # Setup logging
        self.logger = logging.getLogger("YARAScanner")
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        # File handler for detailed logging
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(console_handler)
        
        # YARA scanner properties
        self.rules_path = rules_path
        self.compiled_rules = None
        self.scan_log_path = log_path.replace('.log', '_detailed.json')
        
        # Load rules on initialization
        self.load_rules()
    
    def load_rules(self):
        """
        Compile YARA rules from the specified directory
        """
        try:
            # Find all .yar and .yara files
            rule_files = [
                os.path.join(self.rules_path, f) 
                for f in os.listdir(self.rules_path) 
                if f.endswith(('.yar', '.yara'))
            ]
            
            if not rule_files:
                self.logger.warning(f"No YARA rules found in {self.rules_path}")
                return
            
            # Compile rules
            self.compiled_rules = yara.compile(filepaths={
                os.path.splitext(os.path.basename(rf))[0]: rf 
                for rf in rule_files
            })
            
            self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
            
            # Log loaded rule details
            for rule_file in rule_files:
                self.logger.info(f"Loaded YARA rule file: {os.path.basename(rule_file)}")
        
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {e}")
            self.compiled_rules = None
    
    def scan_file(self, file_path: str) -> Dict[str, List[Dict]]:
        """
        Scan a single file with YARA rules and log detailed results
        
        Args:
            file_path: Path to the file to scan
        
        Returns:
            Dictionary of matched rules with details
        """
        if not self.compiled_rules:
            self.logger.warning("No YARA rules loaded")
            return {}
        
        try:
            # Skip very large files
            file_size = os.path.getsize(file_path)
            if file_size > 100_000_000:  # 100 MB limit
                self.logger.info(f"Skipping large file: {file_path}")
                return {}
            
            # Perform YARA scan
            matches = self.compiled_rules.match(file_path)
            
            # Process matches
            file_matches = []
            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': getattr(match, 'meta', {}),
                    'file_path': file_path,
                    'file_size': file_size,
                    'timestamp': datetime.now().isoformat()
                }
                file_matches.append(match_info)
                
                # Log each match
                self.logger.warning(
                    f"YARA MATCH: Rule '{match.rule}' detected in {file_path}"
                )
            
            # Log detailed matches to JSON
            if file_matches:
                self._log_detailed_matches(file_matches)
            
            return {file_path: file_matches} if file_matches else {}
        
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
            return {}
    
    def _log_detailed_matches(self, matches: List[Dict]):
        """
        Log detailed YARA matches to a JSON file
        
        Args:
            matches: List of match dictionaries
        """
        try:
            # Append to existing log or create new
            if os.path.exists(self.scan_log_path):
                with open(self.scan_log_path, 'r+') as f:
                    try:
                        existing_data = json.load(f)
                    except json.JSONDecodeError:
                        existing_data = []
                    
                    # Append new matches
                    existing_data.extend(matches)
                    
                    # Reset file pointer and write
                    f.seek(0)
                    json.dump(existing_data, f, indent=2)
            else:
                # Create new log file
                with open(self.scan_log_path, 'w') as f:
                    json.dump(matches, f, indent=2)
            
            self.logger.info(f"Detailed YARA matches logged to {self.scan_log_path}")
        
        except Exception as e:
            self.logger.error(f"Error logging detailed matches: {e}")
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, List[Dict]]:
        """
        Scan an entire directory with YARA rules
        
        Args:
            directory_path: Path to directory to scan
            recursive: Whether to scan subdirectories
        
        Returns:
            Dictionary of file paths and their YARA matches
        """
        directory_matches = {}
        
        # Scan start logging
        self.logger.info(f"Starting directory scan: {directory_path}")
        
        # Walk through directory
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Scan file
                file_matches = self.scan_file(file_path)
                
                # Add matches if found
                if file_matches:
                    directory_matches.update(file_matches)
                
                # Stop if not recursive
                if not recursive:
                    break
        
        # Scan completion logging
        self.logger.info(f"Directory scan completed. Total matches: {len(directory_matches)}")
        
        return directory_matches
    
    def reload_rules(self):
        """
        Reload YARA rules from the rules directory
        """
        self.logger.info("Reloading YARA rules")
        self.load_rules()

# Optional: Create default rules if none exist
def create_default_yara_rules(rules_path: str = 'yara_rules'):
    """
    Create default YARA rules if no rules exist
    
    Args:
        rules_path: Directory to store YARA rules
    """
    os.makedirs(rules_path, exist_ok=True)
    
    # Your existing or new default rules can be added here
    default_rules_file = os.path.join(rules_path, 'default_malware.yar')
    
    if not os.path.exists(default_rules_file):
        # Add your default rules content here
        default_rules = '''
rule Default_Suspicious_File {
    meta:
        description = "Basic suspicious file detection"
        author = "USBShield Team"
    
    strings:
        $susp1 = "base64" nocase
        $susp2 = "powershell" nocase
    
    condition:
        filesize < 500KB and 
        1 of them
}
'''
        
        with open(default_rules_file, 'w') as f:
            f.write(default_rules)
        
        print(f"Created default YARA rules in {default_rules_file}")

# Example usage
if __name__ == "__main__":
    # Create default rules if needed
    create_default_yara_rules()
    
    # Example of using the scanner
    scanner = YARAScanner()
    # Uncomment and modify for testing
    # matches = scanner.scan_directory("/path/to/scan")
    # print(matches)