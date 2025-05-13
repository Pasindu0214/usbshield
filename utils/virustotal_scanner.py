import os
import requests
import json
import time
import sqlite3
import hashlib
from datetime import datetime, timedelta
import logging

class VirusTotalScanner:
    """
    A class to handle VirusTotal API calls with caching in a SQLite database.
    """
    
    def __init__(self, api_key="630b0f9af4e90c6f37b90a9efef226d20ae329516ebc3a6869503c462bb49744", 
                 db_path="hashesDB.db", cache_expiry_days=30):
        """
        Initialize the VirusTotal scanner with database caching.
        
        Args:
            api_key: VirusTotal API key (default is your provided key)
            db_path: Path to the SQLite database file
            cache_expiry_days: Number of days to keep cache entries before refreshing
        """
        self.api_key = api_key
        self.db_path = db_path
        self.cache_expiry_days = cache_expiry_days
        self.last_api_call_time = 0
        self.api_call_delay = 15  # Minimum seconds between API calls (free tier limit)
        
        # Set up logging
        self.logger = logging.getLogger("VirusTotalScanner")
        self.logger.setLevel(logging.INFO)
        
        # Create a console handler if none exists
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(console_handler)
        
        # Initialize the database
        self._init_database()
    
    def _init_database(self):
        """Create the database and tables if they don't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create scanned_hashes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scanned_hashes (
                    hash TEXT PRIMARY KEY,
                    scan_date TEXT,
                    detection_count INTEGER,
                    total_engines INTEGER,
                    scan_result TEXT,
                    permalink TEXT,
                    raw_json TEXT
                )
            ''')
            
            # Create expired_hashes view for cleaning
            cursor.execute('''
                CREATE VIEW IF NOT EXISTS expired_hashes AS
                SELECT hash FROM scanned_hashes
                WHERE julianday('now') - julianday(scan_date) > ?
            ''', (self.cache_expiry_days,))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Initialized database at {self.db_path}")
            
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization error: {e}")
    
    def _clean_expired_cache(self):
        """Remove expired entries from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get count of expired hashes
            cursor.execute("SELECT COUNT(*) FROM expired_hashes")
            expired_count = cursor.fetchone()[0]
            
            if expired_count > 0:
                # Delete expired hashes
                cursor.execute("DELETE FROM scanned_hashes WHERE hash IN (SELECT hash FROM expired_hashes)")
                self.logger.info(f"Removed {expired_count} expired entries from cache")
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            self.logger.error(f"Error cleaning expired cache: {e}")
    
    def check_hash_in_db(self, file_hash):
        """
        Check if a hash exists in the database and is not expired.
        
        Args:
            file_hash: SHA-256 hash to check
            
        Returns:
            Dict with results if found and not expired, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if hash exists and is not expired
            cursor.execute('''
                SELECT hash, scan_date, detection_count, total_engines, 
                       scan_result, permalink, raw_json
                FROM scanned_hashes
                WHERE hash = ? AND julianday('now') - julianday(scan_date) <= ?
            ''', (file_hash, self.cache_expiry_days))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                self.logger.info(f"Found hash {file_hash} in database cache")
                return {
                    'hash': row[0],
                    'scan_date': row[1],
                    'detection_count': row[2],
                    'total_engines': row[3],
                    'scan_result': row[4],
                    'permalink': row[5],
                    'raw_json': row[6],
                    'from_cache': True
                }
            
            return None
            
        except sqlite3.Error as e:
            self.logger.error(f"Database query error: {e}")
            return None
    
    def save_hash_to_db(self, hash_data):
        """
        Save hash scanning results to the database.
        
        Args:
            hash_data: Dictionary containing hash scan results
            
        Returns:
            Boolean indicating success
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if hash already exists
            cursor.execute("SELECT hash FROM scanned_hashes WHERE hash = ?", (hash_data['hash'],))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                cursor.execute('''
                    UPDATE scanned_hashes 
                    SET scan_date = ?, detection_count = ?, total_engines = ?,
                        scan_result = ?, permalink = ?, raw_json = ?
                    WHERE hash = ?
                ''', (
                    hash_data['scan_date'],
                    hash_data['detection_count'],
                    hash_data['total_engines'],
                    hash_data['scan_result'],
                    hash_data.get('permalink', ''),
                    hash_data.get('raw_json', '{}'),
                    hash_data['hash']
                ))
                self.logger.info(f"Updated hash {hash_data['hash']} in database")
            else:
                # Insert new record
                cursor.execute('''
                    INSERT INTO scanned_hashes 
                    (hash, scan_date, detection_count, total_engines, scan_result, permalink, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    hash_data['hash'],
                    hash_data['scan_date'],
                    hash_data['detection_count'],
                    hash_data['total_engines'],
                    hash_data['scan_result'],
                    hash_data.get('permalink', ''),
                    hash_data.get('raw_json', '{}')
                ))
                self.logger.info(f"Added new hash {hash_data['hash']} to database")
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Database save error: {e}")
            return False
    
    def scan_file_hash(self, file_hash):
        """
        Scan a file hash using the VirusTotal API, with caching.
        
        This follows the requested flow:
        1. Check the hash in the database
        2. If not found or expired, query VirusTotal API
        3. Store results in the database
        
        Args:
            file_hash: SHA-256 hash of the file to check
            
        Returns:
            Dict with scan results
        """
        # Clean expired cache entries periodically
        self._clean_expired_cache()
        
        # Normalize hash
        file_hash = file_hash.lower()
        
        # Check if hash exists in database
        db_result = self.check_hash_in_db(file_hash)
        if db_result:
            return db_result
        
        # Hash not in database or expired, query VirusTotal API
        self.logger.info(f"Hash {file_hash} not found in database, querying VirusTotal API")
        return self._query_virustotal_api(file_hash)
    
    def _query_virustotal_api(self, file_hash):
        """
        Query the VirusTotal API for a file hash.
        
        Args:
            file_hash: SHA-256 hash to query
            
        Returns:
            Dict with scan results
        """
        # Respect API rate limits (free tier: 4 requests per minute)
        current_time = time.time()
        time_since_last_call = current_time - self.last_api_call_time
        
        if time_since_last_call < self.api_call_delay:
            sleep_time = self.api_call_delay - time_since_last_call
            self.logger.info(f"Rate limiting: Sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        # Set the last API call time to the current time
        self.last_api_call_time = time.time()
        
        # Make the API request
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(url, headers=headers)
            
            # Handle response based on status code
            if response.status_code == 200:
                # Successful request
                data = response.json()
                
                # Extract and process results
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values()) if stats else 0
                
                # Determine scan result
                if malicious > 0:
                    result = "malicious"
                elif suspicious > 0:
                    result = "suspicious"
                else:
                    result = "clean"
                
                # Create result dictionary
                vt_result = {
                    'hash': file_hash,
                    'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'detection_count': malicious + suspicious,
                    'total_engines': total,
                    'scan_result': result,
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}",
                    'raw_json': json.dumps(data),
                    'from_cache': False
                }
                
                # Save to database
                self.save_hash_to_db(vt_result)
                
                self.logger.info(f"Successfully scanned hash {file_hash} with VirusTotal: {result}")
                return vt_result
                
            elif response.status_code == 404:
                # Hash not found in VirusTotal
                vt_result = {
                    'hash': file_hash,
                    'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'detection_count': 0,
                    'total_engines': 0,
                    'scan_result': "unknown",
                    'permalink': "",
                    'raw_json': "{}",
                    'from_cache': False,
                    'error': "File not found in VirusTotal database"
                }
                
                # Save to database
                self.save_hash_to_db(vt_result)
                
                self.logger.info(f"Hash {file_hash} not found in VirusTotal")
                return vt_result
                
            else:
                # API error
                error_msg = f"VirusTotal API error: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                
                return {
                    'hash': file_hash,
                    'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'detection_count': 0,
                    'total_engines': 0,
                    'scan_result': "error",
                    'error': error_msg,
                    'from_cache': False
                }
                
        except Exception as e:
            # Network or other error
            error_msg = f"Error querying VirusTotal API: {str(e)}"
            self.logger.error(error_msg)
            
            return {
                'hash': file_hash,
                'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'detection_count': 0,
                'total_engines': 0,
                'scan_result': "error",
                'error': error_msg,
                'from_cache': False
            }
    
    def get_detection_info(self, result):
        """
        Get human-readable information about the detection.
        
        Args:
            result: Result dictionary from scan_file_hash
            
        Returns:
            Tuple of (detection_text, is_threat, threat_level)
            - detection_text: Human-readable description
            - is_threat: Boolean indicating if it's a threat
            - threat_level: One of "clean", "suspicious", "malicious", "unknown", "error"
        """
        scan_result = result.get('scan_result', 'unknown')
        detection_count = result.get('detection_count', 0)
        total_engines = result.get('total_engines', 0)
        
        is_threat = scan_result in ["malicious", "suspicious"]
        
        if scan_result == "malicious":
            detection_text = f"Malicious file detected by {detection_count}/{total_engines} engines"
            threat_level = "high"
        elif scan_result == "suspicious":
            detection_text = f"Suspicious file detected by {detection_count}/{total_engines} engines"
            threat_level = "medium"
        elif scan_result == "clean":
            detection_text = f"Clean file (0/{total_engines} detections)"
            threat_level = "low"
        elif scan_result == "unknown":
            detection_text = "File not found in VirusTotal database"
            threat_level = "unknown"
        else:  # error
            detection_text = f"Error scanning file: {result.get('error', 'Unknown error')}"
            threat_level = "unknown"
        
        # Add cache status
        if result.get('from_cache', False):
            detection_text += " (cached result)"
        
        return detection_text, is_threat, threat_level

# Simple test function
if __name__ == "__main__":
    scanner = VirusTotalScanner()
    
    # Test with a known malicious hash
    test_hash = "84c82835a5d21bbcf75a61706d8ab549238b33cd28b087e4a9794395d300f991"
    result = scanner.scan_file_hash(test_hash)
    print(f"Test hash: {test_hash}")
    detection_text, is_threat, threat_level = scanner.get_detection_info(result)
    print(f"Detection: {detection_text}")
    print(f"Is threat: {is_threat}")
    print(f"Threat level: {threat_level}")
    
    # Test with the same hash again (should use cache)
    print("\nTesting cache...")
    result2 = scanner.scan_file_hash(test_hash)
    detection_text2, is_threat2, threat_level2 = scanner.get_detection_info(result2)
    print(f"Detection (cached): {detection_text2}")