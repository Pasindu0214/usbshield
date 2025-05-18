rule Test_Detection_Rule {
    meta:
        description = "Test rule to detect specific content in yaratest.txt"
        author = "USBShield Team"
        severity = "info"
    
    strings:
        $test_string = "YARA_TEST_STRING_123" 
        $password = "password=admin123"
        $url = "malicious-example-domain.com"
    
    condition:
        any of them
}

rule Test_TextFile_Pattern {
    meta:
        description = "Simple test rule that matches any text file containing 'test'"
        severity = "info"
    
    strings:
        $test_word = "test" nocase
    
    condition:
        $test_word
}

rule Generic_Ransomware_Detection {
    meta:
        description = "Detects common ransomware characteristics"
        author = "Security Analyst"
        severity = "High"
        date = "2025-05-13"
        
    strings:
        // Ransom note patterns
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase wide ascii
        $ransom_note2 = "pay" nocase wide ascii
        $ransom_note3 = "bitcoin" nocase wide ascii
        $ransom_note4 = "decrypt" nocase wide ascii
        $ransom_note5 = "all your files" nocase wide ascii
        
        // Common file extensions targeted for encryption
        $target_ext1 = ".doc" nocase wide ascii
        $target_ext2 = ".pdf" nocase wide ascii
        $target_ext3 = ".jpg" nocase wide ascii
        $target_ext4 = ".xls" nocase wide ascii
        
        // Common encryption-related strings
        $crypto1 = "AES" nocase wide ascii
        $crypto2 = "RSA" nocase wide ascii
        $crypto3 = "crypto" nocase wide ascii
        
        // Common ransomware file extensions
        $ransom_ext1 = ".locked" nocase wide ascii
        $ransom_ext2 = ".encrypted" nocase wide ascii
        $ransom_ext3 = ".crypt" nocase wide ascii
        $ransom_ext4 = ".crypted" nocase wide ascii
        
        // Shadow copy deletion commands
        $shadow_delete1 = "vssadmin delete shadows" nocase wide ascii
        $shadow_delete2 = "wmic shadowcopy delete" nocase wide ascii
        
        // Common sandbox evasion techniques
        $sandbox1 = { 8D ?? ?? ?? 8B ?? ?? 89 ?? ?? 3D 00 01 00 00 }  // Memory size check
        
        // Suspicious API calls (hex pattern)
        $api_pattern = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 }  // Common API call pattern
        
    condition:
        // Executable file check
        uint16(0) == 0x5A4D and  // MZ header
        
        // Detection logic combining multiple indicators
        (
            // Ransom note indicators
            (2 of ($ransom_note*)) and
            
            // File operation indicators
            (
                (any of ($target_ext*)) or
                (any of ($ransom_ext*))
            ) and
            
            // Encryption indicators
            (any of ($crypto*)) and
            
            // Either shadow copy deletion OR suspicious API pattern
            (
                any of ($shadow_delete*) or
                $api_pattern or
                $sandbox1
            )
        )
}