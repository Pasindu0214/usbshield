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