rule Ransomware_0APT_Feb2026 {
    meta:
        description = "Detects 0APT ransomware (Rust-compiled PE32) - Feb 2026 variant"
        author = "Peris.ai Threat Research Team"
        date = "2026-02-19"
        hash = "b2f915cbf1a2b6879d278f613b13d790de9a460759142f30457c3238e598e077"
        severity = "critical"
        malware_family = "0APT"
        
    strings:
        // Ransom note marker
        $note1 = "::: 0APT LOCKER :::" ascii
        $note2 = "!!! ALL YOUR FILES ARE ENCRYPTED !!!" ascii
        
        // C2 infrastructure
        $c2 = "oaptxiyisljt2kv3we2we34kuudmqda7f2geffoylzpeo7ourhtz4dad.onion" ascii
        
        // Victim ID format
        $victim_id = /[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-0APT-KEY/ ascii
        
        // Readme file
        $readme = "README0apt.txt" ascii
        
        // File extension
        $ext = ".0apt" ascii
        
        // Rust source path
        $rust_src = "src/bin/encrypt.rs" ascii
        
        // Config structure
        $config = "config2.txt" ascii
        
        // Encryption references
        $crypto1 = "AES-256 & RSA-2048" ascii
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        filesize < 10MB and
        (
            // Strong detection: ransom note + C2 + victim ID
            ($note1 and $c2 and $victim_id) or
            
            // Alternative: multiple indicators
            (4 of ($note*, $readme, $ext, $crypto1, $rust_src, $config))
        )
}
