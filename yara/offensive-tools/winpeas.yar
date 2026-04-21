rule WinPEAS_PrivEsc_Tool {
    meta:
        description = "Detects winPEAS.exe - Windows Privilege Escalation Awesome Scripts"
        author = "Peris.ai Threat Research Team"
        date = "2025-03-21"
        hash = "93a2fe494017319e1b6ecd78a28db3d349f762e71e59a1a81bae5aea361f358b"
        severity = "high"
        category = "offensive-tool"
        reference = "https://github.com/carlospolop/PEASS-ng"
        
    strings:
        // PDB path signature
        $pdb = "PEASS-ng\\winPEAS\\winPEASexe\\winPEAS\\obj\\x64\\Release\\winPEAS.pdb" wide ascii
        
        // Unique regex patterns embedded in config
        $regex1 = "regular_expresions:" ascii
        $regex2 = "# Hashes passwords" ascii
        $regex3 = "sha512crypt" ascii
        
        // Configuration markers
        $config1 = "LINPEAS SPECIFICATIONS" ascii
        $config2 = "peass{CHECKS}" ascii
        $config3 = "peass{REGEXES}" ascii
        $config4 = "peass{VARIABLES}" ascii
        
        // Service checking strings
        $svc1 = "PostgreSQL" ascii
        $svc2 = "Elasticsearch" ascii
        $svc3 = "Apache-Nginx" ascii
        $svc4 = "Kubernetes" ascii
        
        // API key detection patterns
        $api1 = "AWS_ACCESS_KEY_ID" ascii nocase
        $api2 = "GITHUB_TOKEN" ascii nocase
        $api3 = "SLACK_TOKEN" ascii nocase
        
    condition:
        uint16(0) == 0x5A4D and // PE signature
        filesize > 5MB and filesize < 15MB and
        (
            $pdb or // Strong indicator
            (3 of ($regex*)) or
            (3 of ($config*)) or
            (4 of ($svc*) and 2 of ($api*))
        )
}

rule WinPEAS_Memory_Pattern {
    meta:
        description = "Detects winPEAS execution patterns in memory"
        author = "Peris.ai Threat Research Team"
        date = "2025-03-21"
        severity = "high"
        
    strings:
        $mem1 = "winPEAS" ascii nocase
        $mem2 = "PEASS-ng" ascii
        $mem3 = "Privilege Escalation Awesome Scripts" ascii
        $mem4 = "peass{" ascii
        $mem5 = "CorExitProcess" wide
        
    condition:
        3 of them
}
