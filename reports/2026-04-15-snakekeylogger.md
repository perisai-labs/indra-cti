# SnakeKeylogger Intelligence Report

**Date:** 2026-04-15  
**Report Type:** Malware Analysis  
**SHA256:** 79e6b2c3d010500745a6a5a68b89b3453e16eca3ff359477718453301c17b034  
**Threat Level:** High

## Executive Summary

SnakeKeylogger is a Windows keylogger malware that captures keyboard input using standard Windows API hooking techniques. The malware is identified by its distinctive "SnakeKeylogger" string and targets sensitive information capture.

## Technical Analysis

### File Characteristics
- **Type:** PE32 executable for MS Windows (x86)
- **File Size:** 665,088 bytes
- **Origin:** Switzerland (CH)

### Core Functionality
- **Keyboard Capture:** Uses `SetWindowsHookEx` to install keyboard hooks
- **Input Processing:** Monitors `GetAsyncKeyState` and `GetKeyState` for keystroke detection
- **Data Storage:** Implements file mapping and file operations for log storage
- **Persistence:** Uses `RegisterHotKey` for hotkey management

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|-------------|----------------|--------|
| T1056.001 | Input Capture: Keylogging | Collection |
| T1056.004 | Input Capture: UI Input | Collection |
| T1082 | System Information Discovery | Discovery |
| T1129 | Shared Modules | Defense Evasion |

## IOCs

### Hash Values
- **SHA256:** 79e6b2c3d010500745a6a5a68b89b3453e16eca3ff359477718453301c17b034

### File IOCs
- **Filename:** 79e6b2c3d010500745a6a5a68b89b3453e16eca3ff359477718453301c17b034.exe

## Detection Rules

### YARA Rule
```yara
rule SnakeKeylogger {
    meta:
        author = "Xhavero - Peris.ai Threat Research"
        date = "2026-04-15"
        description = "Windows Snake Keylogger Malware"
        reference = "MalwareBazaar: 79e6b2c3d010500745a6a5a68b89b3453e16eca3ff359477718453301c17b034"
        severity = "high"
        
    strings:
        $s1 = "SnakeKeylogger" nocase
        $s2 = "keylogger" nocase
        $s3 = "keyboard" nocase
        $s4 = "SetWindowsHookEx" nocase
        $s5 = "CallNextHookEx" nocase
        $s6 = "GetAsyncKeyState" nocase
        $s7 = "GetKeyState" nocase
        $s8 = "RegisterHotKey" nocase
        $s9 = "UnregisterHotKey" nocase
        $s10 = "CreateFileMapping" nocase
        $s11 = "MapViewOfFile" nocase
        $s12 = "Snake" nocase
        
    condition:
        5 of them and filesize < 1MB
}
```

## Recommendations

### Immediate Actions
1. Block the SHA256 hash at network endpoints
2. Monitor for processes using keyboard-related APIs
3. Audit systems for unexplained logging activity
4. Update endpoint protection signatures

### Long-term Mitigations
1. Implement behavioral detection for hook-based keyloggers
2. Monitor for unusual process injection patterns
3. Regular security awareness training
4. Implement application whitelisting policies

## References
- MalwareBazaar: 79e6b2c3d010500745a6a5a68b89b3453e16eca3ff359477718453301c17b034
- Analysis by: Xhavero - Peris.ai Threat Research Team

---
*This report contains public threat intelligence and does not contain internal sensitive information.*