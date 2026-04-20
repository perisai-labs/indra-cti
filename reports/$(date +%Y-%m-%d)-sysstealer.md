# SysStealer Malware Analysis Report
**Date**: April 19, 2026  
**SHA256**: 98ed48c1f09fbcbe4f484327901f4852e18ace0dbf44b926336544cd4167c5c5

## Executive Summary

A sophisticated Windows credential stealer masquerading as a system optimization tool has been analyzed. The malware extracts sensitive data from multiple browsers, encrypts it, and exfiltrates the information to a Telegram bot API endpoint.

## Technical Analysis

### File Characteristics
- **File Type**: PE32+ executable for MS Windows 5.02 (GUI)
- **Architecture**: x86-64
- **File Size**: 199,101 bytes
- **Compilation Date**: April 17, 2026

### Malware Functionality

The malware implements several key functions:

1. **ExtractUserData**: Main data extraction orchestrator
2. **ProcessAndSendData**: Data packaging and exfiltration
3. **CollectSystemInfo**: System fingerprinting
4. **DecryptBrowserPassword**: Credential decryption
5. **HuntCredentials**/`HuntCookies`: Browser data discovery

### Browser Targets
- Google Chrome (`%LOCALAPPDATA%\Google\Chrome\User Data`)
- Microsoft Edge (`%LOCALAPPDATA%\Microsoft\Edge\User Data`)
- Brave Browser (`%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`)
- Mozilla Firefox (`%APPDATA%\Mozilla\Firefox\Profiles`)

### Data Exfiltration
The malware uses Telegram's Bot API for data exfiltration:
- **Bot Token**: 8585418158:AAHA7g-QZWdChwoMl9OBdec5VABL0mI-5b0
- **Target**: api.telegram.org
- **Method**: HTTP POST with ZIP attachments

### MITRE ATT&CK Mapping
- **T1555.004**: Steal web browser credentials
- **T1005**: Browser data theft
- **C2.009**: Webhook
- **T1027**: Obfuscated Files or Information
- **T1082**: System Information Discovery

## IOCs

### Hash
- **SHA256**: 98ed48c1f09fbcbe4f484327901f4852e18ace0dbf44b926336544cd4167c5c5

### Network IOCs
- **C2 Domain**: api.telegram.org
- **Bot Token**: 8585418158:AAHA7g-QZWdChwoMl9OBdec5VABL0mI-5b0

### File Patterns
- **File Names**: System.txt, *Report.zip

## YARA Detection Rule

```yar
rule SysStealer_Malware {
    meta:
        description = "System information stealer with Telegram exfiltration"
        author = "Peris.ai Threat Research Team"
        date = "2026-04-19"
        hash = "98ed48c1f09fbcbe4f484327901f4852e18ace0dbf44b926336544cd4167c5c5"
        severity = "High"
        
    strings:
        $telegram_api = "api.telegram.org" ascii
        $telegram_bot_token = "8585418158:AAHA7g-QZWdChwoMl9OBdec5VABL0mI-5b0" ascii
        $chrome_path = "%LOCALAPPDATA%\\Google\\Chrome\\User Data" wide
        $edge_path = "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data" wide
        $brave_path = "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data" wide
        $firefox_path = "%APPDATA%\\Mozilla\\Firefox\\Profiles" wide
        $extract_userdata = "ExtractUserData" ascii
        $collect_system_info = "CollectSystemInfo" ascii
        $process_and_send = "ProcessAndSendData" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        6 of them and
        filesize < 500KB
}
```

## Detection Recommendations

### Network Detection
- Monitor for outbound connections to api.telegram.org
- Detect HTTP POST requests with "bot" in the URI
- Monitor for multipart/form-data requests with document attachments

### Host Detection
- Monitor processes accessing browser profile directories
- Detect creation of files with "Report.zip" naming pattern
- Monitor for execution of suspicious strings identified in analysis

## Analysis Notes

The malware represents a significant threat to user data security, particularly affecting users of multiple browsers. The sophisticated data collection and exfiltration methods highlight the importance of comprehensive security monitoring.

---

**Analysis Date**: April 19, 2026  
**Tools Used**: radare2, binwalk, file, strings, xxd, YARA