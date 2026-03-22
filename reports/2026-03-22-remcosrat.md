# Malware Analysis: RemcosRAT — Deep Dive into Commercial RAT Capabilities

**Date:** March 22, 2026  
**Author:** Peris.ai Threat Research Team  
**Sample Hash:** `1e3d5fe030122186af6224340deb2440165cf36a932b59ef03d8fc2ca57495b3`  
**Malware Family:** RemcosRAT  
**Severity:** High

---

## Executive Summary

RemcosRAT (Remote Control & Surveillance) is a commercial remote access trojan marketed as a legitimate administrative tool but widely abused by threat actors for cyber espionage, credential theft, and surveillance operations. This analysis examines a recent sample observed in March 2026, revealing sophisticated capabilities including UAC bypass, process injection, keylogging, clipboard monitoring, and geolocation tracking.

**Key Findings:**
- ✅ UAC bypass via registry modification
- ✅ Multi-stage persistence mechanisms
- ✅ Process injection targeting browsers (Chrome, Brave)
- ✅ Keylogging & clipboard stealing capabilities
- ✅ Screen capture functionality (BitBlt API)
- ✅ Geolocation beacon to geoplugin.net

---

## Sample Metadata

![File Information](screenshots/file-info.png)

**File Details:**
- **Type:** PE32 Windows executable
- **Size:** 494 KB (505,856 bytes)
- **Architecture:** Intel 80386
- **Origin:** Netherlands (NL)
- **First Seen:** March 2026

---

## Static Analysis

### Section Analysis

![Sections & Entropy](screenshots/sections-entropy.png)

The binary contains standard PE sections with notable high-entropy regions suggesting packed or encrypted payloads. The `.rdata` section contains extensive string artifacts revealing operational capabilities.

### Entropy Analysis

![Entropy Graph](screenshots/entropy.png)

Binwalk entropy analysis shows multiple high-entropy regions (>0.9) indicating compression or encryption. This is typical of modern malware attempting to evade signature-based detection.

### Imported Functions

![Windows API Imports](screenshots/imports.png)

**Critical API Imports:**
- **Process Injection:** `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`
- **Keylogging:** `SetWindowsHookExA`, `GetAsyncKeyState`
- **Clipboard Theft:** `GetClipboardData`
- **Screen Capture:** `BitBlt` (GDI32)
- **Persistence:** Registry manipulation APIs

These imports confirm the malware's RAT capabilities.

### String Analysis

![Extracted Strings](screenshots/strings.png)

Over 2,600 strings extracted, including:

**UAC Bypass Command:**
```
/k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
```

**Persistence Locations:**
```
Software\Microsoft\Windows\CurrentVersion\Run\
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\
```

**Injection Targets:**
```
\Google\Chrome\Application\Chrome.exe
\BraveSoftware\Brave-Browser\Application\brave.exe
explorer.exe
```

**Network Indicator:**
```
http://geoplugin.net/json.gp
```

---

## Behavioral Analysis

### 1. UAC Bypass (MITRE ATT&CK: T1548.002)

RemcosRAT attempts to disable User Account Control by modifying the `EnableLUA` registry value:

```cmd
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
```

This grants the malware elevated privileges without triggering UAC prompts.

### 2. Persistence (MITRE ATT&CK: T1547.001)

Multiple persistence mechanisms identified:
- Registry Run keys (User & System)
- Registry Policies\Explorer\Run keys
- Startup folder modifications

The malware persists as `rmclient.exe`.

### 3. Process Injection (MITRE ATT&CK: T1055)

![Disassembly - Entry Point](screenshots/disassembly-entry.png)

The malware injects code into legitimate processes to evade detection:
- **Chrome.exe** — browser process injection for credential theft
- **brave.exe** — alternative browser target
- **explorer.exe** — system-level persistence

### 4. Credential & Data Theft

**Keylogging (T1056.001):**
- Uses `SetWindowsHookExA` to intercept keystrokes
- Captures credentials, messages, and sensitive input

**Clipboard Monitoring (T1115):**
- `GetClipboardData` API monitors clipboard for cryptocurrency wallets, passwords

**Screen Capture (T1113):**
- `BitBlt` API captures screenshots for surveillance

### 5. Geolocation & Reconnaissance (T1016.001)

![Network IOCs](screenshots/network-iocs.png)

The malware beacons to:
```
http://geoplugin.net/json.gp
```

This geolocation service identifies the victim's:
- IP address
- Country/city
- ISP information
- Timezone

---

## Reverse Engineering Insights

### Function Analysis

![Functions List](screenshots/functions-list.png)

Radare2 identified **2,389 functions** after auto-analysis. Key functions include:

**Main Function Disassembly:**

![Main Function](screenshots/disassembly-main.png)

The main function orchestrates:
1. Environment checks (VM detection)
2. Privilege escalation
3. Payload decryption
4. Process injection
5. C2 communication initialization

### PE Header Analysis

![Hexdump - PE Header](screenshots/hexdump-header.png)

The PE header shows:
- **MZ signature** (0x5A4D) at offset 0x00
- **PE signature** at offset 0xE8
- Compilation timestamp embedded
- Import table & resource directories present

---

## Detection & Prevention

### YARA Rule

![YARA Detection Test](screenshots/yara-test.png)

```yara
rule RemcosRAT_March2026 {
    meta:
        author = "Peris.ai Threat Research Team"
        date = "2026-03-22"
        description = "Detects RemcosRAT malware based on unique strings and behavior patterns"
        hash = "1e3d5fe030122186af6224340deb2440165cf36a932b59ef03d8fc2ca57495b3"
        severity = "high"
        mitre_attack = "T1055,T1056.001,T1113,T1115,T1548.002"
        
    strings:
        $s1 = "rmclient.exe" ascii
        $s2 = "http://geoplugin.net/json.gp" ascii
        $s3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA" ascii
        
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        
        $api1 = "GetClipboardData"
        $api2 = "SetWindowsHookExA"
        $api3 = "WriteProcessMemory"
        $api4 = "VirtualAlloc"
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (2 of ($s*) and 1 of ($p*)) or
        ($s1 and 3 of ($api*))
}
```

### Brahma XDR Rules

**Rule 900422: UAC Bypass Detection**
```xml
<rule id="900422" level="12">
  <description>RemcosRAT: UAC Bypass via Registry Modification</description>
  <mitre><id>T1548.002</id></mitre>
  <field name="win.eventdata.commandLine" type="pcre2">reg\.exe.*EnableLUA.*REG_DWORD.*0</field>
</rule>
```

**Rule 900423: Process Injection**
```xml
<rule id="900423" level="13">
  <description>RemcosRAT: Process Injection Indicators</description>
  <mitre><id>T1055</id></mitre>
  <field name="win.eventdata.image" type="pcre2">\\(Chrome|brave|explorer)\.exe$</field>
  <field name="win.eventdata.targetImage" type="pcre2">rmclient\.exe</field>
</rule>
```

### Brahma NDR Rule

```
alert http any any -> any any (
  msg:"MALWARE RemcosRAT Geolocation Beacon"; 
  flow:established,to_server; 
  http.host; content:"geoplugin.net"; 
  http.uri; content:"/json.gp"; 
  sid:3900422; 
  metadata:mitre_technique_id T1016;
)
```

---

## Indicators of Compromise (IOCs)

### File Hashes

| Hash Type | Value |
|-----------|-------|
| **SHA256** | `1e3d5fe030122186af6224340deb2440165cf36a932b59ef03d8fc2ca57495b3` |
| **Filename** | `rmclient.exe`, `sc.exe`, `fsutil.exe` |

### Network Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| **Domain** | `geoplugin.net` | Geolocation service |
| **URL** | `http://geoplugin.net/json.gp` | IP geolocation API |

### Registry Keys

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System [EnableLUA]
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\
```

### Suspicious Processes

- `rmclient.exe` — Main RAT executable
- `reg.exe` — UAC bypass execution
- `cmd.exe` — Command execution
- Injection into: `chrome.exe`, `brave.exe`, `explorer.exe`

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
| **T1548.002** | Bypass UAC: Disable EnableLUA | Registry modification command |
| **T1547.001** | Boot/Logon: Registry Run Keys | Persistence via Run keys |
| **T1055** | Process Injection | API imports + targeted processes |
| **T1056.001** | Input Capture: Keylogging | SetWindowsHookExA import |
| **T1113** | Screen Capture | BitBlt API usage |
| **T1115** | Clipboard Data | GetClipboardData import |
| **T1016.001** | System Network Config Discovery | Geolocation beacon |

---

## Recommendations

### For SOC Teams

1. **Deploy YARA/XDR/NDR rules** provided above
2. **Monitor for UAC bypass attempts** (reg.exe + EnableLUA modifications)
3. **Alert on geoplugin.net traffic** from endpoints
4. **Hunt for rmclient.exe processes** and associated filenames
5. **Review registry Run keys** for suspicious entries

### For Endpoint Protection

1. **Enable tamper protection** on security software
2. **Restrict registry modifications** requiring admin rights
3. **Monitor API calls**: `VirtualAlloc`, `WriteProcessMemory`, `SetWindowsHookExA`
4. **Application whitelisting** to prevent unauthorized executables
5. **Behavioral detection** for process injection patterns

### For Network Security

1. **Block geoplugin.net** on perimeter firewalls (unless required)
2. **Monitor HTTP traffic** from unexpected processes
3. **Inspect TLS/SSL traffic** for C2 communication
4. **Deploy NDR rules** for RemcosRAT traffic patterns

---

## Conclusion

RemcosRAT remains a potent threat in 2026, combining commercial-grade capabilities with widespread availability on underground markets. This analysis demonstrates the malware's sophisticated evasion techniques, including UAC bypass, multi-stage persistence, and comprehensive surveillance features.

Organizations should implement layered defenses including:
- **Endpoint detection & response (EDR)** with behavioral analytics
- **Network detection & response (NDR)** for C2 communication
- **YARA-based file scanning** at email gateways and endpoints
- **User awareness training** on phishing and social engineering

The detection rules and IOCs provided enable immediate threat hunting and proactive defense against RemcosRAT campaigns.

---

**References:**
- MITRE ATT&CK Framework: https://attack.mitre.org/
- MalwareBazaar: https://bazaar.abuse.ch/
- RemcosRAT Analysis (Historical): Multiple public reports

**Credits:**  
*By Peris.ai Threat Research Team*

---

**Tags:** #RemcosRAT #MalwareAnalysis #ThreatHunting #ReverseEngineering #DFIR #CyberSecurity #RAT #ThreatIntelligence
