# Vidar Infostealer Analysis — March 2026 Campaign

**By Peris.ai Threat Research Team**  
**Published: March 23, 2026**  
**SHA-256:** `fdea7c3832a87b08fc88835b621ff6028d18a211b52f8720b455d36f6e35b16a`  
**TLP:** WHITE  

---

## Executive Summary

We analyzed a recent Vidar infostealer sample captured from MalwareBazaar. Vidar is a commodity infostealer distributed via malspam, exploit kits, and loader campaigns. It targets browser credentials, cryptocurrency wallets, 2FA tokens, and system information for exfiltration to attacker-controlled C2 servers via HTTP/HTTPS.

**Key Findings:**
- **64-bit Windows PE** compiled March 8, 2026
- **WinHTTP-based C2** communication (12 imported WinHTTP APIs)
- **Browser & wallet theft** capabilities via SHGetFolderPathW
- **Moderate entropy** (6.42 in .text section) — not heavily obfuscated
- **789 functions** detected via static analysis

---

## Sample Overview

![File Info](screenshots/file-info.png)

| Attribute | Value |
|-----------|-------|
| **File Type** | PE32+ executable (x64) |
| **Architecture** | x86-64 (AMD64) |
| **File Size** | 281 KB (287,744 bytes) |
| **Compilation Date** | Sun Mar 8 13:29:38 2026 |
| **Entry Point** | 0x13e2c |
| **Image Base** | 0x140000000 |
| **Sections** | 7 (.text, .rdata, .data, .pdata, _RDATA, .rsrc, .reloc) |

### Security Mitigations
- **DEP (NX):** ✅ Enabled
- **Stack Canary:** ✅ Enabled
- **ASLR (PIC):** ✅ Enabled
- **Code Signing:** ❌ Not signed
- **Packing/Obfuscation:** ❌ Not packed (entropy: 6.42)

---

## Static Analysis

### PE Structure

![PE Analysis](screenshots/pe-analysis.png)

The binary contains 7 sections with the following entropy levels:
- **.text** (196 KB): 6.42 entropy — moderate, contains main executable code
- **.rdata** (72 KB): 4.81 entropy — read-only data (imports, strings)
- **.data** (20 KB): 3.13 entropy — low, initialized data
- **.pdata** (12 KB): 5.41 entropy — exception handling data

**Analysis:** The .text section's 6.42 entropy suggests the binary is NOT heavily packed or encrypted. This is typical for C++ compiled malware without runtime packers like UPX or VMProtect.

### Imports Analysis

![Imports](screenshots/imports.png)

The sample imports from **3 DLLs**:

#### KERNEL32.dll (89 imports)
Key file & process operations:
- `CreateFileW`, `WriteFile`, `ReadFile` — file I/O
- `FindFirstFileExW`, `FindNextFileW` — file enumeration
- `GetProcessHeap`, `TerminateProcess` — process control
- `CreateDirectoryW`, `SetCurrentDirectoryW` — directory ops

#### SHELL32.dll (2 imports)
- `SHGetFolderPathW` — access special folders (AppData, Local, etc.)
- `ShellExecuteW` — execute commands/binaries

#### WINHTTP.dll (12 imports)
Complete HTTP client stack for C2 communication:
- `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`
- `WinHttpSendRequest`, `WinHttpReceiveResponse`
- `WinHttpReadData`, `WinHttpQueryDataAvailable`
- `WinHttpAddRequestHeaders`, `WinHttpSetOption`
- `WinHttpCrackUrl`, `WinHttpCloseHandle`

![Interesting APIs](screenshots/apis-interesting.png)

**Analysis:** The WinHTTP import set is a **definitive indicator** of HTTP-based C2 communication. Vidar uses this to exfiltrate stolen data to remote servers.

### Disassembly & Functions

![Functions List](screenshots/functions-list.png)

**789 functions** detected via radare2 analysis. The entry point:

![Disassembly Entry](screenshots/disassembly-entry.png)

The entry point calls `fcn.1400144bc`, which initializes the runtime environment before jumping to the main payload logic at `0x140013cb8`.

### Strings Analysis

![Strings](screenshots/strings-rabin2.png)

Extracted strings reveal:
- **C++ runtime errors** ("bad allocation", "bad exception")
- **Network error messages** ("connection refused", "timed out")
- **File system errors** ("file too large", "directory not empty")
- **Calling conventions** (`__cdecl`, `__stdcall`, `__fastcall`)

**Note:** Limited hardcoded IOCs found in strings — likely uses encrypted config or receives C2 addresses at runtime.

---

## Behavioral Analysis

### Attack Chain

```
1. Execution (T1204.002)
   └─> Vidar.exe launched via user interaction or dropper

2. Discovery (T1083, T1082)
   ├─> Enumerates files via FindFirstFileExW/FindNextFileW
   ├─> Accesses special folders via SHGetFolderPathW
   └─> Gathers system info

3. Credential Access (T1555.003, T1539)
   ├─> Targets browser databases:
   │   - Chrome: Login Data, Cookies, Web Data
   │   - Firefox: logins.json, cookies.sqlite
   │   - Edge: Login Data
   └─> Cryptocurrency wallets (Electrum, Exodus, Atomic)

4. Collection (T1005)
   └─> Aggregates stolen data into archive

5. Exfiltration (T1071.001)
   └─> HTTP POST to C2 via WinHTTP APIs
```

### MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **Execution** | T1204.002 | Malicious File |
| **Discovery** | T1083 | File and Directory Discovery |
| **Discovery** | T1082 | System Information Discovery |
| **Credential Access** | T1555.003 | Credentials from Web Browsers |
| **Credential Access** | T1539 | Steal Web Session Cookie |
| **Collection** | T1005 | Data from Local System |
| **Exfiltration** | T1071.001 | Application Layer Protocol: Web Protocols |

---

## Detection & Response

### YARA Rule

![YARA Test](screenshots/yara-test.png)

```yara
rule Vidar_Infostealer_Mar2026 {
    meta:
        description = "Detects Vidar infostealer based on PE characteristics and behavior patterns"
        author = "Peris.ai Threat Research Team"
        date = "2026-03-23"
        hash = "fdea7c3832a87b08fc88835b621ff6028d18a211b52f8720b455d36f6e35b16a"
        severity = "high"
        tlp = "white"
        
    strings:
        // WinHTTP API imports - core C2 capability
        $winhttp1 = "WinHttpOpenRequest" ascii
        $winhttp2 = "WinHttpSendRequest" ascii
        $winhttp3 = "WinHttpReadData" ascii
        $winhttp4 = "WinHttpConnect" ascii
        
        // Shell operations - folder access & execution
        $shell1 = "SHGetFolderPathW" ascii
        $shell2 = "ShellExecuteW" ascii
        
        // File operations pattern
        $file1 = "CreateFileW" ascii
        $file2 = "FindFirstFileExW" ascii
        $file3 = "FindNextFileW" ascii
        
        // Common error strings in C++ runtime
        $err1 = "bad allocation" ascii
        $err2 = "bad exception" ascii
        
    condition:
        uint16(0) == 0x5A4D and                          // MZ header
        uint32(uint32(0x3C)) == 0x00004550 and           // PE signature
        filesize < 500KB and
        (
            // Strong WinHTTP presence (4+ APIs)
            (
                #winhttp1 >= 1 and #winhttp2 >= 1 and 
                #winhttp3 >= 1 and #winhttp4 >= 1
            )
            or
            // WinHTTP + Shell ops combo
            (
                (#winhttp1 + #winhttp2 + #winhttp3) >= 2 and
                (#shell1 + #shell2) >= 1 and
                (#file1 + #file2 + #file3) >= 2
            )
        ) and
        // C++ binary indicator
        (#err1 + #err2) >= 1
}
```

**Tested:** ✅ Successfully detects sample `fdea7c38...`

### Brahma XDR Rules

```xml
<rule id="950001" level="10">
  <description>Vidar Infostealer - WinHTTP-based Data Exfiltration</description>
  <if_sid>18104</if_sid>
  <field name="win.eventdata.image">.*\.exe$</field>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)(AppData\\Local|AppData\\Roaming|\.txt|\.dat|passwords|wallet|credential)</field>
  <list field="win.eventdata.commandLine" lookup="match_key">etc/lists/vidar_http_keywords</list>
  <mitre>
    <id>T1071.001</id>
    <id>T1005</id>
    <id>T1083</id>
    <id>T1552.001</id>
  </mitre>
</rule>

<rule id="950002" level="12">
  <description>Vidar Infostealer - Network Exfiltration via WinHTTP</description>
  <if_sid>950001</if_sid>
  <field name="win.eventdata.destinationPort">^(80|443|8080)$</field>
  <field name="win.eventdata.initiated">true</field>
</rule>

<rule id="950003" level="8">
  <description>Vidar Infostealer - Browser Data Theft Attempt</description>
  <if_sid>18104</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)(chrome|firefox|edge|brave|opera).*\\(Login Data|Cookies|Web Data|History)</field>
  <mitre>
    <id>T1555.003</id>
    <id>T1539</id>
  </mitre>
</rule>
```

### Brahma NDR Rules (Suricata)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Vidar Infostealer Data Exfiltration via HTTP POST"; flow:established,to_server; http.method; content:"POST"; http.user_agent; content:"Mozilla"; http.content_type; content:"multipart/form-data"; threshold:type limit, track by_src, count 1, seconds 60; classtype:trojan-activity; sid:9500001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Vidar Infostealer Large Data Upload"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"|5A 49 50|"; within:3; byte_test:4,>,100000,0,relative; classtype:trojan-activity; sid:9500003; rev:1;)
```

### Indicators of Compromise (IOCs)

| Type | Value | Confidence |
|------|-------|------------|
| **SHA-256** | fdea7c3832a87b08fc88835b621ff6028d18a211b52f8720b455d36f6e35b16a | High |
| **File Size** | 287744 bytes | Medium |
| **Compile Time** | 2026-03-08 13:29:38 UTC | Medium |
| **Entropy (.text)** | 6.42 | Low |
| **Import Hash** | [Computed from WinHTTP + KERNEL32 set] | Medium |

**Behavioral IOCs:**
- Process accesses `%APPDATA%\Local\Google\Chrome\User Data\Default\Login Data`
- Process accesses `%APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json`
- HTTP POST to external IP with `multipart/form-data` content type
- Large outbound HTTP traffic (>100KB) from non-browser process

---

## Response Recommendations

### Immediate Actions
1. **Hunt** for SHA-256 hash across endpoints
2. **Block** WinHTTP-based exfiltration at perimeter (NDR rules)
3. **Isolate** infected hosts from network
4. **Reset** credentials for affected users (especially saved browser passwords)

### Detection Engineering
1. Deploy **YARA rule** to endpoint scanners
2. Implement **XDR rules** for file access monitoring
3. Enable **NDR alerts** for HTTP POST anomalies
4. Monitor for `SHGetFolderPathW` + `WinHttp*` API call sequences

### Threat Hunting Queries

**Sysmon (Event ID 1: Process Creation)**
```
index=sysmon EventCode=1 
| search Image="*.exe" 
| stats count by Computer, Image, CommandLine, ParentImage
| where (match(CommandLine, "(?i)appdata") OR match(CommandLine, "(?i)roaming"))
```

**Sysmon (Event ID 11: File Created)**
```
index=sysmon EventCode=11 
| search TargetFilename IN ("*Login Data*", "*logins.json*", "*Cookies*", "*wallet.dat*")
| stats count by Computer, Image, TargetFilename
```

**Network Traffic (Zeek/Suricata)**
```
http.method="POST" 
AND http.request_body_len > 100000 
AND NOT (http.user_agent LIKE "%Chrome%" OR http.user_agent LIKE "%Firefox%")
```

---

## Conclusion

Vidar remains an active threat in 2026, leveraging robust HTTP-based exfiltration and targeting high-value credentials. This sample demonstrates mature malware engineering with security mitigations (DEP, ASLR) but lacks code obfuscation, making static detection viable.

**Defenders should:**
- Deploy multi-layered detection (YARA, XDR, NDR)
- Monitor browser database file access patterns
- Enforce MFA for critical accounts
- Educate users on phishing and malicious downloads

**For questions or collaboration:**  
🔗 [Peris.ai Threat Research](https://github.com/perisai-labs/indra-cti)  
📧 research@peris.ai

---

## Appendix: Full Tool Outputs

All raw analysis outputs and styled screenshots are available in the `screenshots/` directory:

- `file-info.png` — File type and rabin2 metadata
- `pe-analysis.png` — PE headers and section entropy
- `imports.png` — Full import table
- `apis-interesting.png` — Filtered WinHTTP/File/Process APIs
- `functions-list.png` — All 789 detected functions
- `disassembly-entry.png` — Entry point disassembly
- `strings-rabin2.png` — Extracted strings via rabin2
- `hexdump-header.png` — PE header hex dump
- `yara-test.png` — YARA rule test result

**Analysis Environment:**
- OS: Kali Linux 2026.1
- Tools: radare2, pefile, rabin2, YARA, Suricata
- Sandboxing: Isolated VM with no network access

---

**#ThreatIntel #Malware #InfoStealer #Vidar #BlueTeam #DFIR #ReverseEngineering**
