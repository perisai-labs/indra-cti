# SantaStealer Infostealer — Amadey Botnet Payload

**Classification:** TLP:WHITE  
**Severity:** HIGH  
**Malware Family:** SantaStealer  
**Campaign:** Amadey Botnet Distribution  
**Date Analyzed:** 2026-02-23  
**Sample SHA-256:** `89ae9a2ad575daa389d6340696b23ca795101c72e9326cd295b8856a6b967d38`

---

## Executive Summary

**SantaStealer** is a VMProtect-packed information stealer distributed as a secondary payload by the **Amadey botnet** infrastructure. First observed in the wild on **February 22, 2026**, this malware targets a comprehensive range of sensitive data including browser credentials, cryptocurrency wallets, email clients, and Windows Credential Manager stores.

**Key Findings:**
- **Threat Level:** HIGH — Active distribution via Amadey botnet
- **Detection Rate:** 17/67 (25%) on VirusTotal — low due to VMProtect packing
- **Primary Capabilities:** Credential theft, browser data exfiltration, cryptocurrency wallet harvesting
- **Distribution:** Web download from compromised infrastructure (130.12.180.43)
- **Target Profile:** Windows users with browser-stored credentials and cryptocurrency wallets
- **Evasion Techniques:** VMProtect packing, anti-debugging, process enumeration
- **Associated Tools:** TeamViewer, TightVNC (potential remote access components)

**Business Impact:**
- **Financial:** Direct cryptocurrency theft, banking credential compromise
- **Data Breach:** Email credentials, browser session tokens, saved passwords
- **Lateral Movement:** Harvested RDP/VPN credentials enable network expansion
- **Operational:** RMM tool abuse (TeamViewer/TightVNC) for persistent remote access

---

## Technical Analysis

### Sample Information

| Attribute | Value |
|-----------|-------|
| **SHA-256** | `89ae9a2ad575daa389d6340696b23ca795101c72e9326cd295b8856a6b967d38` |
| **MD5** | `edf91e6b1faa7792734a82ad1ed4d23b` |
| **SHA-1** | `e2bf10aa4403933d0c7af400fd4d66c51700730c` |
| **File Size** | 9,327,104 bytes (9.3 MB) |
| **File Type** | PE32+ (AMD64) Windows GUI executable |
| **Packer** | VMProtect (confirmed by ESET, Sophos signatures) |
| **Compile Date** | 1970-01-01 (epoch timestamp — typical of packed binaries) |
| **Imphash** | `b4436fe2ccd1a0108c1cda48be61b0bf` |
| **SSDEEP** | `196608:mL4jAqSFcwRvXNal+KKCGSKYvIjYyBTe6TBDCvTRioi7JIy:mL6AqsraMPCGjjJq6Fm0Z` |
| **First Seen** | 2026-02-22 18:33:31 UTC |
| **Dropped By** | Amadey botnet |

### Distribution & Infrastructure

**Download URL:**
```
http://130.12.180.43/files/5926060486/p4oPI3H.exe
```

**C2 Infrastructure:**
- **IP Address:** 130.12.180.43
- **Country:** Germany
- **ISP:** Virtualine Technologies (virtualine.org)
- **Reputation:** 8% abuse score (AbuseIPDB), 50 OTX threat intelligence pulses

### Capabilities

#### 1. Credential Harvesting
**Targets:**
- Windows Credential Manager
- Browser password stores (Chrome, Firefox, Edge, Opera, Brave)
- Email clients (Outlook, Thunderbird, Windows Mail)
- FTP clients (FileZilla, WinSCP)
- VPN clients

**Technique:**
- SQLite database parsing for browser credentials
- DPAPI decryption for encrypted stores
- Registry enumeration

#### 2. Cryptocurrency Wallet Theft
**Targeted Wallets:**
- Exodus, Electrum, Atomic Wallet, Coinomi
- Browser extension wallets (MetaMask, Phantom, etc.)
- Desktop wallet applications

**Data Stolen:**
- Private keys, seed phrases, wallet.dat files, configuration files

#### 3. Browser Data Exfiltration
**Stolen Data:**
- Cookies (session hijacking)
- Autofill data
- Browsing history
- Bookmarks
- Browser extensions

#### 4. System Reconnaissance
**Collected Information:**
- Computer name, username
- Installed software
- Processor information
- Geographic location
- Network configuration

#### 5. Remote Access Components
**Associated Tools:**
- TeamViewer (RMM tool abuse)
- TightVNC (VNC server for screen access)

---

## MITRE ATT&CK Mapping

### Initial Access
- **T1566** - Phishing (Amadey delivery via malspam)

### Execution
- **T1204.002** - User Execution: Malicious File
- **T1106** - Native API

### Persistence
- **T1547.001** - Registry Run Keys
- **T1053.005** - Scheduled Task

### Defense Evasion
- **T1027.002** - Software Packing (VMProtect)
- **T1622** - Debugger Evasion
- **T1497.001** - System Checks (sandbox evasion)
- **T1055** - Process Injection

### Credential Access
- **T1555.003** - Credentials from Web Browsers
- **T1555.004** - Windows Credential Manager
- **T1555** - Credentials from Password Stores
- **T1539** - Steal Web Session Cookies

### Discovery
- **T1082** - System Information Discovery
- **T1083** - File and Directory Discovery
- **T1518** - Software Discovery
- **T1057** - Process Discovery

### Collection
- **T1005** - Data from Local System
- **T1185** - Browser Session Cookie Theft
- **T1113** - Screen Capture

### Command and Control
- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1219** - Remote Access Software (TeamViewer/TightVNC)

### Exfiltration
- **T1041** - Exfiltration Over C2 Channel
- **T1020** - Automated Exfiltration

---

## Indicators of Compromise (IOCs)

### File Hashes
```
SHA-256: 89ae9a2ad575daa389d6340696b23ca795101c72e9326cd295b8856a6b967d38
MD5:     edf91e6b1faa7792734a82ad1ed4d23b
SHA-1:   e2bf10aa4403933d0c7af400fd4d66c51700730c
Imphash: b4436fe2ccd1a0108c1cda48be61b0bf
```

### Network Indicators
```
C2 IP:          130.12.180.43
Download URL:   http://130.12.180.43/files/5926060486/p4oPI3H.exe
ASN:            AS200019 (Virtualine Technologies)
Country:        Germany
```

### Behavioral Indicators
- Process enumeration via WMI/API
- Access to browser credential databases:
  - `%APPDATA%\Local\Google\Chrome\User Data\Default\Login Data`
  - `%APPDATA%\Roaming\Mozilla\Firefox\Profiles\*.default\logins.json`
- Registry access: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Windows Credential Manager API calls: `CredEnumerateA`, `CredReadA`
- Anti-debugging API: `NtSetInformationThreadHideFromDebugger`
- Process injection: `WriteProcessMemory` to system processes

---

## Detection

### YARA Rules

```yara
import "pe"

rule SantaStealer_Imphash_Match
{
    meta:
        description = "Detects SantaStealer via Import Hash"
        author = "Peris.ai Threat Intelligence"
        date = "2026-02-23"
        malware_family = "SantaStealer"
        severity = "high"
        tlp = "white"
        
    condition:
        pe.imphash() == "b4436fe2ccd1a0108c1cda48be61b0bf"
}

rule SantaStealer_Behavioral_Indicators
{
    meta:
        description = "Detects SantaStealer behavioral patterns"
        author = "Peris.ai Threat Intelligence"
        date = "2026-02-23"
        malware_family = "SantaStealer"
        use_case = "Memory scanning, runtime detection"
        tlp = "white"
        
    strings:
        // Credential harvesting
        $cred1 = "CredEnumerateA" fullword
        $cred2 = "CredReadA" fullword
        
        // Browser targeting
        $browser1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" nocase
        $browser2 = "\\Mozilla\\Firefox\\Profiles\\" nocase
        $browser3 = "SELECT origin_url, username_value, password_value FROM logins" nocase
        
        // Wallet targeting
        $wallet1 = "wallet.dat" nocase
        $wallet2 = "\\Exodus\\" nocase
        $wallet3 = "\\Electrum\\" nocase
        
        // Anti-debugging
        $antidbg1 = "NtSetInformationThread" fullword
        $antidbg2 = "ThreadHideFromDebugger" fullword
        
        // RMM abuse
        $rmm1 = "TeamViewer" nocase
        $rmm2 = "TightVNC" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        filesize > 5MB and
        (
            (2 of ($cred*) and 2 of ($browser*)) or
            (2 of ($wallet*) and 1 of ($browser*)) or
            (1 of ($antidbg*) and 2 of ($browser*)) or
            (2 of ($rmm*))
        )
}
```

### Endpoint Detection Patterns

**Suspicious Process Behavior:**
- Non-browser process accessing browser credential databases
- `WriteProcessMemory` to system processes (svchost, explorer)
- Credential Manager API enumeration
- Crypto wallet file access by non-wallet processes

**Network Indicators:**
- HTTP POST requests to 130.12.180.43
- Large outbound data transfers (> 50KB) to unknown IPs
- Connections to Virtualine Technologies ASN (AS200019)

---

## Remediation Steps

### Immediate Actions (First Hour)
1. **Isolate infected systems** — Network-level isolation
2. **Block C2 infrastructure** — Firewall block 130.12.180.43
3. **Disable compromised accounts** — Lock Active Directory accounts, revoke cloud sessions
4. **Alert security team** — Escalate to incident response

### Short-Term Actions (24 Hours)
5. **Credential reset** — All browser-saved passwords, banking, email, crypto exchanges
6. **Forensic analysis** — Memory dump, disk timeline, browser database extraction
7. **Network-wide IOC hunt** — Search for imphash, C2 IP connections
8. **Amadey infection vector analysis** — Email logs, web proxy, endpoint telemetry

### Long-Term Actions (1 Week)
9. **Endpoint hardening** — Application whitelisting, credential protection
10. **User security training** — Phishing awareness, credential hygiene
11. **Detection rule tuning** — Baseline browser credential access patterns
12. **Threat hunting** — Regular scans for VMProtect signatures, unusual credential access

### Prevention Measures
13. **Email security** — Block executable attachments, implement sandboxing
14. **Endpoint protection** — Behavioral detection, anti-exploit features
15. **Network segmentation** — Zero-trust architecture, micro-segmentation
16. **Credential management** — Enforce MFA, enterprise password managers

---

## Threat Intelligence Context

### Amadey Botnet Ecosystem
**Amadey** is a modular botnet active since 2018, primarily used as a malware loader/dropper.

**Characteristics:**
- **Business Model:** Malware-as-a-Service (MaaS)
- **Delivery Methods:** Phishing, exploit kits, malvertising, software cracks
- **Secondary Payloads:** Infostealers (RedLine, Vidar, Raccoon), ransomware, cryptominers
- **Infrastructure:** Fast-flux DNS, bulletproof hosting (Germany, Netherlands, Russia)

### VMProtect Packing Trends
- **Adoption:** 80% of infostealers now use commercial packers
- **Detection Evasion:** Average AV detection drops from 70% to 25% with VMProtect
- **Countermeasures:** Behavioral detection more effective than static signatures

### Financial Impact
**Credential Market Prices (2026 Q1):**
- Bank logins: $50-$200 per account
- Cryptocurrency exchange: $100-$500
- Email + password combos: $2-$10
- Browser sessions (banking): $20-$100

**Estimated revenue per successful infection:** $500-$2,000 for threat actors

---

## Conclusion

SantaStealer represents a **high-severity threat** combining modern evasion techniques (VMProtect packing) with comprehensive credential harvesting capabilities. Its distribution via the established Amadey botnet infrastructure indicates a **professionally operated cybercrime campaign** targeting financial gain through stolen credentials and cryptocurrency theft.

**Critical Takeaways:**
1. Low AV detection (25%) makes signature-based defenses insufficient
2. Credential theft scope enables both financial theft and lateral movement
3. Amadey distribution suggests ongoing campaign with additional variants expected
4. VMProtect packing requires enhanced analysis capabilities

**Recommended Actions:**
- Deploy behavioral detection rules immediately
- Implement network-wide IOC hunting
- Review browser credential storage policies
- Enhance phishing defenses (Amadey's primary delivery vector)

---

## References

- **MalwareBazaar:** https://bazaar.abuse.ch/sample/89ae9a2ad575daa389d6340696b23ca795101c72e9326cd295b8856a6b967d38/
- **ANY.RUN Sandbox:** https://app.any.run/tasks/9eb31db7-d347-4c1d-a079-b9c86f3e49f1
- **Triage Sandbox:** https://tria.ge/reports/260222-w7vhdaev8h/
- **CAPE Sandbox:** https://www.capesandbox.com/analysis/54098/
- **MITRE ATT&CK:** https://attack.mitre.org/

---

**Analysis Date:** 2026-02-23  
**Threat Intelligence:** Peris.ai Security Research Team  
**Classification:** TLP:WHITE  
**Distribution:** Public
