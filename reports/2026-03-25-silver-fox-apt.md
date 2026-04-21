# Silver Fox APT - Indonesia & Southeast Asia Targeting Campaign

## Metadata
- **Threat Actor:** Silver Fox
- **Attribution:** China-based (High Confidence)
- **Active Period:** January 2025 - Present (March 2026)
- **Target Geography:** Indonesia, Malaysia, Philippines, Thailand, Singapore, India
- **Primary Target:** Indonesia (Tax Authority Impersonation)
- **Threat Type:** Hybrid APT/Cybercrime
- **Sophistication:** Medium
- **Status:** Ongoing

## Executive Summary

Silver Fox is a China-based threat actor conducting hybrid espionage and financially-motivated campaigns across Southeast Asia, with significant targeting of Indonesian organizations. The group evolved through three distinct campaign waves (2025-2026), shifting from ValleyRAT backdoor deployment to Python-based credential stealers. Silver Fox primarily uses tax authority impersonation as initial access, exploiting cultural relevance and organizational trust. Indonesian entities face heightened risk due to targeted tax-themed phishing campaigns impersonating national taxation authorities.

## Campaign Timeline

### Wave 1 (January - Mid 2025)
- **Target:** Taiwan, China (initial focus)
- **Vector:** Tax-themed phishing emails with malicious PDF attachments
- **Payload:** ValleyRAT backdoor
- **Technique:** DLL side-loading
- **Geographic Expansion:** Extended to South Asia including **Indonesia**

### Wave 2 (Mid-December 2025)
- **Target:** **Indonesia, Malaysia, Philippines, Thailand, Singapore, India**
- **Vector:** Phishing websites hosting malware/RMM tools
- **Payload:** Remote Monitoring and Management (RMM) tools (legitimate but abused)
- **Motivation:** Profit-driven + espionage
- **Change:** Shifted from attachments to download sites

### Wave 3 (February 2026 - Present)
- **Target:** Malaysia (primary), broader South Asia (likely)
- **Vector:** Phishing disguised as legitimate applications
- **Payload:** Python-based stealer masquerading as WhatsApp application
- **Sophistication:** Lower (simpler credential theft focus)
- **Status:** Ongoing operations expected across region

## Malware Arsenal

### ValleyRAT (Waves 1-2)
- **Type:** Remote Access Trojan (RAT)
- **Language:** C/C++
- **Capabilities:**
  - Remote command execution
  - File system manipulation
  - Credential harvesting
  - Screen capture
  - Keylogging
  - Persistence mechanisms
- **Delivery:** PDF attachments with DLL side-loading
- **C2:** HTTP/HTTPS encrypted channels

### HoldingHands (Associated Backdoor)
- **Type:** Secondary implant
- **Purpose:** Redundant access, lateral movement
- **Association:** Deployed alongside ValleyRAT in espionage campaigns

### Python-Based Stealer (Wave 3)
- **Type:** Credential/Information Stealer
- **Language:** Python (likely PyInstaller compiled)
- **Disguise:** WhatsApp application lookalike
- **Targets:**
  - Browser saved passwords
  - Session tokens
  - Cryptocurrency wallets
  - Saved credentials
  - Email client data
- **Delivery:** Phishing websites mimicking legitimate download portals

### RMM Tool Abuse (Wave 2)
- **Tools:** AnyDesk, TeamViewer, or similar legitimate RMM software
- **Tactic:** Social engineering victims to install "support tools"
- **Risk:** Persistent remote access without deploying custom malware

## Indonesia-Specific Threat Profile

### Targeting Rationale
1. **Tax Season Exploitation:** Campaigns align with Indonesian tax filing periods
2. **Authority Impersonation:** Lures impersonate Direktorat Jenderal Pajak (DGP)
3. **Language Localization:** Phishing content in Bahasa Indonesia
4. **Cultural Trust:** Exploitation of government authority respect
5. **Digital Adoption:** Growing cloud/SaaS adoption creates attack surface

### Attack Scenarios for Indonesia

#### Scenario 1: Tax Audit Phishing
```
Subject: [URGENT] Verifikasi Data SPT Tahunan 2025 - Direktorat Jenderal Pajak
Body: Yth. Wajib Pajak,
Kami memerlukan verifikasi dokumen pajak Anda. Silakan unduh formulir terlampir 
dan lengkapi sebelum [deadline]. Kegagalan memverifikasi dapat mengakibatkan denda.

Attachment: Formulir_Verifikasi_Pajak_2025.pdf [MALICIOUS]
```

#### Scenario 2: Payroll Document Lure
```
Subject: Update Slip Gaji & Tunjangan - Maret 2026
Body: Berikut slip gaji dan informasi tunjangan bulan Maret 2026.
Silakan unduh aplikasi verifikasi untuk melihat rincian lengkap.

Link: hxxps://payroll-verification[.]com/download [PYTHON STEALER]
```

## Indicators of Compromise (IOCs)

### Email Indicators
- Sender impersonating tax authorities (@pajak.go.id lookalikes)
- Urgent language requiring immediate action
- Tax audit, verification, or penalty themes
- Attachments: PDF files with government branding
- Links to typosquatted domains mimicking government sites

### File Indicators
- **ValleyRAT Samples:**
  - PDF files with embedded DLL loaders
  - DLL files with suspicious exports (e.g., `ServiceMain`, `DllEntry`)
  - Sideloaded legitimate executables with malicious DLLs
- **Python Stealer:**
  - Executables disguised as `WhatsApp_Installer.exe`
  - PyInstaller compiled binaries (check `PyInstaller` strings)
  - Icons mimicking popular applications

### Network Indicators
- HTTP/HTTPS C2 communication with unusual TLS certificates
- Connections to infrastructure in China or VPS providers
- Large outbound data transfers (credential exfiltration)
- DNS queries to newly registered domains mimicking government sites

### Behavioral Indicators
- Unexpected RMM tool installations (AnyDesk, TeamViewer)
- Python process spawning from user directories
- DLL loading from %TEMP% or %APPDATA%
- Registry modifications for persistence
- Scheduled tasks created by non-admin processes

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Wave |
|--------|--------------|----------------|------|
| Reconnaissance | T1589.001 | Gather Victim Identity Information: Credentials | All |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | All |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | 1 |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | 2-3 |
| Initial Access | T1189 | Drive-by Compromise | 2-3 |
| Execution | T1204.001 | User Execution: Malicious Link | 2-3 |
| Execution | T1204.002 | User Execution: Malicious File | 1 |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | 3 |
| Persistence | T1574.002 | Hijack Execution Flow: DLL Side-Loading | 1 |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | 1-2 |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | 3 |
| Defense Evasion | T1027.002 | Obfuscated Files or Information: Software Packing | 3 |
| Credential Access | T1555.003 | Credentials from Password Stores: Web Browsers | 3 |
| Credential Access | T1056.001 | Input Capture: Keylogging | 1-2 |
| Discovery | T1082 | System Information Discovery | 1-2 |
| Collection | T1113 | Screen Capture | 1-2 |
| Collection | T1005 | Data from Local System | All |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | 1-2 |
| Command and Control | T1219 | Remote Access Software | 2 |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | All |

## Brahma XDR Detection Rules

```xml
<rule id="900020" level="10" frequency="1" timeframe="60">
  <description>Silver Fox APT: Tax-Themed Phishing Email (Indonesia)</description>
  <category>phishing</category>
  <info type="threat-actor">Silver Fox</info>
  <info type="geography">Indonesia</info>
  
  <if_sid>12300</if_sid>
  <match type="pcre2">(?i)(pajak|direktorat jenderal pajak|dgp|verifikasi|SPT|denda|audit)</match>
  <match type="pcre2">(?i)(\.pdf|\.zip|\.rar)</match>
  
  <mitre>
    <id>T1566.001</id>
    <tactic>Initial Access</tactic>
    <technique>Phishing: Spearphishing Attachment</technique>
  </mitre>
</rule>

<rule id="900021" level="12" frequency="1" timeframe="60">
  <description>Silver Fox APT: ValleyRAT DLL Side-Loading Detection</description>
  <category>malware</category>
  <info type="threat-actor">Silver Fox</info>
  <info type="malware">ValleyRAT</info>
  
  <if_sid>554</if_sid>
  <match type="pcre2">(?i)(DllEntry|ServiceMain|Start)</match>
  <match>loaded from: %TEMP%</match>
  
  <mitre>
    <id>T1574.002</id>
    <tactic>Defense Evasion</tactic>
    <technique>Hijack Execution Flow: DLL Side-Loading</technique>
  </mitre>
</rule>

<rule id="900022" level="11" frequency="1" timeframe="60">
  <description>Silver Fox APT: Python Stealer Execution (WhatsApp Impersonation)</description>
  <category>malware</category>
  <info type="threat-actor">Silver Fox</info>
  
  <if_sid>61603</if_sid>
  <program_name>python.exe|pythonw.exe</program_name>
  <match type="pcre2">(?i)(WhatsApp|Telegram|Discord).*\.(exe|com)</match>
  
  <mitre>
    <id>T1036.005</id>
    <tactic>Defense Evasion</tactic>
    <technique>Masquerading: Match Legitimate Name or Location</technique>
  </mitre>
</rule>

<rule id="900023" level="10" frequency="1" timeframe="60">
  <description>Silver Fox APT: Unauthorized RMM Tool Installation</description>
  <category>malware</category>
  <info type="threat-actor">Silver Fox</info>
  
  <if_sid>554</if_sid>
  <match type="pcre2">(?i)(anydesk|teamviewer|ammyy|supremo).*installed</match>
  
  <mitre>
    <id>T1219</id>
    <tactic>Command and Control</tactic>
    <technique>Remote Access Software</technique>
  </mitre>
</rule>

<rule id="900024" level="13" frequency="1" timeframe="60">
  <description>Silver Fox APT: Credential Harvesting from Browser Stores</description>
  <category>credential-access</category>
  <info type="threat-actor">Silver Fox</info>
  
  <if_sid>550</if_sid>
  <match type="pcre2">(?i)(Login Data|Cookies|Web Data|passwords\.txt)</match>
  <match type="pcre2">(?i)(Chrome|Firefox|Edge|Brave).*AppData</match>
  
  <mitre>
    <id>T1555.003</id>
    <tactic>Credential Access</tactic>
    <technique>Credentials from Password Stores: Web Browsers</technique>
  </mitre>
</rule>
```

## Brahma NDR Detection Rules

```
alert tcp any any -> any any (msg:"Silver Fox APT ValleyRAT C2 Beacon Pattern"; flow:established,to_server; content:"|00 00 00|"; depth:3; content:"|FF FE|"; distance:0; within:10; threshold:type threshold, track by_src, count 5, seconds 300; classtype:trojan-activity; sid:9000020; rev:1; metadata:threat_actor "Silver Fox";)

alert http any any -> any any (msg:"Silver Fox APT Phishing Site Access (Tax Theme)"; flow:established,to_server; http.host; pcre:"/pajak|tax|dgp|verification|verifikasi/i"; http.uri; content:".pdf"; nocase; classtype:trojan-activity; sid:9000021; rev:1; metadata:threat_actor "Silver Fox";)

alert http any any -> any any (msg:"Silver Fox APT Python Stealer Download"; flow:established,from_server; file.name; pcre:"/WhatsApp.*\.exe|Telegram.*\.exe/i"; classtype:trojan-activity; sid:9000022; rev:1; metadata:threat_actor "Silver Fox";)

alert tcp any any -> any any (msg:"Silver Fox APT RMM Tool Outbound Connection"; flow:established; content:"AnyDesk"; nocase; content:"TeamViewer"; nocase; classtype:policy-violation; sid:9000023; rev:1; metadata:threat_actor "Silver Fox";)

alert tls any any -> any any (msg:"Silver Fox APT Suspicious TLS Certificate (CN Mismatch Government)"; flow:established; tls.subject; pcre:"/pajak\.go\.id|tax\.gov/i"; tls.issuer; content:!"DigiCert"; content:!"GlobalSign"; classtype:trojan-activity; sid:9000024; rev:1; metadata:threat_actor "Silver Fox";)
```

## Recommendations for Indonesian Organizations

### Immediate Actions
1. **User Awareness Training:**
   - Educate employees on tax-themed phishing campaigns
   - Clarify official DGP communication channels
   - Train on identifying impersonation attempts
   - Emphasize verification before opening attachments

2. **Email Security:**
   - Block emails with tax/audit keywords from non-government domains
   - Implement DMARC, SPF, DKIM for @pajak.go.id verification
   - Sandbox all PDF attachments before delivery
   - Flag external emails with urgent/penalty language

3. **Endpoint Protection:**
   - Deploy XDR/EDR with DLL side-loading detection
   - Block unauthorized RMM tool installations
   - Monitor Python process execution from user directories
   - Enable tamper protection on security tools

### Detection & Monitoring
1. Deploy XDR/NDR rules tailored for Silver Fox TTPs
2. Monitor for tax-themed emails during filing seasons
3. Alert on credential file access by non-browser processes
4. Track installations of RMM tools without IT tickets
5. Baseline legitimate DLL loading patterns

### Threat Hunting
1. **Hunt for ValleyRAT:**
   - Search for DLL files in %TEMP%, %APPDATA% with suspicious exports
   - Identify legitimate executables loading unusual DLLs
   - Check scheduled tasks created by user-level processes

2. **Hunt for Python Stealers:**
   - Find PyInstaller executables in user directories
   - Identify Python processes accessing browser data directories
   - Search for executables with messaging app names

3. **Hunt for RMM Abuse:**
   - Audit all installed RMM tools against IT asset database
   - Check for RMM tools with no corresponding support tickets
   - Review RMM tool connection logs for unauthorized sessions

### Hardening
1. Implement application whitelisting (AppLocker/WDAC)
2. Restrict DLL loading to signed libraries only
3. Block execution from %TEMP% and %APPDATA%
4. Disable unnecessary scripting interpreters (Python, PowerShell) for regular users
5. Enforce MFA for all email and cloud services
6. Segment networks to limit lateral movement

### Incident Response Playbook
1. **Triage:**
   - Isolate affected systems from network
   - Preserve memory dump and disk image
   - Collect process listing and network connections

2. **Analysis:**
   - Identify malware variant (ValleyRAT vs Python stealer)
   - Extract C2 infrastructure IOCs
   - Determine scope of credential compromise

3. **Containment:**
   - Block C2 domains/IPs at perimeter
   - Disable compromised accounts
   - Remove RMM tools or revoke access

4. **Eradication:**
   - Remove malware files and persistence mechanisms
   - Delete unauthorized scheduled tasks
   - Clean registry keys

5. **Recovery:**
   - Force password resets for all users on affected systems
   - Restore from clean backups if ransomware deployed
   - Rebuild systems if deep compromise suspected

6. **Post-Incident:**
   - Update detection rules with campaign-specific IOCs
   - Conduct lessons-learned session
   - Enhance email filtering rules
   - Schedule follow-up threat hunt

## Strategic Assessment

### Motivation Analysis
- **Dual-Use Operations:** Silver Fox demonstrates both espionage and financial motivations
- **Espionage Campaigns:** ValleyRAT deployment suggests intelligence collection (Taiwan focus)
- **Cybercrime Campaigns:** Python stealer and RMM abuse indicate profit-seeking (broader SEA)
- **Indonesia as Target:** Likely combination of economic espionage and credential harvesting for resale

### Evolution Trend
- **Sophistication Decline:** Shift from custom RATs to simpler stealers suggests lower-skilled affiliates
- **TTPs Adaptation:** Move from attachments to phishing sites shows awareness of detection
- **Geographic Expansion:** Broadening from Taiwan/China to SEA indicates success/resource availability
- **Tool Diversity:** Use of RMM tools reduces custom malware development needs

### Future Threat Prediction
- Continued tax-themed campaigns during Indonesian filing seasons (March-April, September-October)
- Potential adoption of AI-generated phishing content in Bahasa Indonesia
- Possible shift to mobile malware targeting Indonesian banking apps
- Likely collaboration with other China-nexus groups for shared infrastructure

## References
- Silver Fox Threat Intelligence Report (Secureworks CTU)
- ValleyRAT Technical Analysis (Multiple Security Vendors)
- Indonesia Tax Authority Phishing Advisory
- MITRE ATT&CK Framework

## Threat Intelligence
- **Actor Attribution Confidence:** High (China-based)
- **Targeting Confidence:** Very High (Indonesia confirmed target)
- **Campaign Status:** Ongoing (March 2026)
- **Detection Difficulty:** Medium (phishing requires user awareness)
- **Remediation Difficulty:** Medium (user training + technical controls)

---
**Analysis Date:** March 25, 2026  
**Analyst:** Xhavero  
**Classification:** TLP:AMBER (Indonesian Government/Private Sector Sharing)  
**Threat Level:** HIGH (Indonesia-specific)  
**Geographic Focus:** Indonesia, Southeast Asia
