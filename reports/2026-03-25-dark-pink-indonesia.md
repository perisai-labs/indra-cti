# Dark Pink APT: Indonesia Government Targeting Analysis

**Date:** 2026-03-25  
**Severity:** HIGH  
**Threat Actor:** Dark Pink (aka Saaiwc, DarkPink)  
**Status:** Active (since mid-2021)  
**Category:** Advanced Persistent Threat (APT), Cyberespionage

---

## Executive Summary

Dark Pink is an APT group active since mid-2021, conducting targeted cyberespionage operations against government, military, and high-profile organizations in Indonesia and Southeast Asia. The group employs sophisticated custom malware and living-off-the-land techniques for long-term data exfiltration.

**Indonesia-Specific Attacks:**
- **January 2023:** Indonesian government agency breach
- **December 8, 2022:** Indonesian government entity compromised
- **Total Victims:** 13+ organizations in APAC region

**Unique Characteristics:**
- Custom, previously unseen toolkit
- Telegram API for C2 (TelePowerBot, KamiKakaBot)
- GitHub-hosted malware repositories
- DLL side-loading for stealth
- Microphone recording and messenger data theft

**Target Profile:** Government agencies, military bodies, high-value organizations in Indonesia, Philippines, Malaysia, Cambodia, Vietnam, Brunei.

---

## Technical Details

### Threat Actor Profile
- **Name:** Dark Pink (Saaiwc, DarkPink)
- **Active Since:** Mid-2021
- **Attribution:** Likely APAC-origin, no confirmed nation-state attribution
- **Targeting:** Government, military, aerospace, telecommunications
- **Motivation:** Cyberespionage, intelligence collection

### Attack Methodology

**Initial Access:**
1. **Spear-Phishing:** Spoofed emails on trade issues, job applications
   - Scans job vacancy portals to impersonate legitimate applicants
   - Weaponized documents with embedded exploits
2. **Exploitation:** WinRAR zero-day vulnerabilities
3. **Social Engineering:** High-quality pretexts tailored to target organizations

**Execution & Persistence:**
- **Custom Malware Toolkit:** Previously unseen, regularly updated
- **DLL Side-Loading:** Legitimate applications abused for malware execution
- **Living-off-the-Land:** Native Windows tools for stealth
- **Scheduled Tasks:** Persistence via Windows Task Scheduler

**Command & Control:**
- **Telegram API:** Primary C2 channel (bots: TelePowerBot, KamiKakaBot)
- **GitHub Repositories:** Malware hosting (first commit: January 9, 2023)
- **Dropbox/Email:** Backup exfiltration channels

**Data Collection:**
- Microphone audio recording
- Document theft (Office files, PDFs, emails)
- Messenger application data (WhatsApp, Telegram, Signal)
- Screenshots and clipboard capture
- Credential harvesting

**Defense Evasion:**
- Custom toolkit regularly updated to avoid detection
- Encrypted ZIP archives for exfiltration
- Anti-analysis techniques in malware
- Use of legitimate cloud services (Telegram, Dropbox, GitHub)

---

## Indicators of Compromise (IOCs)

### Malware Tools

**Named Tools:**
- **TelePowerBot** — Custom Trojan for data theft and network access
- **KamiKakaBot** — Telegram-based C2 bot for command execution

**Tool Characteristics:**
- Custom, homemade malware (not commodity tools)
- Telegram bot API integration
- DLL side-loading loaders
- Microphone capture utilities
- Messenger data stealers

### Behavioral IOCs

**Network Indicators:**
- Telegram API connections (`api.telegram.org`)
- GitHub repository access for tool downloads
- Dropbox API connections
- SMTP traffic to attacker-controlled email addresses
- Unusual data volumes to cloud services

**File System:**
- DLL side-loading indicators:
  - Legitimate executables with malicious DLLs in same directory
  - Unexpected DLLs in user `%APPDATA%` or `%TEMP%` directories
- Compressed archives (ZIP) with stolen data
- Microphone recordings in unusual locations
- Messenger database copies

**Process Execution:**
- Legitimate applications loading suspicious DLLs
- PowerShell with encoded commands
- Scheduled tasks created by non-admin users
- WinRAR exploitation artifacts

**Registry Modifications:**
- Scheduled task persistence keys
- Run/RunOnce keys for malware auto-start
- DLL search order hijacking entries

### Phishing Indicators

**Email Characteristics:**
- Job application themes (HR departments targeted)
- Trade/business collaboration topics
- Government policy/regulation updates
- Spoofed sender addresses (legitimate domains)
- Weaponized attachments: DOCX, PDF, RAR archives

**Attachment Indicators:**
- Exploited WinRAR archives
- Macro-enabled Office documents
- Embedded executables in document containers

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Details |
|--------|--------------|----------------|---------|
| Reconnaissance | T1589.002 | Gather Victim Identity Information | Job portal scraping for impersonation |
| Resource Development | T1583.008 | Acquire Infrastructure: Malware Repositories | GitHub repos for tools |
| Resource Development | T1587.001 | Develop Capabilities: Malware | Custom toolkit (TelePowerBot, KamiKakaBot) |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Weaponized docs on trade/jobs |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Malicious links in emails |
| Execution | T1203 | Exploitation for Client Execution | WinRAR 0-day |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Script-based execution |
| Persistence | T1053.005 | Scheduled Task/Job | Windows Task Scheduler |
| Persistence | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | DLL side-loading |
| Defense Evasion | T1027 | Obfuscated Files or Information | Encrypted/packed malware |
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading | Legitimate apps abused |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Runtime decryption |
| Credential Access | T1555 | Credentials from Password Stores | Browser/messenger credentials |
| Discovery | T1082 | System Information Discovery | OS/user enumeration |
| Discovery | T1083 | File and Directory Discovery | Document searches |
| Discovery | T1120 | Peripheral Device Discovery | Microphone enumeration |
| Collection | T1005 | Data from Local System | Document theft |
| Collection | T1113 | Screen Capture | Screenshots |
| Collection | T1115 | Clipboard Data | Clipboard monitoring |
| Collection | T1123 | Audio Capture | Microphone recording |
| Collection | T1114 | Email Collection | Email client data theft |
| Collection | T1119 | Automated Collection | Systematic data gathering |
| Collection | T1213.003 | Data from Information Repositories: Code Repositories | GitHub access |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | Telegram API |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: To Cloud Storage | Dropbox, Telegram |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Telegram bot exfil |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Email exfil |

---

## Brahma XDR Detection Rules

```xml
<!-- Rule 900301: Dark Pink - Telegram API C2 Communication -->
<rule id="900301" level="12">
  <if_sid>92003</if_sid>
  <field name="win.eventdata.destinationHostname">api.telegram.org</field>
  <field name="win.eventdata.image" type="pcre2">(?!telegram\.exe|telegrampro\.exe)</field>
  <description>Dark Pink APT: Suspicious Telegram API access from non-Telegram process</description>
  <mitre>
    <id>T1102.002</id>
    <id>T1041</id>
  </mitre>
  <group>windows,apt,dark-pink,c2,</group>
</rule>

<!-- Rule 900302: Dark Pink - DLL Side-Loading Activity -->
<rule id="900302" level="11">
  <if_sid>92007</if_sid>
  <field name="win.eventdata.imageLoaded" type="pcre2">(?i)\\appdata\\|\\temp\\|\\public\\</field>
  <field name="win.eventdata.signed">false</field>
  <description>Dark Pink APT: Suspicious unsigned DLL load from user directory</description>
  <mitre>
    <id>T1574.002</id>
  </mitre>
  <group>windows,apt,dark-pink,dll-sideloading,</group>
</rule>

<!-- Rule 900303: Dark Pink - Microphone Audio Capture -->
<rule id="900303" level="13">
  <if_sid>92000</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?!skype|zoom|teams|discord)</field>
  <field name="win.system.message" type="pcre2">(?i)audio.*recording|microphone.*access|winmm\.dll</field>
  <description>Dark Pink APT: Microphone audio capture by suspicious process</description>
  <mitre>
    <id>T1123</id>
  </mitre>
  <group>windows,apt,dark-pink,audio-capture,</group>
</rule>

<!-- Rule 900304: Dark Pink - Messenger Data Exfiltration -->
<rule id="900304" level="12">
  <if_sid>92011</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)whatsapp|telegram|signal|messenger</field>
  <field name="win.eventdata.targetFilename" type="pcre2">\.db$|\.sqlite$|\.dat$</field>
  <field name="win.eventdata.targetFilename" type="pcre2">\\appdata\\roaming\\</field>
  <description>Dark Pink APT: Messenger database file access detected</description>
  <mitre>
    <id>T1005</id>
    <id>T1114</id>
  </mitre>
  <group>windows,apt,dark-pink,exfiltration,</group>
</rule>

<!-- Rule 900305: Dark Pink - GitHub Malware Repository Access -->
<rule id="900305" level="10">
  <if_sid>92003</if_sid>
  <field name="win.eventdata.destinationHostname" type="pcre2">github\.com|githubusercontent\.com</field>
  <field name="win.eventdata.image" type="pcre2">powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe</field>
  <description>Dark Pink APT: Suspicious GitHub access from script interpreter</description>
  <mitre>
    <id>T1213.003</id>
  </mitre>
  <group>windows,apt,dark-pink,malware-download,</group>
</rule>

<!-- Rule 900306: Dark Pink - WinRAR Exploitation -->
<rule id="900306" level="14">
  <if_sid>92000</if_sid>
  <field name="win.eventdata.parentImage">winrar.exe</field>
  <field name="win.eventdata.image" type="pcre2">cmd\.exe|powershell\.exe|wscript\.exe|mshta\.exe</field>
  <description>Dark Pink APT: WinRAR spawning suspicious child process (potential exploitation)</description>
  <mitre>
    <id>T1203</id>
  </mitre>
  <group>windows,apt,dark-pink,exploitation,</group>
</rule>

<!-- Rule 900307: Dark Pink - Spearphishing Attachment Execution -->
<rule id="900307" level="11">
  <if_sid>92000</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)job.*application|trade.*proposal|vacancy|recruitment</field>
  <field name="win.eventdata.parentImage" type="pcre2">outlook\.exe|thunderbird\.exe|winmail\.exe</field>
  <description>Dark Pink APT: Suspicious execution from email client with phishing keywords</description>
  <mitre>
    <id>T1566.001</id>
  </mitre>
  <group>windows,apt,dark-pink,phishing,</group>
</rule>

<!-- Rule 900308: Dark Pink - ZIP Archive Exfiltration Preparation -->
<rule id="900308" level="11">
  <if_sid>92000</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)7z.*a|winrar.*a|powershell.*compress-archive</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)documents|downloads|desktop|appdata</field>
  <description>Dark Pink APT: Suspicious archive creation of user data directories</description>
  <mitre>
    <id>T1560.001</id>
    <id>T1119</id>
  </mitre>
  <group>windows,apt,dark-pink,exfiltration,</group>
</rule>
```

---

## Brahma NDR Detection Rules (Suricata)

```suricata
# SID 3000301: Dark Pink - Telegram Bot API C2 Traffic
alert tls $HOME_NET any -> any 443 (msg:"PERIS Dark Pink APT Telegram Bot API C2 Communication"; flow:established,to_server; tls.sni; content:"api.telegram.org"; fast_pattern; content:"sendDocument"; http_uri; nocase; threshold:type limit, track by_src, count 1, seconds 300; reference:url,perisai.ai/dark-pink; classtype:trojan-activity; sid:3000301; rev:1; metadata:attack_target Client_Endpoint, deployment Internal, signature_severity Critical, created_at 2026_03_25, performance_impact Low, affected_product Windows, tag Dark_Pink_APT;)

# SID 3000302: Dark Pink - GitHub Malware Repository Download
alert http $HOME_NET any -> any $HTTP_PORTS (msg:"PERIS Dark Pink APT GitHub Malware Repository Access"; flow:established,to_server; http.host; content:"raw.githubusercontent.com"; fast_pattern; http.uri; pcre:"/\/(TelePowerBot|KamiKakaBot|darkpink)/i"; http.method; content:"GET"; reference:url,perisai.ai/dark-pink; classtype:trojan-activity; sid:3000302; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2026_03_25, performance_impact Low, affected_product Windows, tag Dark_Pink_APT;)

# SID 3000303: Dark Pink - Dropbox Exfiltration
alert tls $HOME_NET any -> any 443 (msg:"PERIS Dark Pink APT Dropbox Data Exfiltration"; flow:established,to_server; tls.sni; content:"api.dropboxapi.com"; fast_pattern; content:"files/upload"; http_uri; nocase; filesize:>1000000; reference:url,perisai.ai/dark-pink; classtype:trojan-activity; sid:3000303; rev:1; metadata:attack_target Client_Endpoint, deployment Internal, signature_severity Critical, created_at 2026_03_25, performance_impact Moderate, affected_product Windows, tag Dark_Pink_APT;)

# SID 3000304: Dark Pink - Email Exfiltration via SMTP
alert tcp $HOME_NET any -> any 25 (msg:"PERIS Dark Pink APT SMTP Data Exfiltration with Attachment"; flow:established,to_server; content:"Content-Disposition|3a| attachment"; nocase; fast_pattern; content:".zip"; distance:0; within:200; threshold:type limit, track by_src, count 1, seconds 600; reference:url,perisai.ai/dark-pink; classtype:trojan-activity; sid:3000304; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2026_03_25, performance_impact Low, affected_product Windows, tag Dark_Pink_APT;)

# SID 3000305: Dark Pink - Spearphishing Attachment Delivery
alert smtp any any -> $HOME_NET 25 (msg:"PERIS Dark Pink APT Spearphishing Email with Job Application Theme"; flow:established,to_client; content:"Content-Type|3a| application"; nocase; content:"job application"; nocase; distance:0; content:".rar"; distance:0; within:500; reference:url,perisai.ai/dark-pink; classtype:social-engineering; sid:3000305; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2026_03_25, performance_impact Low, affected_product Windows, tag Dark_Pink_APT;)
```

---

## Recommendations

### Immediate Actions (Indonesia Government Agencies)
1. **Threat Hunt:** Search for Dark Pink IoCs in logs (2021-present)
2. **Telegram API Monitoring:** Block/monitor non-business Telegram API access
3. **GitHub Access Review:** Audit GitHub repository access from workstations
4. **Email Filtering:** Block job application emails with RAR/ZIP attachments
5. **Incident Response:** Activate IR team if indicators found

### Detection & Monitoring
- Deploy Brahma XDR rules 900301-900308 for endpoint detection
- Deploy Brahma NDR rules 3000301-3000305 for network monitoring
- Enable advanced logging:
  - Sysmon: Image load, network connections, file creation
  - PowerShell script block logging
  - DLL load monitoring
  - Audio device access events
- Monitor for:
  - Telegram API connections from non-Telegram apps
  - DLL side-loading patterns
  - Messenger database access
  - Large ZIP archive creation + upload

### Hardening Measures
- **Email Security:**
  - Sandbox all attachments before delivery
  - Block executable files in archives (RAR, ZIP, 7z)
  - Implement DMARC/DKIM/SPF for spoofing prevention
- **Application Whitelisting:** Block unauthorized script interpreters
- **DLL Search Order:** Enforce SafeDllSearchMode via Group Policy
- **WinRAR Patching:** Update to latest version (mitigate 0-day risks)
- **Microphone Permissions:** Restrict audio capture to approved apps

### Specific Indonesia Recommendations
1. **Government Communication Channels:**
   - Verify all job vacancy portals used by HR departments
   - Implement out-of-band verification for external job applicants
   - Educate HR staff on impersonation tactics
2. **Regional Threat Intel Sharing:**
   - Coordinate with ASEAN CSIRTs on Dark Pink IoCs
   - Share indicators with Indonesia Aviation Sector CSIRT
   - Participate in regional APT threat briefings
3. **High-Value Target Protection:**
   - Air-gap sensitive military/government systems
   - Implement privileged access workstations (PAWs)
   - Deploy deception technology (honeytokens for Telegram/GitHub access)

### Long-Term Strategy
- **Zero Trust Architecture:** Assume breach, verify everything
- **Threat Intel Platform:** Centralize Dark Pink IoC tracking
- **Red Team Exercises:** Simulate Dark Pink TTPs quarterly
- **Security Awareness:** Train staff on APAC-specific APT threats
- **Endpoint Hardening:** Block PowerShell for non-admin users
- **Cloud Access Security Broker (CASB):** Monitor Telegram, GitHub, Dropbox access

---

## Victim Organizations (Confirmed)

| Country | Organization Type | Date | Impact |
|---------|-------------------|------|--------|
| 🇮🇩 Indonesia | Government Agency | Jan 2023 | Data theft |
| 🇮🇩 Indonesia | Government Entity | Dec 8, 2022 | Espionage |
| 🇵🇭 Philippines | Military | 2022-2023 | Intelligence collection |
| 🇲🇾 Malaysia | Military | 2022-2023 | Data exfiltration |
| 🇰🇭 Cambodia | Government | 2022-2023 | Cyberespionage |
| 🇻🇳 Vietnam | Government | 2022-2023 | Document theft |
| 🇧🇳 Brunei | Government | 2022-2023 | Surveillance |
| 🇹🇭 Thailand | Unknown | 2022-2023 | Unknown |
| 🇧🇪 Belgium | Unknown | 2022-2023 | Unknown |

**Total Confirmed:** 13+ organizations (APAC-focused)

---

## Intelligence Gaps & Future Research

1. **Full IoC List:** Specific hashes, IPs, domains not publicly available
2. **Malware Samples:** TelePowerBot/KamiKakaBot reverse engineering needed
3. **Attribution:** Nation-state affiliation unclear (APAC-origin suspected)
4. **Current Activity:** Post-2023 operations not detailed in open sources
5. **Indonesia Targeting:** Additional unreported incidents likely

**Recommendation:** Coordinate with Group-IB, NSFOCUS, regional CSIRTs for comprehensive IoC sharing.

---

## References

- **Threat Group:** Dark Pink (Saaiwc, DarkPink)
- **Active Since:** Mid-2021
- **Primary Targets:** Indonesia, Philippines, Malaysia, Cambodia, Vietnam
- **Research:** Group-IB, NSFOCUS, Kaspersky
- **GitHub Indicators:** First commit January 9, 2023

---

**Analysis by:** Xhavero (L3 Blue Team)  
**Date:** 2026-03-25 20:00 WIB  
**Classification:** TLP:AMBER (Indonesia Government Audience)  
**Next Review:** 2026-04-15  
**Priority:** HIGH (Active threat to Indonesian government)
