# Amaranth-Dragon APT Campaign (ASEAN/Indonesia 2026)

**Analysis Date:** 2026-04-01  
**Analyst:** Xhavero  
**Threat Level:** 🔴 **CRITICAL**

## Executive Summary

Amaranth-Dragon is a newly identified China-linked APT group (correlated with APT41 infrastructure) conducting extensive cyber espionage campaigns targeting ASEAN government and law enforcement agencies throughout 2025 and into 2026. The group demonstrates advanced capabilities including zero-day exploitation (WinRAR CVE within days of disclosure), highly tailored social engineering, and geo-restricted infrastructure designed to evade detection outside target countries. **Indonesia is within the operational scope as an ASEAN member nation.**

## Threat Actor Profile

### Attribution
- **Primary Name:** Amaranth-Dragon
- **Aliases:** TBD (newly identified cluster)
- **Correlation:** APT41 infrastructure overlap
- **Suspected Attribution:** China (PRC state-nexus)
- **First Observed:** Early 2025
- **Status:** **ACTIVE** (ongoing operations into 2026)

### Target Profile
- **Primary Targets:** ASEAN government agencies
- **Secondary Targets:** Law enforcement organizations
- **Geographic Focus:** Southeast Asia (Indonesia, Thailand, Philippines, Vietnam, Malaysia, Singapore, Myanmar, Cambodia, Laos, Brunei)
- **Vertical Focus:** Government, public sector, law enforcement, diplomatic entities

### Sophistication Level
**VERY HIGH** - Nation-state capabilities

- Zero-day exploitation within days of disclosure
- Custom malware development
- Advanced operational security (geo-restricted infrastructure)
- Tailored social engineering tied to regional events
- Mimics legitimate security software for defense evasion
- Long-term persistent access operations

## Campaign Overview

### Objectives
- **Strategic Intelligence Collection:** Government policy, diplomatic communications
- **Law Enforcement Intelligence:** Criminal investigations, surveillance operations
- **Geopolitical Intelligence:** ASEAN regional coordination, South China Sea policies
- **Long-term Access:** Persistent presence for ongoing intelligence gathering

### Timeline
- **Early 2025:** Campaign initiation observed
- **Throughout 2025:** Sustained operations against ASEAN targets
- **2026:** Ongoing active operations

### Key Characteristics

1. **Rapid Exploit Adoption**
   - Exploited WinRAR vulnerability within days of disclosure
   - Demonstrates strong exploit development capability
   - Quick integration into operational toolset

2. **Geo-Targeted Infrastructure**
   - C2 infrastructure geo-restricted to specific countries
   - Evades sandbox analysis from non-target regions
   - Anti-analysis techniques targeting security researchers

3. **Contextual Social Engineering**
   - Lures based on local political events
   - Regional news and policy developments
   - Language-appropriate targeting
   - Cultural awareness in phishing content

4. **Defense Evasion**
   - Malware mimics legitimate security software
   - Code signing certificate abuse
   - Legitimate service impersonation
   - Living-off-the-land techniques

## Attack Chain

### Stage 1: Initial Access (T1566, T1190)

**Spear Phishing (Primary Vector)**
- Highly targeted emails to government officials
- Attachments exploiting WinRAR vulnerability
- Lures tied to ASEAN summits, regional policy, political events
- Example themes:
  - ASEAN ministerial meetings
  - Regional security cooperation
  - South China Sea policy documents
  - Law enforcement coordination briefings

**Exploit Public-Facing Application (Secondary)**
- Exploitation of internet-facing government web applications
- Known CVEs adapted for target environment

### Stage 2: Execution (T1059, T1204)
- Malicious document execution
- WinRAR vulnerability exploitation
- Script-based execution (PowerShell, VBScript)
- DLL sideloading of malicious payloads

### Stage 3: Persistence (T1547, T1053)
- Registry run keys
- Scheduled tasks
- Service creation mimicking legitimate software
- Bootkit/rootkit installation (advanced cases)

### Stage 4: Privilege Escalation (T1068, T1078)
- Exploit local vulnerabilities for SYSTEM access
- Credential harvesting and reuse
- Token manipulation

### Stage 5: Defense Evasion (T1027, T1036, T1070)
- Code obfuscation
- Masquerading as security software (AV, EDR)
- Log deletion and timestamp manipulation
- Certificate abuse for code signing
- Anti-sandbox/anti-VM techniques
- Geo-restricted C2 (only responds to target countries)

### Stage 6: Credential Access (T1003, T1555)
- LSASS memory dumping
- SAM/registry credential extraction
- Password store harvesting
- Keylogging capabilities

### Stage 7: Discovery (T1083, T1082, T1016)
- System information gathering
- Network topology mapping
- File and directory enumeration
- Government agency document searches

### Stage 8: Lateral Movement (T1021)
- RDP abuse with harvested credentials
- SMB/Windows Admin Shares
- PsExec and similar tools
- Pass-the-hash techniques

### Stage 9: Collection (T1005, T1114, T1113)
- Sensitive document exfiltration
- Email harvesting (diplomatic communications)
- Screenshot capture of classified material
- Audio recording (government meetings)

### Stage 10: Command & Control (T1071, T1573)
- HTTPS-based C2 communication
- Legitimate web service abuse (cloud storage)
- Encrypted channels
- Geo-restricted C2 responses

### Stage 11: Exfiltration (T1041, T1567)
- Data exfiltration over C2 channel
- Cloud storage services for staging
- Encrypted archives
- Slow exfiltration to avoid detection

## Indicators of Compromise (IOCs)

### Network Indicators

**Geo-Restricted C2 Infrastructure:**
```
(Infrastructure geo-restricted to ASEAN countries)
- C2 servers only respond to connections from target country IP ranges
- Use VPN/proxy from Indonesia/SEA for threat hunting
- Monitor for:
  - Unusual HTTPS connections to unknown cloud services
  - Long-duration encrypted sessions
  - Beaconing patterns (regular intervals)
```

**Traffic Patterns:**
```
- Periodic HTTPS beacons (300-3600 second intervals)
- Small data exfiltration over time (anti-DLP evasion)
- Encrypted archive uploads to cloud storage
- DNS tunneling (potential)
```

### File Indicators

**Malware Characteristics:**
- Mimics legitimate security software names
- Code signed with stolen/fraudulent certificates
- WinRAR exploit delivery (CVE from 2025)
- DLL sideloading payloads

**Suspicious Files to Hunt:**
```
Locations:
%TEMP%
%APPDATA%\Local\
%PROGRAMDATA%
C:\Windows\System32\ (masquerading)

File Types:
- Executables masquerading as security software
- DLL files with security vendor names
- Archives (.rar, .zip) with exploits
- LNK files with hidden payloads
- Office documents with macros/exploits
```

### Host Indicators

- Scheduled tasks with security software names
- Services mimicking AV/EDR vendors
- Registry persistence in Run keys
- Unusual PowerShell execution history
- LSASS access by non-security processes
- Large archive creation in temp directories
- Unusual outbound HTTPS connections

### Behavioral Indicators

- Government document searches by unauthorized processes
- Mass file access during off-hours
- Credential dumping tool execution
- Lateral movement to file servers/domain controllers
- Email mailbox enumeration
- Screenshot capture activity
- Audio recording device access

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Details |
|--------|-----------|----|---------| 
| **Initial Access** | Phishing: Spearphishing Attachment | T1566.001 | Targeted emails with exploits |
| Initial Access | Exploit Public-Facing Application | T1190 | Web app exploitation |
| **Execution** | User Execution | T1204 | Malicious document opening |
| Execution | Command and Scripting Interpreter | T1059 | PowerShell/VBScript |
| **Persistence** | Boot or Logon Autostart Execution | T1547 | Registry run keys |
| Persistence | Scheduled Task/Job | T1053 | Scheduled tasks |
| **Privilege Escalation** | Exploitation for Privilege Escalation | T1068 | Local exploits |
| Privilege Escalation | Valid Accounts | T1078 | Credential reuse |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Code obfuscation |
| Defense Evasion | Masquerading | T1036 | Mimic security software |
| Defense Evasion | Indicator Removal | T1070 | Log deletion |
| **Credential Access** | OS Credential Dumping | T1003 | LSASS dumping |
| Credential Access | Credentials from Password Stores | T1555 | Browser/app credentials |
| **Discovery** | File and Directory Discovery | T1083 | Document searches |
| Discovery | System Information Discovery | T1082 | Host enumeration |
| Discovery | Network Service Discovery | T1046 | Network mapping |
| **Lateral Movement** | Remote Services | T1021 | RDP/SMB abuse |
| **Collection** | Data from Local System | T1005 | Document collection |
| Collection | Email Collection | T1114 | Mailbox harvesting |
| Collection | Screen Capture | T1113 | Screenshot capture |
| **Command & Control** | Application Layer Protocol | T1071 | HTTPS C2 |
| Command & Control | Encrypted Channel | T1573 | Encrypted comms |
| **Exfiltration** | Exfiltration Over C2 Channel | T1041 | Data exfiltration |
| Exfiltration | Exfiltration to Cloud Storage | T1567 | Cloud service abuse |

## Brahma XDR Detection Rules

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rule id="900020" level="14" frequency="1" timeframe="60">
  <description>Amaranth-Dragon APT: WinRAR Exploit Execution</description>
  <match>
    <field name="process.name" operator="regex">winrar\.exe</field>
    <field name="process.command_line" operator="contains">-x</field>
    <field name="file.extension" operator="in">.exe,.dll,.scr</field>
    <field name="parent.process.name" operator="regex">(outlook|chrome|firefox|edge)\.exe</field>
  </match>
  <mitre>
    <tactic>Execution</tactic>
    <technique>T1204.002</technique>
  </mitre>
  <severity>high</severity>
  <action>alert</action>
  <tags>apt,amaranth-dragon,apt41,china</tags>
</rule>

<rule id="900021" level="15" frequency="1" timeframe="60">
  <description>Amaranth-Dragon APT: Masquerading as Security Software</description>
  <match>
    <field name="process.name" operator="regex">(symantec|mcafee|kaspersky|trendmicro|sophos|defender).*\.exe</field>
    <field name="process.path" operator="not_regex">^C:\\Program Files.*</field>
    <field name="file.signed" operator="equals">false</field>
  </match>
  <mitre>
    <tactic>Defense Evasion</tactic>
    <technique>T1036</technique>
  </mitre>
  <severity>critical</severity>
  <action>alert,isolate</action>
  <tags>apt,amaranth-dragon,masquerading</tags>
</rule>

<rule id="900022" level="14" frequency="1" timeframe="300">
  <description>Amaranth-Dragon APT: Government Document Collection</description>
  <match>
    <field name="file.path" operator="regex">.*(rahasia|confidential|secret|classified|intern).*</field>
    <field name="event.action">file_read</field>
    <field name="process.name" operator="not_regex">(winword|excel|outlook|acrobat)\.exe</field>
  </match>
  <mitre>
    <tactic>Collection</tactic>
    <technique>T1005</technique>
  </mitre>
  <severity>high</severity>
  <action>alert</action>
  <tags>apt,amaranth-dragon,collection,indonesia</tags>
</rule>

<rule id="900023" level="15" frequency="1" timeframe="60">
  <description>Amaranth-Dragon APT: LSASS Credential Dumping</description>
  <match>
    <field name="target.process.name">lsass.exe</field>
    <field name="process.granted_access">0x1010</field>
    <field name="process.name" operator="not_regex">(svchost|services|csrss)\.exe</field>
  </match>
  <mitre>
    <tactic>Credential Access</tactic>
    <technique>T1003.001</technique>
  </mitre>
  <severity>critical</severity>
  <action>alert,isolate</action>
  <tags>apt,amaranth-dragon,credential-theft</tags>
</rule>

<rule id="900024" level="13" frequency="5" timeframe="600">
  <description>Amaranth-Dragon APT: Suspicious Geo-Located C2 Beaconing</description>
  <match>
    <field name="destination.geo.country" operator="not_in">ID,TH,PH,VN,MY,SG,MM,KH,LA,BN</field>
    <field name="network.protocol">https</field>
    <field name="source.process.name" operator="regex">.*(update|security|system).*\.exe</field>
  </match>
  <mitre>
    <tactic>Command and Control</tactic>
    <technique>T1071.001</technique>
  </mitre>
  <severity>high</severity>
  <action>alert</action>
  <tags>apt,amaranth-dragon,c2</tags>
</rule>

<rule id="900025" level="14" frequency="1" timeframe="300">
  <description>Amaranth-Dragon APT: Data Staging for Exfiltration</description>
  <match>
    <field name="event.action">file_create</field>
    <field name="file.extension" operator="in">.zip,.rar,.7z</field>
    <field name="file.size" operator="greater_than">10000000</field>
    <field name="file.path" operator="regex">.*(temp|appdata|programdata).*</field>
  </match>
  <mitre>
    <tactic>Collection</tactic>
    <technique>T1560</technique>
  </mitre>
  <severity>high</severity>
  <action>alert</action>
  <tags>apt,amaranth-dragon,exfiltration-prep</tags>
</rule>
```

## Brahma NDR Detection Rules (Suricata Format)

```suricata
# Amaranth-Dragon APT: Geo-Restricted C2 Communication
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"PERISAI Amaranth-Dragon APT Suspected C2 Communication"; flow:established,to_server; tls.sni; pcre:"/^(?!.*(microsoft|google|amazon|cloudflare)).*/"; threshold:type both, track by_src, count 10, seconds 3600; classtype:trojan-activity; sid:9000020; rev:1; metadata:attack_target Client_Endpoint, deployment Internal, severity High, created_at 2026-04-01, malware Amaranth-Dragon, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1071.001;)

# Amaranth-Dragon APT: Large Archive Upload (Data Exfiltration)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI Amaranth-Dragon APT Large Archive Upload"; flow:established,to_server; http.method; content:"POST"; http.content_type; pcre:"/(application\/(zip|x-rar|x-7z))/"; fileext:"zip,rar,7z"; dsize:>5000000; classtype:data-loss; sid:9000021; rev:1; metadata:severity Critical, created_at 2026-04-01, malware Amaranth-Dragon, mitre_technique_id T1041;)

# Amaranth-Dragon APT: Cloud Storage Exfiltration
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"PERISAI Amaranth-Dragon APT Cloud Storage Exfiltration"; flow:established,to_server; tls.sni; pcre:"/(dropbox|mega\.nz|box\.com|drive\.google|onedrive)/"; threshold:type both, track by_src, count 5, seconds 300; filesize:>10000000; classtype:data-loss; sid:9000022; rev:1; metadata:severity High, created_at 2026-04-01, malware Amaranth-Dragon, mitre_technique_id T1567;)

# Amaranth-Dragon APT: Lateral Movement via SMB
alert smb any any -> $HOME_NET 445 (msg:"PERISAI Amaranth-Dragon APT Lateral SMB Admin Share Access"; flow:established,to_server; smb.share; content:"ADMIN$"; smb.command; content:"CREATE"; threshold:type both, track by_src, count 3, seconds 600; classtype:attempted-admin; sid:9000023; rev:1; metadata:severity High, created_at 2026-04-01, malware Amaranth-Dragon, mitre_technique_id T1021.002;)

# Amaranth-Dragon APT: DNS Tunneling Detection
alert dns $HOME_NET any -> any 53 (msg:"PERISAI Amaranth-Dragon APT Potential DNS Tunneling"; dns.query; content:!".id"; content:!".com"; content:!".net"; content:!".org"; pcre:"/^[a-z0-9]{20,}\./"; threshold:type both, track by_src, count 50, seconds 60; classtype:policy-violation; sid:9000024; rev:1; metadata:severity Medium, created_at 2026-04-01, malware Amaranth-Dragon, mitre_technique_id T1071.004;)
```

## Recommendations

### Prevention

1. **Email Security**
   - Advanced email filtering for government domains
   - Sandbox execution of all attachments
   - Block WinRAR/archive execution from email
   - User training on ASEAN-themed phishing

2. **Endpoint Protection**
   - Deploy EDR on all government endpoints
   - Application whitelisting
   - Disable unnecessary archive handling
   - Regular vulnerability patching (prioritize exploited CVEs)

3. **Network Segmentation**
   - Isolate government classified networks
   - Segment law enforcement systems
   - Restrict lateral movement paths
   - Monitor east-west traffic

4. **Access Controls**
   - MFA for all government accounts
   - Privileged access management (PAM)
   - Regular password rotation
   - Principle of least privilege

### Detection

1. **Deploy Detection Rules**
   - Implement Brahma XDR rules immediately
   - Deploy Brahma NDR signatures
   - Tune for government/law enforcement environment

2. **Threat Hunting**
   - Search for masquerading security software
   - Hunt for geo-restricted C2 patterns
   - Look for credential dumping activity
   - Review document access patterns

3. **Monitoring Focus**
   - Sensitive document access
   - Lateral movement attempts
   - Large archive creation
   - Unusual outbound HTTPS connections
   - After-hours activity

### Response

1. **Incident Response Preparation**
   - APT-specific IR playbook
   - Government notification procedures
   - Evidence preservation protocols
   - International coordination (ASEAN CERT)

2. **Intelligence Sharing**
   - Share IOCs with ID-SIRTII
   - Coordinate with ASEAN cybersecurity agencies
   - Report to national intelligence services
   - Engage threat intel vendors

3. **Forensics & Investigation**
   - Memory forensics for implant detection
   - Network forensics for C2 identification
   - Disk forensics for persistence mechanisms
   - Timeline analysis for breach scope

## Indonesia-Specific Considerations

### Risk Assessment

**Threat Level:** 🔴 **CRITICAL**

Indonesia faces HIGH risk from Amaranth-Dragon APT:

1. **Target Profile Match**
   - Indonesian government agencies (target profile)
   - Law enforcement organizations (specific target)
   - ASEAN member state (primary focus)
   - Diplomatic communications (intelligence value)

2. **Geopolitical Context**
   - South China Sea territorial disputes
   - ASEAN-China relations
   - Regional security cooperation
   - Indonesia's strategic importance in SEA

3. **Attack Surface**
   - Large government agency footprint
   - Varying cybersecurity maturity
   - Legacy systems in some agencies
   - Email as primary communication

### Recommended Actions for Indonesian Organizations

1. **Immediate (Within 24 Hours)**
   - Alert all government IT security teams
   - Deploy detection rules to SIEM/XDR
   - Initiate threat hunting for IOCs
   - Review email security posture

2. **Short-term (Within 1 Week)**
   - Conduct security assessment of government agencies
   - Implement email attachment sandboxing
   - Deploy EDR to high-value targets
   - User awareness training (ASEAN-themed phishing)

3. **Medium-term (Within 1 Month)**
   - Network segmentation for classified systems
   - Deploy deception technology (honeypots)
   - Establish threat intelligence sharing
   - Conduct red team exercise (APT simulation)

4. **Long-term (Ongoing)**
   - Continuous threat hunting program
   - Zero Trust architecture implementation
   - Regular security assessments
   - International intel collaboration

### Coordination

- **ID-SIRTII:** National CERT coordination
- **BSSN:** National Cyber and Crypto Agency
- **Ministry of Defense:** Defense sector coordination
- **Police Cyber Crime:** Law enforcement liaison
- **ASEAN CERT:** Regional intelligence sharing

## Intelligence Sources

- Threat intelligence vendor reports (2025-2026)
- ASEAN cybersecurity agency sharing
- Open-source intelligence (OSINT)
- Peris.ai Indra Threat Intelligence Platform
- International cybersecurity partnerships

## Attribution Confidence

**Moderate-High Confidence** - China-linked APT

- Infrastructure overlap with APT41
- Target profile consistent with PRC strategic interests
- TTP alignment with known Chinese APT groups
- Geopolitical context (South China Sea, ASEAN relations)
- Advanced capabilities indicating nation-state resources

---

**Status:** ⚠️ **ACTIVE THREAT**  
**Last Updated:** 2026-04-01 10:00 WIB  
**Next Review:** Weekly (ongoing campaign monitoring)
