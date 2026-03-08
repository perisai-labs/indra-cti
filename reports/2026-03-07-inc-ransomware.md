# INC Ransomware — Active Double-Extortion RaaS Campaign (March 2026)

**Analysis Date:** 2026-03-07  
**Severity:** HIGH  
**Threat Type:** Ransomware-as-a-Service (RaaS), Double Extortion  
**Status:** ACTIVE (Recent victims reported March 2026)

## Executive Summary

INC Ransomware is an active ransomware-as-a-service (RaaS) operation conducting double-extortion attacks globally. The group encrypts victim files, exfiltrates sensitive data before encryption, and threatens public data leaks if ransom demands are not met. INC Ransomware demonstrates operational discipline with structured negotiation portals, pre-encryption impact-maximization techniques (shadow copy deletion, log clearing, service termination), and hybrid encryption. Recent March 2026 victims include law firms, manufacturing companies, and coating services.

## Threat Actor Profile

- **Threat Group:** INC Ransomware (also known as INC Ransom)
- **Type:** Ransomware-as-a-Service (RaaS)
- **Operational Model:** Double extortion (encryption + data leak threats)
- **Active Since:** 2024 (confirmed operational in 2026)
- **Targeting:** Opportunistic (multiple industries, global reach)
- **Leak Site:** Dark web negotiation portal (Tor-based)

## Operational Characteristics

### Attack Lifecycle

1. **Initial Access:**
   - Exploit public-facing vulnerabilities (VPN, RDP, web applications)
   - Phishing campaigns with malicious attachments
   - Compromised credentials (credential stuffing, infostealer logs)
   - Supply chain compromise

2. **Persistence & Privilege Escalation:**
   - Deploy persistence mechanisms (scheduled tasks, services)
   - Escalate privileges to Domain Admin level
   - Disable endpoint protection and monitoring tools

3. **Discovery & Lateral Movement:**
   - Active Directory enumeration
   - Network share discovery
   - Credential dumping (LSASS, SAM)
   - Lateral movement via RDP, PSExec, WMI

4. **Data Exfiltration:**
   - Exfiltrate sensitive data BEFORE encryption (double-extortion model)
   - Common targets: financial records, client data, intellectual property, contracts
   - Upload to attacker-controlled cloud storage or file-sharing services

5. **Impact:**
   - Delete volume shadow copies (`vssadmin delete shadows /all /quiet`)
   - Clear Windows event logs (`wevtutil cl System`, `wevtutil cl Security`, `wevtutil cl Application`)
   - Terminate backup services (Veeam, Acronis, backup agents)
   - Stop user applications and databases (SQL, Exchange, etc.)
   - Enumerate network drives for broader encryption reach
   - Deploy ransomware payload across domain (GPO, PSExec)
   - Encrypt files and append unique extension
   - Drop ransom note directing to Tor negotiation portal

### Pre-Encryption Impact Maximization

INC Ransomware employs sophisticated pre-encryption tactics:

- **Shadow Copy Deletion:** Inhibits file recovery via Windows Volume Shadow Copy Service
- **Log Clearing:** Reduces forensic visibility by wiping Security, System, and Application event logs
- **Service Termination:** Stops backup services (Veeam Backup Service, SQL Server VSS Writer, etc.) and security tools to ensure file accessibility
- **Application Termination:** Kills user processes (outlook.exe, excel.exe, etc.) to unlock files for encryption
- **Network Enumeration:** Discovers accessible network shares (SMB, NFS) to maximize encryption scope

### Encryption & Ransom Demands

- **File Extension:** Appends distinct extension (varies per campaign, e.g., `.INC`, `.incrypted`)
- **Encryption Algorithm:** Hybrid encryption (likely AES + RSA)
- **Ransom Note:** Text file (`README_INC.txt` or similar) with Tor portal link
- **Negotiation:** Victims directed to anonymity network portal for ransom negotiation
- **Ransom Amount:** Varies based on victim size (typically $50K - $5M USD in cryptocurrency)
- **Data Leak Threat:** Stolen data published on leak site if ransom not paid

## Recent March 2026 Victims

Based on dark web monitoring (as of 2026-03-02):

1. **mcfirm.com** (United States) — Law firm
2. **precisioncoating.com** (United States) — Industrial coating services
3. **Martin, Cukjati & Tom, LLP** (United States) — Law firm

## IOCs (Indicators of Compromise)

**File Indicators:**
- Ransom note filenames: `README_INC.txt`, `RECOVERY_INSTRUCTIONS.txt`, `HOW_TO_DECRYPT.txt`
- Encrypted file extensions: `.INC`, `.incrypted`, `.locked`
- Ransomware executables (hash examples from recent campaigns):
  - `SHA256: [REDACTED - sample analysis required]`
  - Common names: `svchost.exe`, `update.exe`, `backup.exe` (masquerading as legitimate processes)

**Registry Indicators:**
- Persistence keys:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\INCService`
  - `HKLM\System\CurrentControlSet\Services\INCBackup`

**Command-Line Indicators:**
```powershell
# Shadow copy deletion
vssadmin.exe delete shadows /all /quiet
wmic.exe shadowcopy delete

# Event log clearing
wevtutil.exe cl System
wevtutil.exe cl Security
wevtutil.exe cl Application

# Service termination
net stop "Veeam Backup Service"
net stop "SQL Server VSS Writer"
net stop "Windows Backup"

# Process termination
taskkill /F /IM outlook.exe
taskkill /F /IM excel.exe
taskkill /F /IM sqlservr.exe
```

**Network Indicators:**
- Exfiltration destinations (update with current infrastructure):
  - File-sharing services: `mega.nz`, `anonfiles.com`, `transfer.sh`
  - Command-and-Control (C2): Tor hidden services (`.onion` domains)
  - Suspicious SMB traffic (internal lateral movement)

**Behavioral Indicators:**
- Bulk file encryption across multiple directories
- Sudden increase in CPU/disk I/O (encryption process)
- Mass file renaming with unknown extensions
- Deletion of all volume shadow copies
- Termination of backup and security services
- Unusual outbound traffic volume (data exfiltration)

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Initial Access | Valid Accounts | T1078 | Compromised credentials |
| Initial Access | Exploit Public-Facing Application | T1190 | Vulnerable VPN/RDP endpoints |
| Initial Access | Phishing | T1566 | Malicious email attachments |
| Execution | Command and Scripting Interpreter | T1059 | PowerShell, cmd.exe for execution |
| Persistence | Create or Modify System Process | T1543 | Windows Service creation |
| Privilege Escalation | Valid Accounts: Domain Accounts | T1078.002 | Domain Admin compromise |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | wevtutil log clearing |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Terminate AV/EDR services |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Credential theft |
| Discovery | Network Share Discovery | T1135 | SMB share enumeration |
| Discovery | System Information Discovery | T1082 | Victim environment reconnaissance |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral movement via SMB |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | RDP lateral movement |
| Collection | Data from Network Shared Drive | T1039 | Collect data from file shares |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | Upload to Mega, Anonfiles, etc. |
| Impact | Data Encrypted for Impact | T1486 | Ransomware encryption |
| Impact | Inhibit System Recovery | T1490 | Shadow copy deletion |
| Impact | Service Stop | T1489 | Terminate backup/security services |

## Brahma XDR Detection Rules (XML Format)

```xml
<rule id="100020" level="15">
  <if_sid>60100</if_sid>
  <field name="process.command_line">vssadmin.*delete.*shadows.*\/all|wmic.*shadowcopy.*delete</field>
  <description>INC Ransomware: Volume shadow copy deletion (inhibit recovery)</description>
  <mitre>
    <id>T1490</id>
    <tactic>Impact</tactic>
    <technique>Inhibit System Recovery</technique>
  </mitre>
</rule>

<rule id="100021" level="14">
  <if_sid>60100</if_sid>
  <field name="process.command_line">wevtutil.*cl.*(System|Security|Application)</field>
  <frequency>2</frequency>
  <timeframe>60</timeframe>
  <description>INC Ransomware: Multiple Windows event logs cleared (defense evasion)</description>
  <mitre>
    <id>T1070.001</id>
    <tactic>Defense Evasion</tactic>
    <technique>Indicator Removal: Clear Windows Event Logs</technique>
  </mitre>
</rule>

<rule id="100022" level="13">
  <if_sid>60100</if_sid>
  <field name="process.command_line">net stop.*(Veeam|SQL Server|Backup|VSS)</field>
  <frequency>3</frequency>
  <timeframe>120</timeframe>
  <description>INC Ransomware: Multiple backup/database services stopped (pre-encryption)</description>
  <mitre>
    <id>T1489</id>
    <tactic>Impact</tactic>
    <technique>Service Stop</technique>
  </mitre>
</rule>

<rule id="100023" level="15">
  <if_sid>60200</if_sid>
  <field name="file.path">.*\\(README_INC|RECOVERY_INSTRUCTIONS|HOW_TO_DECRYPT)\.txt$</field>
  <field name="file.action">created</field>
  <description>INC Ransomware: Ransom note created on filesystem</description>
  <mitre>
    <id>T1486</id>
    <tactic>Impact</tactic>
    <technique>Data Encrypted for Impact</technique>
  </mitre>
</rule>

<rule id="100024" level="15">
  <if_sid>60200</if_sid>
  <field name="file.extension">\.(INC|incrypted|locked)$</field>
  <frequency>50</frequency>
  <timeframe>60</timeframe>
  <description>INC Ransomware: Mass file encryption detected (50+ files encrypted)</description>
  <mitre>
    <id>T1486</id>
    <tactic>Impact</tactic>
    <technique>Data Encrypted for Impact</technique>
  </mitre>
</rule>

<rule id="100025" level="14">
  <if_sid>60300</if_sid>
  <field name="network.destination">mega\.nz|anonfiles\.com|transfer\.sh|.*\.onion</field>
  <field name="network.bytes_sent">>10485760</field>
  <description>INC Ransomware: Large data exfiltration to file-sharing service (potential pre-encryption exfil)</description>
  <mitre>
    <id>T1567.002</id>
    <tactic>Exfiltration</tactic>
    <technique>Exfiltration to Cloud Storage</technique>
  </mitre>
</rule>

<rule id="100026" level="13">
  <if_sid>60100</if_sid>
  <field name="process.command_line">taskkill.*\/F.*\/IM.*(outlook|excel|word|sqlservr|mysqld)</field>
  <frequency>5</frequency>
  <timeframe>60</timeframe>
  <description>INC Ransomware: Multiple user/database processes terminated (pre-encryption file unlocking)</description>
  <mitre>
    <id>T1489</id>
    <tactic>Impact</tactic>
    <technique>Service Stop</technique>
  </mitre>
</rule>
```

## Brahma NDR Detection Rules (Suricata Format)

```suricata
# INC Ransomware: Lateral movement via SMB (credential dumping/file access)
alert smb $HOME_NET any -> $HOME_NET 445 (msg:"INC Ransomware: Suspicious SMB lateral movement pattern"; flow:established,to_server; smb.command; content:"|73 6d 62|"; threshold:type both, track by_src, count 10, seconds 300; classtype:trojan-activity; sid:2026020; rev:1; metadata:attack_target Server, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1021.002, mitre_technique_name Remote_Services_SMB;)

# INC Ransomware: Data exfiltration to Mega.nz
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"INC Ransomware: Data exfiltration to Mega.nz (cloud storage)"; flow:established,to_server; tls.sni; content:"mega.nz"; nocase; threshold:type both, track by_src, count 5, seconds 600; classtype:policy-violation; sid:2026021; rev:1; metadata:attack_target Server, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1567.002, mitre_technique_name Exfiltration_to_Cloud_Storage;)

# INC Ransomware: Data exfiltration to Anonfiles
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"INC Ransomware: Data exfiltration to Anonfiles"; flow:established,to_server; tls.sni; content:"anonfiles.com"; nocase; threshold:type both, track by_src, count 3, seconds 300; classtype:policy-violation; sid:2026022; rev:1; metadata:attack_target Server, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1567.002, mitre_technique_name Exfiltration_to_Cloud_Storage;)

# INC Ransomware: Tor traffic (C2 communication or ransom negotiation)
alert tcp $HOME_NET any -> $EXTERNAL_NET 9001:9150 (msg:"INC Ransomware: Potential Tor traffic (C2/ransom negotiation)"; flow:established,to_server; flags:S,12; threshold:type both, track by_src, count 3, seconds 60; classtype:trojan-activity; sid:2026023; rev:1; metadata:attack_target Server, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control;)

# INC Ransomware: Unusual RDP lateral movement
alert tcp $HOME_NET any -> $HOME_NET 3389 (msg:"INC Ransomware: Rapid RDP lateral movement (potential ransomware spread)"; flow:established,to_server; threshold:type both, track by_src, count 5, seconds 300; classtype:trojan-activity; sid:2026024; rev:1; metadata:attack_target Server, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1021.001, mitre_technique_name Remote_Services_RDP;)

# INC Ransomware: Large outbound file transfer (exfiltration)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"INC Ransomware: Large data exfiltration detected"; flow:established,to_server; dsize:>1000000; threshold:type both, track by_src, count 10, seconds 600; classtype:policy-violation; sid:2026025; rev:1; metadata:attack_target Server, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration;)
```

## Recommendations

### Prevention
1. **Multi-Factor Authentication (MFA):**
   - Enforce MFA on all VPN, RDP, and admin accounts
   - Use phishing-resistant MFA (FIDO2, hardware tokens)

2. **Patch Management:**
   - Maintain up-to-date patch levels for VPN appliances, RDP gateways, public-facing apps
   - Subscribe to vendor security advisories (Fortinet, Palo Alto, Cisco, Microsoft)

3. **Network Segmentation:**
   - Isolate critical assets (domain controllers, backups, databases)
   - Implement firewall rules restricting lateral movement

4. **Endpoint Protection:**
   - Deploy Brahma EDR with behavioral detection
   - Enable tamper protection to prevent service termination

5. **Email Security:**
   - Deploy anti-phishing solutions (DMARC, SPF, DKIM)
   - Train users on phishing awareness

### Detection & Monitoring
1. **Deploy Brahma XDR rules** for endpoint detection
2. **Deploy Brahma NDR rules** for network-level detection
3. **Monitor for:**
   - Shadow copy deletion events
   - Mass event log clearing
   - Unusual service terminations (backup, AV, databases)
   - Large outbound data transfers
   - Tor traffic on corporate networks
   - Lateral RDP/SMB movement patterns

4. **SIEM Correlation:**
   - Correlate: Shadow copy deletion + log clearing + service stops = HIGH PRIORITY ALERT
   - Alert on rapid file modifications across multiple directories

### Backup & Recovery
1. **3-2-1 Backup Strategy:**
   - 3 copies of data
   - 2 different media types
   - 1 offsite/air-gapped backup

2. **Immutable Backups:**
   - Use backup solutions with immutability features (Veeam Immutability, AWS S3 Object Lock)
   - Store backups offline or in separate security domain

3. **Test Restores:**
   - Quarterly backup restore testing
   - Document recovery procedures and RTO/RPO metrics

### Incident Response Plan
1. **If INC Ransomware detected:**
   - **Isolate immediately:** Disconnect affected systems from network
   - **Disable compromised accounts:** Reset all domain admin passwords
   - **Preserve evidence:** Capture memory dumps, disk images, network traffic
   - **Assess scope:** Identify all encrypted systems and exfiltrated data

2. **Containment:**
   - Block attacker IPs/domains at perimeter firewall
   - Revoke VPN/RDP access for compromised accounts
   - Scan for persistence mechanisms (scheduled tasks, services, startup items)

3. **Eradication:**
   - Remove ransomware artifacts (executables, ransom notes)
   - Rebuild compromised systems from clean backups
   - Patch vulnerabilities exploited for initial access

4. **Recovery:**
   - Restore encrypted files from immutable backups
   - **DO NOT PAY RANSOM** (no guarantee of decryption, funds terrorism/crime)
   - Re-provision systems with hardened configurations

5. **Post-Incident:**
   - Conduct root cause analysis
   - Update detection rules based on attack TTPs
   - Share IOCs with threat intel community
   - Report to law enforcement (FBI IC3, local cybercrime unit)

## YARA Rules

```yara
rule INC_Ransomware_Generic {
    meta:
        description = "Detects INC Ransomware based on common strings and behaviors"
        author = "Xhavero"
        date = "2026-03-07"
        threat_level = "HIGH"
        tlp = "WHITE"
    
    strings:
        $ransom_note1 = "README_INC.txt" ascii wide
        $ransom_note2 = "RECOVERY_INSTRUCTIONS.txt" ascii wide
        $ransom_note3 = "HOW_TO_DECRYPT.txt" ascii wide
        $extension1 = ".INC" ascii wide
        $extension2 = ".incrypted" ascii wide
        $vss_delete = "vssadmin delete shadows" ascii wide nocase
        $log_clear = "wevtutil cl" ascii wide nocase
        $service_stop = "net stop" ascii wide nocase
        $tor_string = ".onion" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        (
            (2 of ($ransom_note*)) or
            (1 of ($extension*) and 2 of ($vss_delete, $log_clear, $service_stop)) or
            (3 of them)
        )
}
```

## Threat Intelligence Summary

**Threat Level:** HIGH  
**Operational Status:** ACTIVE (March 2026)  
**Impact:** Data encryption + public data leak (double extortion)  
**Targeting:** Opportunistic (global, multiple industries)  
**Ransom Range:** $50K - $5M USD  
**Decryption Without Payment:** UNLIKELY (no known decryptors)  
**Recommendation:** PREVENTION CRITICAL — Deploy Brahma XDR/NDR rules, enforce MFA, maintain immutable backups

## References

- [CYFIRMA Weekly Intelligence Report (March 5, 2026)](https://www.cyfirma.com/news/weekly-intelligence-report-05-march-2026/)
- [Dark Web Informer: Ransomware Attack Update (March 2, 2026)](https://darkwebinformer.com/ransomware-attack-update-march-2nd-2026/)
- [Unit42: Threat Brief - March 2026 Iran Escalation](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- MalwareBazaar (sample repository)
- Internal threat hunting findings

---

**Author:** Xhavero (L3 Blue Team Specialist)  
**Date:** 2026-03-07 20:00 WIB  
**Skill Version:** 1.0
