# APT41 (Earth Baku) - Indonesia & Southeast Asia Cyberespionage Campaign

**Date:** 2026-04-02  
**Analyst:** Xhavero  
**Severity:** 🔴 CRITICAL  
**Status:** Active Campaign (Ongoing)  

---

## Executive Summary

APT41 (also tracked as Earth Baku, Earth Longzhi, Double Dragon) is a Chinese state-sponsored APT group conducting sustained cyberespionage operations across Southeast Asia, including **Indonesia**. Active since at least 2012, APT41 targets government agencies, military, energy sectors, and critical infrastructure in Indonesia, Malaysia, Philippines, Taiwan, and Vietnam. 

The group deploys sophisticated custom malware toolsets including **StealthVector**, **StealthMutant**, **ScrambleCross** backdoor, and customized Cobalt Strike loaders. Recent campaigns (2025-2026) demonstrate advanced operational security with strict geographic enforcement and infrastructure-dependent attack vectors.

**Regional Impact:** Direct threat to Indonesian government, law enforcement, and critical infrastructure.

---

## Technical Details

### Threat Actor Profile
- **Primary Name:** APT41
- **Aliases:** Earth Baku, Earth Longzhi, Double Dragon, Winnti (overlaps)
- **Attribution:** China (state-sponsored)
- **Active Since:** 2012
- **Motivation:** Cyber espionage + financial (dual-purpose)
- **Target Sectors:**
  - Government & law enforcement
  - Military & defense
  - Energy & utilities
  - Telecommunications
  - Technology companies

### Southeast Asia Campaign (2025-2026)
**Indonesian Targeting:**
- Trend Micro identified APT41/Earth Baku cyberespionage campaign hitting Indonesian firms
- Focus on infrastructure-dependent organizations
- Part of broader Indo-Pacific government/military targeting
- Overlaps with campaigns in Philippines (military), Vietnam (energy), Taiwan

**Related APT Operations:**
- **Amaranth-Dragon:** Untracked actor linked to APT41, targeting ASEAN government/law enforcement (Indonesia, Cambodia, Thailand, Laos, Singapore, Philippines) since March 2025
- **Geographic Enforcement:** Attack infrastructure rejects connections from non-target countries (advanced OpSec)

---

## Malware Arsenal

### Custom Toolset (150+ unique malware variants)

| Malware | Type | Function | Campaign |
|---------|------|----------|----------|
| **StealthVector** | Shellcode Loader | Initial payload loading | Indo-Pacific 2025-2026 |
| **StealthMutant** | Shellcode Loader | Secondary loading stage | Indo-Pacific 2025-2026 |
| **ScrambleCross** | Backdoor | Persistence & C2 | Indo-Pacific 2025-2026 |
| **Cobalt Strike (custom)** | C2 Framework | Command & control, multi-protocol | SEA Gov't/Military |
| **EAGLEDOOR** | Backdoor | DLL side-loading persistence | Asia-Pacific |
| **HIGHNOON** | Backdoor | Shared with Winnti group | Various campaigns |
| **China Chopper** | Webshell | Post-exploitation (ProxyLogon) | Exchange servers |
| **MBR Rootkit** | Rootkit/Bootkit | Deep persistence & evasion | Advanced intrusions |

### Cobalt Strike Customization
- Custom loaders using DLL side-loading techniques
- Multi-protocol C2 channels:
  - DNS tunneling
  - HTTP/HTTPS
  - TCP direct
  - **Telegram Bot API** for command relay
- Data exfiltration via `curl.exe` with Telegram integration

---

## Indicators of Compromise (IOCs)

### Network IOCs
**C2 Infrastructure (Historical - update with current intel):**
- Multi-protocol C2 domains (DNS, HTTP, TCP)
- Telegram Bot API usage for covert channels
- Infrastructure enforces geographic access control

**Detection Patterns:**
- Unusual DNS queries to recently registered domains
- Telegram Bot API traffic from servers/endpoints
- `curl.exe` POST requests to Telegram API endpoints
- Cobalt Strike beacon patterns (customized)

### File/Hash IOCs
**Malware Families (specific hashes require current threat intel feeds):**
- StealthVector/StealthMutant loaders
- ScrambleCross backdoor
- Custom Cobalt Strike beacons
- China Chopper webshell variants
- EAGLEDOOR backdoor
- MBR rootkit components

**File Artifacts:**
- DLL side-loading components
- Scheduled tasks with `InstallUtil.exe`
- Webshells in Exchange/IIS directories
- Malicious .chm files (phishing)

### Behavioral IOCs
- SQL injection attempts leading to file upload
- ProxyLogon exploitation (CVE-2021-26855)
- Scheduled task creation via `InstallUtil.exe`
- Abnormal `curl.exe` usage for data exfil
- GPU/memory-intensive processes (cryptocurrency mining secondary activity)

---

## MITRE ATT&CK TTPs

### Initial Access
| Technique | ID | Description |
|-----------|-----|-------------|
| Spearphishing Attachment | T1566.001 | Malicious .chm files, document exploits |
| Spearphishing Link | T1566.002 | Phishing emails with malicious links |
| Exploit Public-Facing Application | T1190 | ProxyLogon (CVE-2021-26855), SQL injection |
| Valid Accounts | T1078 | Compromised credentials for access |

### Execution
| Technique | ID | Description |
|-----------|-----|-------------|
| User Execution | T1204 | .chm file execution, malicious documents |
| Command and Scripting Interpreter | T1059 | PowerShell, cmd.exe for payload delivery |
| Scheduled Task/Job | T1053 | InstallUtil.exe via scheduled tasks |

### Persistence
| Technique | ID | Description |
|-----------|-----|-------------|
| Server Software Component: Web Shell | T1505.003 | China Chopper webshell deployment |
| Boot or Logon Autostart Execution | T1547 | MBR rootkit, DLL side-loading |
| Scheduled Task/Job | T1053 | Persistent scheduled tasks |
| Create or Modify System Process | T1543 | Bootkit installation |

### Defense Evasion
| Technique | ID | Description |
|-----------|-----|-------------|
| Rootkit | T1014 | MBR rootkit for stealth |
| DLL Side-Loading | T1574.002 | EAGLEDOOR loading technique |
| Obfuscated Files or Information | T1027 | Custom loaders, encrypted payloads |
| Valid Accounts | T1078 | Legitimate credential usage |

### Command and Control
| Technique | ID | Description |
|-----------|-----|-------------|
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP/HTTPS C2 |
| Application Layer Protocol: DNS | T1071.004 | DNS tunneling |
| Protocol Tunneling | T1572 | TCP tunneling |
| Web Service | T1102 | Telegram Bot API for C2 |
| Multi-hop Proxy | T1090.003 | Infrastructure chaining |

### Exfiltration
| Technique | ID | Description |
|-----------|-----|-------------|
| Exfiltration Over C2 Channel | T1041 | Data exfil via Cobalt Strike |
| Exfiltration Over Web Service | T1567 | curl.exe to Telegram |

---

## Brahma XDR Detection Rules

```xml
<!-- APT41: StealthVector/StealthMutant Loader Detection -->
<rule id="900200" level="12">
  <if_sid>60000</if_sid>
  <field name="file.name" type="pcre2">(?i)\.dll$</field>
  <field name="file.hash.sha256" type="pcre2">STEALTHVECTOR_HASH_PATTERN</field>
  <description>APT41 StealthVector/StealthMutant loader detected</description>
  <mitre>
    <id>T1204</id>
    <id>T1059</id>
  </mitre>
</rule>

<!-- APT41: China Chopper Webshell Detection -->
<rule id="900201" level="13">
  <if_sid>60000</if_sid>
  <field name="file.path" type="pcre2">(?i)wwwroot|inetpub|exchange</field>
  <field name="file.extension">^aspx?$</field>
  <field name="file.size">^[1-9]\d{2,3}$</field>
  <description>APT41 China Chopper webshell deployment suspected</description>
  <mitre>
    <id>T1505.003</id>
    <id>T1190</id>
  </mitre>
</rule>

<!-- APT41: Cobalt Strike Custom Beacon -->
<rule id="900202" level="12">
  <if_sid>60000</if_sid>
  <field name="network.protocol">dns|http|https|tcp</field>
  <field name="destination.domain" type="pcre2">KNOWN_APT41_C2_PATTERN</field>
  <description>APT41 Cobalt Strike C2 communication detected</description>
  <mitre>
    <id>T1071</id>
    <id>T1090</id>
  </mitre>
</rule>

<!-- APT41: Telegram Bot API Exfiltration -->
<rule id="900203" level="13">
  <if_sid>60000</if_sid>
  <field name="process.name">curl\.exe|powershell\.exe</field>
  <field name="process.command_line" type="pcre2">api\.telegram\.org|sendDocument|sendMessage</field>
  <description>APT41 data exfiltration via Telegram Bot API</description>
  <mitre>
    <id>T1567</id>
    <id>T1102</id>
  </mitre>
</rule>

<!-- APT41: ProxyLogon Exploitation -->
<rule id="900204" level="14">
  <if_sid>60000</if_sid>
  <field name="event.module">exchange</field>
  <field name="event.action">autodiscover</field>
  <field name="url.path" type="pcre2">/autodiscover/autodiscover\.json</field>
  <field name="http.response.status_code">^302$</field>
  <description>APT41 ProxyLogon (CVE-2021-26855) exploitation attempt</description>
  <mitre>
    <id>T1190</id>
    <id>T1505.003</id>
  </mitre>
</rule>

<!-- APT41: DLL Side-Loading (EAGLEDOOR) -->
<rule id="900205" level="12">
  <if_sid>60000</if_sid>
  <field name="event.type">library_load</field>
  <field name="file.name" type="pcre2">(?i)version\.dll|dbghelp\.dll|msvcr\d+\.dll</field>
  <field name="process.name" type="pcre2">(?i)^((?!system32|syswow64).)*$</field>
  <description>APT41 DLL side-loading technique (EAGLEDOOR)</description>
  <mitre>
    <id>T1574.002</id>
  </mitre>
</rule>

<!-- APT41: InstallUtil Scheduled Task -->
<rule id="900206" level="11">
  <if_sid>60000</if_sid>
  <field name="process.name">schtasks\.exe</field>
  <field name="process.command_line">InstallUtil\.exe</field>
  <description>APT41 persistence via InstallUtil scheduled task</description>
  <mitre>
    <id>T1053</id>
  </mitre>
</rule>

<!-- APT41: SQL Injection File Upload -->
<rule id="900207" level="13">
  <if_sid>60000</if_sid>
  <field name="url.query" type="pcre2">(?i)union.*select|exec.*xp_cmdshell|0x</field>
  <field name="http.request.method">POST</field>
  <field name="file.extension">aspx?|jsp|php</field>
  <description>APT41 SQL injection leading to file upload</description>
  <mitre>
    <id>T1190</id>
    <id>T1505.003</id>
  </mitre>
</rule>
```

---

## Brahma NDR Detection Rules

```suricata
# APT41: Cobalt Strike DNS Tunneling
alert dns any any -> any any (msg:"PERISAI APT APT41 Cobalt Strike DNS Tunneling"; dns_query; content:"|00|"; pcre:"/^[a-f0-9]{32,}\./i"; reference:url,attack.mitre.org/groups/G0096; classtype:trojan-activity; sid:9000200; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02, attack_target Client_Endpoint, deployment Perimeter;)

# APT41: Telegram Bot API C2
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI APT APT41 Telegram Bot API C2 Communication"; flow:established,to_server; content:"POST"; http_method; content:"/bot"; http_uri; depth:4; content:"api.telegram.org"; http_host; reference:url,attack.mitre.org/groups/G0096; classtype:trojan-activity; sid:9000201; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02, former_category MALWARE;)

# APT41: China Chopper Webshell Activity
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"PERISAI APT APT41 China Chopper Webshell Command Execution"; flow:established,to_server; content:"POST"; http_method; content:".asp"; http_uri; content:"eval"; http_client_body; content:"base64_decode"; distance:0; reference:url,attack.mitre.org/groups/G0096; classtype:web-application-attack; sid:9000202; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# APT41: ProxyLogon Exploitation
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 443 (msg:"PERISAI APT APT41 ProxyLogon CVE-2021-26855 Exploitation"; flow:established,to_server; content:"/autodiscover/autodiscover.json"; http_uri; content:"Email=autodiscover/autodiscover.json"; http_header; pcre:"/X-AnonResource-Backend|X-BEResource/i"; reference:cve,2021-26855; reference:url,attack.mitre.org/groups/G0096; classtype:attempted-admin; sid:9000203; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# APT41: Cobalt Strike HTTP Beacon
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI APT APT41 Cobalt Strike HTTP Beacon"; flow:established,to_server; content:"GET"; http_method; urilen:>100; http_header; content:!"Referer|3a|"; content:!"Accept-Language|3a|"; http_user_agent; content:"Mozilla/5.0"; content:"compatible"; reference:url,attack.mitre.org/groups/G0096; classtype:trojan-activity; sid:9000204; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# APT41: Data Exfiltration via curl to Telegram
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI APT APT41 Data Exfiltration via Telegram"; flow:established,to_server; content:"POST"; http_method; content:"/sendDocument"; http_uri; content:"api.telegram.org"; http_host; content:"multipart/form-data"; http_header; filestore:request,force; reference:url,attack.mitre.org/groups/G0096; classtype:trojan-activity; sid:9000205; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# APT41: SQL Injection Attempt
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"PERISAI APT APT41 SQL Injection File Upload Attempt"; flow:established,to_server; content:"POST"; http_method; pcre:"/union.+select|exec.+xp_cmdshell|0x[0-9a-f]{10,}/i"; content:".asp"; distance:0; reference:url,attack.mitre.org/groups/G0096; classtype:web-application-attack; sid:9000206; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# APT41: ScrambleCross Backdoor C2
alert tcp $HOME_NET any -> $EXTERNAL_NET $HIGH_PORTS (msg:"PERISAI APT APT41 ScrambleCross Backdoor C2 Traffic"; flow:established,to_server; dsize:>100; content:"|00 00 00|"; depth:3; detection_filter:track by_src, count 5, seconds 300; reference:url,attack.mitre.org/groups/G0096; classtype:trojan-activity; sid:9000207; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)
```

---

## Recommendations

### Immediate Actions (P0)
1. **Threat Hunt for APT41 Indicators:**
   - Deploy Brahma XDR rules (900200-900207)
   - Deploy Brahma NDR rules (9000200-9000207)
   - Search for China Chopper webshells in IIS/Exchange directories
   - Audit scheduled tasks for `InstallUtil.exe` references
   - Check for unauthorized DLL files in application directories

2. **Patch ProxyLogon Vulnerability:**
   - Ensure CVE-2021-26855 is patched on all Exchange servers
   - Review Exchange server logs for exploitation attempts

3. **Network Isolation:**
   - Block Telegram Bot API domains if not business-required:
     - `api.telegram.org`
     - `*.t.me`
   - Implement egress filtering for suspicious DNS queries

### Detection & Monitoring (P1)
1. **Enable Enhanced Logging:**
   - Windows Security Event Logging (4688, 4698, 7045)
   - IIS/Exchange logs with full request logging
   - PowerShell script block logging
   - DNS query logging

2. **SIEM Correlation Rules:**
   - ProxyLogon exploitation + webshell deployment
   - `curl.exe` + Telegram API access
   - Abnormal DLL loads from non-system directories
   - Scheduled task creation with unusual parent processes

3. **Network Monitoring:**
   - Monitor for long-duration DNS queries (tunneling)
   - Track HTTP POST requests to Telegram API
   - Detect Cobalt Strike beacon patterns (HTTP malleable C2)

4. **Endpoint Monitoring:**
   - Monitor file creation in web directories
   - Track process injection and DLL loading
   - Alert on rootkit installation attempts

### Hardening (P2)
1. **Email Security:**
   - Block .chm attachments at email gateway
   - Implement advanced phishing protection (attachment sandboxing)
   - Train users on APT-style spearphishing

2. **Application Hardening:**
   - Disable SQL Server `xp_cmdshell` if not required
   - Implement Web Application Firewall (WAF) for public-facing apps
   - Restrict `InstallUtil.exe` execution via AppLocker/WDAC

3. **Network Segmentation:**
   - Isolate critical government/military networks
   - Implement micro-segmentation for sensitive systems
   - Restrict lateral movement paths

4. **Privilege Management:**
   - Audit and reduce administrative privileges
   - Implement PAM (Privileged Access Management)
   - Enable MFA for all administrative accounts

### Threat Intelligence Integration (P2)
1. **IOC Feeds:**
   - Subscribe to APT41 threat intelligence feeds
   - Integrate with Brahma Indra threat intelligence platform
   - Monitor MISP communities for APT41 indicators

2. **Regional Collaboration:**
   - Share threat intelligence with ASEAN CERTs
   - Participate in Indonesia-CERT threat sharing programs
   - Monitor regional threat reports (Trend Micro, Recorded Future)

3. **Continuous Monitoring:**
   - Daily review of APT41 campaign updates
   - Weekly threat hunt exercises
   - Monthly tabletop exercises for APT scenarios

### Indonesia-Specific Recommendations
1. **Critical Infrastructure Protection:**
   - Priority: Government, law enforcement, energy sectors
   - Implement air-gapped networks for sensitive operations
   - Deploy behavioral analytics for anomaly detection

2. **Regional Threat Awareness:**
   - Monitor campaigns targeting neighboring countries (Philippines, Malaysia, Vietnam)
   - Share intelligence with regional partners
   - Anticipate spillover from regional operations

3. **Capacity Building:**
   - Train SOC analysts on APT41 TTPs
   - Conduct purple team exercises simulating APT41 attacks
   - Develop incident response playbooks for state-sponsored threats

---

## References

- Trend Micro: APT41/Earth Baku Indo-Pacific Cyberespionage
- Check Point Research: Amaranth-Dragon APT Campaign
- MITRE ATT&CK: G0096 (APT41)
- Mandiant: APT41 Threat Profile
- Indonesia-CERT Advisories

---

## Threat Intelligence Summary

**Attribution:** China (state-sponsored, Ministry of State Security linkage suspected)  
**Confidence:** High  
**Target Profile:** Indonesian government, law enforcement, critical infrastructure  
**Campaign Status:** Active and ongoing (2025-2026)  
**Sophistication:** Advanced (custom malware, geographic enforcement, multi-protocol C2)  
**Risk Level:** CRITICAL for Indonesian organizations in targeted sectors  

**Regional Context:**
- Part of broader China cyber operations in South China Sea disputes
- Likely targeting intelligence on Indonesian government policies
- Energy sector targeting may relate to infrastructure/resource intelligence
- Law enforcement targeting suggests counter-intelligence operations

**Recommended Response Level:** Tier 1 (highest priority threat monitoring)

---

**Last Updated:** 2026-04-02 10:00 WIB  
**Next Review:** Daily monitoring, weekly detailed assessment  
**Analyst Contact:** Xhavero (L3 Blue Team)
