# Interlock Ransomware Campaign (2026)

**Analysis Date:** 2026-04-01  
**Analyst:** Xhavero  
**Threat Level:** 🔴 **CRITICAL**

## Executive Summary

Interlock is an active ransomware operation conducting targeted attacks against organizations using Cisco Secure Firewall Management Center (FMC). The group exploited **CVE-2026-20131** (critical RCE) in zero-day fashion from January 26, 2026, nearly six weeks before public disclosure on March 4, 2026. This demonstrates advanced threat intelligence capabilities and infrastructure targeting focus.

## Campaign Overview

- **Campaign Name:** Interlock Ransomware
- **Active Since:** January 26, 2026 (confirmed exploitation)
- **Target Vector:** Cisco Secure Firewall Management Center
- **Primary Exploit:** CVE-2026-20131 (CVSS 9.8)
- **Geographic Focus:** Global (infrastructure targets)
- **Victims:** Enterprise networks with Cisco FMC deployments

## Threat Actor Profile

### Capabilities
- **Zero-day exploitation:** Pre-disclosure exploit development
- **Infrastructure targeting:** Focus on network security appliances
- **Lateral movement:** Post-compromise movement via firewall infrastructure
- **Dual extortion:** Encryption + data theft

### Motivation
- Financial (ransomware extortion)
- Network disruption
- Data exfiltration for secondary extortion

### Sophistication Level
**HIGH** - Zero-day exploitation, infrastructure focus, operational security

## Attack Chain

### Stage 1: Initial Access (T1190)
- Exploit CVE-2026-20131 on internet-facing Cisco FMC
- Unauthenticated remote code execution via HTTP PUT requests
- No user interaction required

### Stage 2: Execution (T1059)
- Remote code execution on FMC with system privileges
- Deploy custom malware/webshells
- Establish persistence mechanisms

### Stage 3: Persistence (T1136, T1053)
- Create backdoor admin accounts
- Install scheduled tasks/cron jobs
- Modify system configurations

### Stage 4: Privilege Escalation (T1068)
- Already system-level via exploit
- Harvest credentials from FMC
- Access managed firewall credentials

### Stage 5: Defense Evasion (T1070, T1562)
- Clear logs on FMC
- Disable security monitoring
- Tamper with firewall policies

### Stage 6: Credential Access (T1555)
- Extract stored credentials from FMC
- Harvest VPN configs and certificates
- Access firewall management credentials

### Stage 7: Discovery (T1046, T1018)
- Network topology mapping via FMC
- Identify managed firewalls and networks
- Enumerate valuable targets

### Stage 8: Lateral Movement (T1210)
- Move to managed Cisco firewalls
- Pivot to internal networks
- Compromise connected infrastructure

### Stage 9: Collection (T1005, T1039)
- Exfiltrate FMC configurations
- Steal network topology data
- Harvest credentials and certificates

### Stage 10: Command & Control (T1071.001)
- HTTPS-based C2 communication
- Encrypted channels via TLS
- Potential .onion (Tor) communication

### Stage 11: Exfiltration (T1041)
- Exfiltrate collected data to attacker infrastructure
- Dual extortion preparation

### Stage 12: Impact (T1486, T1498)
- Deploy ransomware across network
- Encrypt critical systems
- Network service disruption
- Ransom demand delivery

## Indicators of Compromise (IOCs)

### Network Indicators

**HTTP Exploitation Patterns:**
```
Method: HTTP PUT
Target: https://[cisco-fmc-host]/fmc/api/*
User-Agent: (varies, custom agents used)
Content-Type: application/octet-stream
```

**Suspicious Activity:**
- Unexpected PUT requests to FMC management interfaces
- File uploads to `/opt/cisco/` directories
- Unauthorized certificate installations
- Abnormal outbound HTTPS traffic from FMC

### File System Indicators

**Locations to Monitor:**
```
/opt/cisco/var/
/var/tmp/
/tmp/
/.ssh/
/etc/cron.d/
/etc/systemd/system/
```

**Suspicious Files:**
- New executable files (.bin, .elf, .sh)
- Unexpected Python/Perl scripts
- New SSH keys
- Modified system binaries

### Host Indicators

- Unauthorized admin accounts created
- New scheduled tasks/cron jobs
- Firewall policy modifications
- Disabled security features
- Log clearing activities
- Unexpected process execution

### Ransomware Artifacts

- Encrypted file extensions: (Monitor for patterns)
- Ransom notes in various directories
- Contact info: (TOR sites, encrypted email)
- Wallpaper changes
- Exfiltration staging directories

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Details |
|--------|-----------|----|---------| 
| Initial Access | Exploit Public-Facing Application | T1190 | CVE-2026-20131 exploitation |
| Execution | Command and Scripting Interpreter | T1059 | Remote code execution |
| Persistence | Create Account | T1136 | Backdoor admin accounts |
| Persistence | Scheduled Task/Job | T1053 | Cron/systemd persistence |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | System-level access via RCE |
| Defense Evasion | Indicator Removal | T1070 | Log deletion |
| Defense Evasion | Impair Defenses | T1562 | Disable security monitoring |
| Credential Access | Credentials from Password Stores | T1555 | Extract FMC credentials |
| Discovery | Network Service Discovery | T1046 | Network topology mapping |
| Discovery | Remote System Discovery | T1018 | Identify managed devices |
| Lateral Movement | Exploitation of Remote Services | T1210 | Pivot to managed firewalls |
| Collection | Data from Local System | T1005 | Harvest FMC data |
| Collection | Data from Network Shared Drive | T1039 | Config/credential extraction |
| Command and Control | Web Protocols | T1071.001 | HTTPS C2 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Data exfiltration |
| Impact | Data Encrypted for Impact | T1486 | Ransomware encryption |
| Impact | Network Denial of Service | T1498 | Infrastructure disruption |

## Brahma XDR Detection Rules

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rule id="900010" level="15" frequency="1" timeframe="60">
  <description>Interlock Ransomware: Initial Exploitation via CVE-2026-20131</description>
  <match>
    <field name="destination.port">443</field>
    <field name="http.method">PUT</field>
    <field name="http.url" operator="contains">/fmc/api/</field>
    <field name="source.ip" operator="not_in">$ADMIN_NETWORKS</field>
  </match>
  <mitre>
    <tactic>Initial Access</tactic>
    <technique>T1190</technique>
  </mitre>
  <severity>critical</severity>
  <action>alert,block</action>
  <tags>ransomware,interlock,cve-2026-20131</tags>
</rule>

<rule id="900011" level="14" frequency="1" timeframe="60">
  <description>Interlock Ransomware: Suspicious Account Creation on Network Device</description>
  <match>
    <field name="event.type">user_created</field>
    <field name="user.role" operator="in">admin,root,superuser</field>
    <field name="device.type" operator="in">firewall,router,security_appliance</field>
  </match>
  <mitre>
    <tactic>Persistence</tactic>
    <technique>T1136</technique>
  </mitre>
  <severity>high</severity>
  <action>alert</action>
  <tags>ransomware,interlock,persistence</tags>
</rule>

<rule id="900012" level="13" frequency="1" timeframe="60">
  <description>Interlock Ransomware: Credential Harvesting from Network Device</description>
  <match>
    <field name="event.action">credential_access</field>
    <field name="file.path" operator="regex">.*(passwd|shadow|config|credentials).*</field>
    <field name="process.name" operator="regex">.*(cat|grep|strings|base64).*</field>
  </match>
  <mitre>
    <tactic>Credential Access</tactic>
    <technique>T1555</technique>
  </mitre>
  <severity>high</severity>
  <action>alert</action>
  <tags>ransomware,interlock,credential-theft</tags>
</rule>

<rule id="900013" level="15" frequency="5" timeframe="300">
  <description>Interlock Ransomware: Mass File Encryption Activity</description>
  <match>
    <field name="event.type">file_modified</field>
    <field name="file.extension" operator="regex">.*(encrypted|locked|interlock).*</field>
  </match>
  <mitre>
    <tactic>Impact</tactic>
    <technique>T1486</technique>
  </mitre>
  <severity>critical</severity>
  <action>alert,isolate</action>
  <tags>ransomware,interlock,encryption</tags>
</rule>

<rule id="900014" level="14" frequency="1" timeframe="60">
  <description>Interlock Ransomware: Network Topology Discovery from Firewall</description>
  <match>
    <field name="process.command_line" operator="regex">.*(show|get|list).*(network|route|interface|topology).*</field>
    <field name="process.parent.name" operator="regex">.*(fmc|cisco|firewall).*</field>
  </match>
  <mitre>
    <tactic>Discovery</tactic>
    <technique>T1018</technique>
  </mitre>
  <severity>high</severity>
  <action>alert</action>
  <tags>ransomware,interlock,discovery</tags>
</rule>
```

## Brahma NDR Detection Rules (Suricata Format)

```suricata
# Interlock Ransomware: CVE-2026-20131 Exploitation
alert http $EXTERNAL_NET any -> $HOME_NET 443 (msg:"PERISAI Interlock Ransomware CVE-2026-20131 Exploitation"; flow:established,to_server; http.method; content:"PUT"; http.uri; content:"/fmc/api/"; fast_pattern; reference:cve,2026-20131; classtype:attempted-admin; sid:9000010; rev:1; metadata:attack_target Server, deployment Perimeter, severity Critical, created_at 2026-04-01, malware Interlock, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190;)

# Interlock Ransomware: Suspicious POST Exploitation Traffic
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI Interlock Ransomware Suspicious Outbound from FMC"; flow:established,to_server; http.method; content:"POST"; http.user_agent; content:!"Mozilla/"; content:!"Chrome/"; http.content_type; content:"application/octet-stream"; reference:cve,2026-20131; classtype:trojan-activity; sid:9000011; rev:1; metadata:severity High, created_at 2026-04-01, malware Interlock, mitre_technique_id T1041;)

# Interlock Ransomware: Data Exfiltration Pattern
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"PERISAI Interlock Ransomware Large Data Exfiltration"; flow:established,to_server; threshold:type both, track by_src, count 10, seconds 60; dsize:>100000; reference:cve,2026-20131; classtype:data-loss; sid:9000012; rev:1; metadata:severity Critical, created_at 2026-04-01, malware Interlock, mitre_technique_id T1041;)

# Interlock Ransomware: TOR C2 Communication
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"PERISAI Interlock Ransomware TOR C2 Communication"; flow:established,to_server; tls.sni; content:".onion"; pcre:"/interlock|ransom/i"; classtype:trojan-activity; sid:9000013; rev:1; metadata:severity Critical, created_at 2026-04-01, malware Interlock, mitre_technique_id T1071.001;)

# Interlock Ransomware: Lateral Movement via RDP
alert tcp $HOME_NET any -> $HOME_NET 3389 (msg:"PERISAI Interlock Ransomware Lateral RDP from Compromised Firewall"; flow:to_server,established; content:"|03 00|"; depth:2; threshold:type both, track by_src, count 5, seconds 300; classtype:attempted-user; sid:9000014; rev:1; metadata:severity High, created_at 2026-04-01, malware Interlock, mitre_technique_id T1210;)
```

## Recommendations

### Prevention

1. **Immediate Patching**
   - Apply Cisco CVE-2026-20131 patch to ALL FMC instances
   - Verify patch deployment across entire infrastructure
   - Test firewall functionality post-patch

2. **Network Segmentation**
   - Isolate FMC management interfaces from internet
   - Restrict FMC access to authorized admin networks only
   - Implement VPN/jumpbox for remote FMC management

3. **Access Controls**
   - Enable MFA for all FMC administrative access
   - Implement principle of least privilege
   - Regular credential rotation
   - Disable unused accounts

4. **Security Hardening**
   - Disable unnecessary FMC services
   - Configure strict firewall policies for FMC itself
   - Enable comprehensive logging
   - Regular security configuration audits

### Detection

1. **Deploy Detection Rules**
   - Implement Brahma XDR rules immediately
   - Deploy Brahma NDR signatures
   - Enable anomaly detection on FMC traffic

2. **Monitoring**
   - Continuous monitoring of FMC access logs
   - Alert on unusual PUT/POST requests
   - Monitor for new account creation
   - Track configuration changes
   - Watch for abnormal outbound traffic

3. **Threat Hunting**
   - Search for IOCs from January 26, 2026 onwards
   - Hunt for lateral movement from FMC
   - Review firewall policy changes
   - Check for unauthorized accounts

### Response

1. **Incident Response Plan**
   - Prepare IR playbook for firewall compromise
   - Define escalation procedures
   - Establish communication protocols
   - Identify business continuity options

2. **Backup Strategy**
   - Maintain offline FMC configuration backups
   - Regular backup testing and validation
   - Document restoration procedures
   - Secure backup storage

3. **Recovery Procedures**
   - FMC rebuild process documentation
   - Configuration restoration playbooks
   - Network service restoration priorities
   - Post-incident security validation

## Indonesia/SEA Impact Assessment

**Risk Level:** 🔴 **CRITICAL**

### Regional Context

1. **Widespread Cisco Deployment**
   - Cisco FMC widely used in Indonesian enterprises
   - Government agencies rely on Cisco infrastructure
   - Financial sector heavy Cisco adoption
   - Telecommunications infrastructure exposure

2. **Attack Surface**
   - Many internet-facing FMC instances in region
   - Limited patching cadence in some organizations
   - Potential for widespread compromise

3. **Potential Impact**
   - Critical infrastructure disruption
   - Financial sector ransomware attacks
   - Government network compromise
   - Data breach of sensitive information

### Recommended Actions for Indonesia Organizations

1. **Emergency Patching Campaign**
   - Prioritize all Cisco FMC patching immediately
   - Weekend/off-hours patching if needed
   - Coordinate with Cisco TAC for support

2. **Regional Threat Sharing**
   - Share IOCs with ID-SIRTII
   - Coordinate with sector ISACs
   - Report incidents to authorities

3. **Business Continuity**
   - Test firewall failover procedures
   - Prepare manual network operations
   - Establish alternative security controls

## Attribution & Intel Sources

- **Initial Detection:** Amazon Threat Intelligence (January 26, 2026)
- **Public Disclosure:** Cisco Security Advisory (March 4, 2026)
- **Ongoing Research:** Peris.ai Indra Threat Intelligence
- **Community Sharing:** Security vendor reports

## Timeline

- **2026-01-26:** First Interlock exploitation observed
- **2026-03-04:** CVE-2026-20131 public disclosure by Cisco
- **2026-04-01:** Active campaign ongoing, widespread exploitation

---

**Status:** ⚠️ **ACTIVE CAMPAIGN**  
**Last Updated:** 2026-04-01 10:00 WIB  
**Next Review:** Daily during active exploitation
