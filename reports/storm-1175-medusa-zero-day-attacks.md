# Storm-1175 / Medusa Ransomware — Zero-Day Exploit Campaign

**Date:** 2026-04-07
**Severity:** 🔴 CRITICAL
**Threat Actor:** Storm-1175 (China-based, financially motivated)
**Associated Malware:** Medusa Ransomware
**Source:** Microsoft Security Blog, BleepingComputer

## Summary

Microsoft reports that **Storm-1175**, a China-based financially motivated threat group deploying **Medusa ransomware**, has escalated to deploying **zero-day and n-day exploits** in high-velocity attacks. The group weaponizes new vulnerabilities within a day of discovery and in some cases exploits them **a full week before patches are released**.

Storm-1175 rapidly moves from initial access to data exfiltration and ransomware deployment — often within 24 hours. Recent campaigns have heavily impacted **healthcare**, education, professional services, and finance sectors in **Australia, UK, and the US**.

In October 2025, Storm-1175 exploited **CVE-2025-10035** (GoAnywhere MFT, CVSS 10.0) as a zero-day for over a week before patching. More recently, they exploited **CVE-2026-23760** (SmarterMail auth bypass) as a zero-day.

## Exploited CVEs (16+ across 10 products)
| CVE | Product | Type |
|-----|---------|------|
| CVE-2025-10035 | GoAnywhere MFT | RCE (CVSS 10.0) |
| CVE-2026-23760 | SmarterMail | Auth Bypass |
| CVE-2023-21529 | Microsoft Exchange | RCE |
| CVE-2023-27351, CVE-2023-27350 | PaperCut | RCE |
| CVE-2023-46805, CVE-2024-21887 | Ivanti Connect Secure | Auth Bypass + RCE |
| CVE-2024-1709, CVE-2024-1708 | ConnectWise ScreenConnect | Auth Bypass |
| CVE-2024-27198, CVE-2024-27199 | JetBrains TeamCity | Auth Bypass |
| CVE-2024-57726/7/8 | SimpleHelp | RCE |
| CVE-2025-31161 | CrushFTP | Auth Bypass |
| CVE-2025-52691 | SmarterMail | Auth Bypass |
| CVE-2026-1731 | BeyondTrust | Auth Bypass |

## Attack Chain
1. **Initial Access:** Exploit web-facing vulnerable services (MFT, email servers, VPN)
2. **Persistence:** Create new user accounts, deploy RMM tools
3. **Credential Access:** Steal credentials, dump LSASS
4. **Defense Evasion:** Disable security software
5. **Exfiltration:** Rapid data staging and exfiltration
6. **Impact:** Deploy Medusa ransomware (often within 24h)

## MITRE ATT&CK TTPs
| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Create Account | T1136 |
| Credential Access | OS Credential Dumping | T1003 |
| Defense Evasion | Disable or Modify Tools | T1562.001 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Impact | Data Encrypted for Impact | T1486 |

## Brahma XDR Detection Rules (XML)

```xml
<Rule id="900103" name="Storm-1175 Medusa Ransomware Indicator - Rapid Account Creation" severity="critical">
  <Description>Detects rapid creation of new user accounts followed by RMM tool deployment, characteristic of Storm-1175</Description>
  <Platform>Windows</Platform>
  <Conditions>
    <Sequence timeWindow="3600">
      <Event>
        <ID>4720</ID>
        <Description>User account created</Description>
      </Event>
      <ProcessCreate>
        <Image condition="contains_any">anydesk, teamviewer, screenconnect, splashtop, meshagent, simpleshelp</Image>
      </ProcessCreate>
    </Sequence>
  </Conditions>
  <MitreAttack>
    <Technique>T1136.001</Technique>
    <Technique>T1219</Technique>
  </MitreAttack>
</Rule>

<Rule id="900104" name="Medusa Ransomware File Encryption Activity" severity="critical">
  <Description>Detects mass file encryption patterns consistent with Medusa ransomware deployment</Description>
  <Platform>Windows</Platform>
  <Conditions>
    <FileCreate>
      <Extension condition="equals">.medusa</Extension>
    </FileCreate>
    <Or>
      <Sequence timeWindow="60">
        <FileCreate count="greater_than">100</FileCreate>
        <FileDelete count="greater_than">50</FileDelete>
      </Sequence>
    </Or>
  </Conditions>
  <MitreAttack>
    <Technique>T1486</Technique>
  </MitreAttack>
</Rule>

<Rule id="900105" name="Storm-1175 Known Exploit Pattern - Web Shell Upload" severity="high">
  <Description>Detects web shell upload patterns targeting GoAnywhere, TeamCity, PaperCut, ScreenConnect</Description>
  <Platform>Windows</Platform>
  <Conditions>
    <FileCreate>
      <Path condition="contains_any">/goanywhere/, /teamcity/, /papercut/, /screenconnect/</Path>
      <Extension condition="contains_any">.jsp, .aspx, .ashx, .php</Extension>
    </FileCreate>
  </Conditions>
  <MitreAttack>
    <Technique>T1505.003</Technique>
    <Technique>T1190</Technique>
  </MitreAttack>
</Rule>
```

## Brahma NDR Detection Rules (Suricata)

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT GoAnywhere MFT CVE-2025-10035 Exploit Attempt"; flow:established,to_server; http.uri; content:"/goanywhere/"; content:"license"; nocase; http.method; content:"POST"; reference:cve,2025-10035; classtype:web-application-attack; sid:202690103; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT SmarterMail CVE-2026-23760 Auth Bypass Attempt"; flow:established,to_server; http.uri; content:"/api/v1/"; content:"auth"; nocase; http.header; content:"SmarterMail"; classtype:web-application-attack; sid:202690104; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Medusa Ransomware C2 Beacon"; flow:established,to_server; content:"medusa"; nocase; dsize:<200; classtype:trojan-activity; sid:202690105; rev:1;)
```

## Recommendations
1. **IMMEDIATE:** Patch all listed CVEs — prioritize GoAnywhere MFT, SmarterMail, CrushFTP, BeyondTrust
2. **Audit** all internet-facing services for exposure
3. **Monitor** for rapid account creation + RMM deployment (key Storm-1175 pattern)
4. **Segment** networks — limit lateral movement after perimeter breach
5. **Healthcare/education orgs** at highest risk — prioritize defensive measures
6. **Indonesia/SEA context:** Check for exposed GoAnywhere, TeamCity, SmarterMail instances — common in APAC enterprises
7. **Backup verification** — ensure offline backups are tested and current
