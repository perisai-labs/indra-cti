# Qilin & Warlock Ransomware — BYOVD EDR Bypass Campaign

## Metadata
- **Date:** 2026-04-07
- **Severity:** 🔴 CRITICAL
- **Threat Actors:** Qilin Ransomware Group, Warlock Ransomware Group
- **Sources:** Cisco Talos, Trend Micro
- **Reference:** https://thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html

## Summary
Qilin and Warlock ransomware operations have been observed using the **Bring Your Own Vulnerable Driver (BYOVD)** technique to disable **300+ EDR/security tools** on compromised hosts. Qilin deploys a malicious DLL named `msimg32.dll` that leverages vulnerable legitimate kernel drivers to gain kernel-level access and terminate security processes.

This technique allows ransomware operators to blind security monitoring before encrypting files, significantly reducing detection and response time.

## Attack Chain
1. Initial access (phishing, RDP exploitation, or purchased access)
2. Deploy vulnerable legitimate driver (e.g., RTCore64.sys, DBUtil_2_3.sys, or similar)
3. Load malicious `msimg32.dll` via DLL side-loading
4. Exploit driver to gain kernel-level privileges
5. Terminate 300+ known EDR/AV processes
6. Deploy ransomware payload
7. Encrypt files and exfiltrate data for double extortion

## TTPs (MITRE ATT&CK)
| Tactic | Technique | ID |
|--------|-----------|-----|
| Defense Evasion | Indicator Blocking | T1562.001 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Defense Evasion | Rootkit | T1014 |
| Execution | Shared Modules | T1129 |
| Impact | Data Encrypted for Impact | T1486 |
| Impact | Data Transfer Size Limits | T1567 |

## IOCs
- Malicious DLL: `msimg32.dll` (side-loaded)
- Known BYOVD drivers: RTCore64.sys, DBUtil_2_3.sys, AsIO.sys, capcom.sys
- Ransomware families: Qilin (.qilin extension), Warlock

## Brahma XDR Detection Rule (XML)
```xml
<Rule id="900102" severity="critical">
  <name>BYOVD EDR Disable - Qilin/Warlock Ransomware Pattern</name>
  <description>Detects BYOVD technique used by Qilin/Warlock ransomware to disable EDR tools via vulnerable kernel drivers</description>
  <logic>
    <or>
      <and>
        <event source="windows" category="process">
          <action>CREATE</action>
          <target_image matches="regex">(?i).*\\msimg32\.dll$</target_image>
          <not>
            <target_signed_by>microsoft</target_signed_by>
          </not>
        </event>
        <event source="windows" category="driver">
          <action>LOAD</action>
          <within_minutes>10</within_minutes>
          <image matches="regex">(?i).*(RTCore64|DBUtil_2_3|AsIO|capcom|PROCEXP|ene\.sys|WinRing0).*\.sys$</image>
        </event>
      </and>
      <and>
        <event source="windows" category="process">
          <action>TERMINATE</action>
          <target_image matches="regex">(?i).*(edr|defender|crowdstrike|sentinel|carbonblack|virus|security|protect).*\.exe$</target_image>
        </event>
        <event source="windows" category="process">
          <action>TERMINATE</action>
          <count>5</count>
          <within_minutes>5</within_minutes>
        </event>
      </and>
    </or>
  </logic>
  <tags>ransomware,byovd,qilin,warlock,edr-bypass,t1562.001,t1068</tags>
</Rule>
```

## Brahma NDR Rule (Suricata)
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Known Vulnerable Driver Download - BYOVD Pattern"; flow:established,to_server; content:"RTCore64"; http_uri; nocase; reference:url,thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html; classtype:trojan-activity; sid:2026902; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Known Vulnerable Driver Download - DBUtil BYOVD"; flow:established,to_server; content:"DBUtil"; http_uri; nocase; classtype:trojan-activity; sid:2026903; rev:1;)
```

## Recommendations
1. **Block** known vulnerable drivers using Microsoft's vulnerable driver blocklist (HVCI)
2. **Enable** Microsoft Vulnerable Driver Blocklist (Windows Security > Device Security)
3. **Monitor** for driver loads from non-standard paths
4. **Deploy** kernel-mode tamper protection on EDR agents
5. **Hunt** for `msimg32.dll` in application directories (not in system32)
6. **Implement** driver signature enforcement policies
7. **Backup** critical data with offline/immutable copies
8. **Review** EDR console for mass process termination events
