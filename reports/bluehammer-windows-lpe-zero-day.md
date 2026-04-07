# BlueHammer — Windows Local Privilege Escalation Zero-Day

**Date:** 2026-04-07
**Severity:** 🔴 HIGH
**Status:** UNPATCHED (Zero-Day)
**Source:** BleepingComputer, Will Dormann (Tharros)

## Summary

A disgruntled security researcher operating under the alias "Chaotic Eclipse" (aka Nightmare-Eclipse) publicly released exploit code for an unpatched Windows local privilege escalation vulnerability dubbed **BlueHammer**. The flaw was reported privately to Microsoft but the researcher grew frustrated with MSRC's handling and disclosed the exploit on April 3, 2026.

BlueHammer is a TOCTOU (time-of-check to time-of-use) combined with path confusion vulnerability. It allows a local attacker to access the Security Account Manager (SAM) database, extract password hashes, and escalate to SYSTEM privileges. On Windows Server, it elevates to elevated administrator (UAC-protected).

The exploit is not fully reliable (contains bugs per the researcher), but has been confirmed working by Will Dormann (Tharros). No official patch exists yet.

## Affected Products
- Windows 10/11 (client — full SYSTEM escalation)
- Windows Server (elevated administrator via UAC bypass)

## Technical Details
- **Type:** Local Privilege Escalation (LPE)
- **Mechanism:** TOCTOU + path confusion
- **Impact:** SAM database access → SYSTEM shell
- **Exploit Published:** GitHub (Nightmare-Eclipse)
- **Reliability:** Intermittent — bugs in PoC code

## IOCs
- GitHub repo: Nightmare-Eclipse / BlueHammer exploit
- Blog post: deadeclipse666.blogspot.com

## MITRE ATT&CK TTPs
| Tactic | Technique | ID |
|--------|-----------|-----|
| Privilege Escalation | Access Token Manipulation | T1134 |
| Credential Access | OS Credential Dumping: SAM Database | T1003.001 |
| Execution | Shared Modules | T1129 |

## Brahma XDR Detection Rule (XML)

```xml
<Rule id="900101" name="Suspicious SAM Database Access via TOCTOU Exploit" severity="high">
  <Description>Detects potential BlueHammer exploitation via abnormal SAM file access patterns from non-SYSTEM processes</Description>
  <Platform>Windows</Platform>
  <Conditions>
    <FileAccess>
      <Path condition="contains">\Windows\System32\config\SAM</Path>
      <Process condition="not_in">lsass.exe, svchost.exe, wininit.exe</Process>
    </FileAccess>
  </Conditions>
  <MitreAttack>
    <Technique>T1003.001</Technique>
  </MitreAttack>
</Rule>

<Rule id="900102" name="BlueHammer Exploit Binary Execution" severity="critical">
  <Description>Detects execution of known BlueHammer exploit binary or suspicious TOCTOU-related process behavior</Description>
  <Platform>Windows</Platform>
  <Conditions>
    <ProcessCreate>
      <Image condition="contains">bluehammer</Image>
    </ProcessCreate>
    <Or>
      <ProcessCreate>
        <CommandLine condition="contains">TOCTOU</CommandLine>
        <ParentImage condition="not_in">explorer.exe, cmd.exe, powershell.exe</ParentImage>
      </ProcessCreate>
    </Or>
  </Conditions>
  <MitreAttack>
    <Technique>T1134</Technique>
    <Technique>T1003.001</Technique>
  </MitreAttack>
</Rule>
```

## Brahma NDR Detection Rule (Suricata)

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN BlueHammer Exploit Download Attempt"; flow:established,to_server; http.user_agent; content:"Nightmare-Eclipse"; reference:url,github.com; classtype:trojan-activity; sid:202690101; rev:1;)
```

## Recommendations
1. **Monitor** SAM file access by unusual processes immediately
2. **Block** known exploit repositories at network perimeter
3. **Restrict** local administrator privileges where possible
4. **Enable** LSA Protection (RunAsPPL) to harden SAM access
5. **Watch** for Microsoft out-of-band patch — prioritize deployment
6. **Audit** for unexpected new local admin accounts
