# UNC1069 Axios npm Supply Chain Attack

**Date:** 2026-04-04
**Severity:** 🔴 CRITICAL
**Threat Actor:** UNC1069 (North Korea-nexus, financially motivated, active since 2018)
**Malware:** WAVESHAPER.V2 RAT (cross-platform: macOS, Windows, Linux)

## Summary

UNC1069 compromised the Axios npm package (1.14.1, 0.30.4) via a sophisticated social engineering campaign targeting the lead maintainer Jason Saayman. Attackers impersonated a legitimate company, created a convincing Slack workspace with fake employee profiles and staged activity, then lured the maintainer into a Microsoft Teams meeting where a fake "RTC connection error" prompted installation of a malicious update — actually a RAT. The RAT was used to steal npm credentials and publish malicious Axios versions containing a dependency (`plain-crypto-js`) that deployed cross-platform malware. Malicious versions were live for ~3 hours.

## Attack Chain

1. **Reconnaissance** — Identified open-source maintainers with publish access
2. **Social Engineering** — Cloned legitimate company branding, created fake Slack workspace with staged channels and fake employee profiles (including fake OSS maintainers)
3. **Initial Access** — Invited target to fake Teams meeting, displayed fake error, tricked into installing malicious "Teams update" (WAVESHAPER.V2 RAT)
4. **Credential Theft** — RAT harvested npm credentials, bypassed MFA via session token theft
5. **Supply Chain Injection** — Published malicious Axios versions with `plain-crypto-js` dependency
6. **Impact** — Cross-platform RAT deployed on any system installing the malicious versions

## IOCs

### Malicious Packages
- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js` (malicious dependency)

### Infrastructure
- Fake Slack workspace (impersonating legitimate company)
- Fake Microsoft Teams meeting infrastructure

### Malware
- WAVESHAPER.V2 RAT (updated version of WAVESHAPER)
- Fake "Teams update" binary

## MITRE ATT&CK TTPs

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Gather Victim Identity Information | T1589 |
| Resource Development | Compromise Accounts | T1586 |
| Resource Development | Compromise Infrastructure | T1584 |
| Initial Access | Supply Chain Compromise | T1195.002 |
| Initial Access | Phishing | T1566 |
| Execution | User Execution | T1204 |
| Defense Evasion | Masquerading | T1036 |
| Credential Access | Credentials from Password Stores | T1555 |
| Credential Access | Steal Web Session Cookie | T1539 |
| Command and Control | Remote Access Software | T1219 |

## Brahma XDR Detection Rules (XML)

```xml
<Rule id="900101" severity="critical">
  <name>SUSPICIOUS_NPM_PACKAGE_INSTALL_AXIOS_COMPROMISED</name>
  <description>Detects installation of known compromised Axios versions (1.14.1, 0.30.4) or plain-crypto-js dependency</description>
  <pattern>
    <event>process_exec</event>
    <command>npm install axios@1.14.1|npm install axios@0.30.4|plain-crypto-js</command>
  </pattern>
  <action>alert</action>
  <confidence>high</confidence>
</Rule>

<Rule id="900102" severity="critical">
  <name>TEAMS_FAKE_UPDATE_EXECUTION</name>
  <description>Detects execution of fake Microsoft Teams update binary from non-standard paths</description>
  <pattern>
    <event>process_exec</event>
    <path>~/.local/share/Teams/update*|/tmp/teams*update*|/tmp/*.pkg</path>
  </pattern>
  <condition>
    <not>
      <path>/Applications/Microsoft Teams.app/*|/Program Files/Microsoft Teams/*|/opt/teams/*</path>
    </not>
  </condition>
  <action>alert</action>
</Rule>

<Rule id="900103" severity="high">
  <name>WAVESHAPER_V2_RAT_NETWORK_ACTIVITY</name>
  <description>Detects WAVESHAPER.V2 RAT C2 beaconing patterns</description>
  <pattern>
    <event>network_connect</event>
    <behavior>periodic_beacon</behavior>
    <protocol>https</protocol>
    <interval>30-120s</interval>
  </pattern>
  <action>alert</action>
</Rule>

<Rule id="900104" severity="high">
  <name>NPM_CREDENTIAL_ACCESS_VIA_SESSION_TOKEN</name>
  <description>Detects access to .npmrc files or npm token extraction from unexpected processes</description>
  <pattern>
    <event>file_access</event>
    <path>.npmrc</path>
    <process>NOT node,npm,npx</process>
  </pattern>
  <action>alert</action>
</Rule>
```

## Brahma NDR Detection Rules (Suricata)

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN UNC1069 WAVESHAPER.V2 RAT Check-in"; flow:established,to_server; http.method; content:"POST"; http.header; content:"Content-Type|3a| application/json"; http.user_agent; content:"axios/"; distance:0; classtype:trojan-activity; sid:2026101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SUPPLY_CHAIN Compromised Axios npm package fetching malicious dependency plain-crypto-js"; flow:established,to_server; http.host; content:"registry.npmjs.org"; http.uri; content:"plain-crypto-js"; classtype:trojan-activity; sid:2026102; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Possible WAVESHAPER C2 TLS Beacon Detected"; flow:established,to_server; tls.sni; content:".workers.dev"; reference:url,cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package; classtype:trojan-activity; sid:2026103; rev:1;)
```

## Recommendations

1. **Immediate:** Audit all systems for `axios@1.14.1`, `axios@0.30.4`, or `plain-crypto-js` in node_modules. If found, isolate and rebuild.
2. **Credential Rotation:** Rotate ALL credentials and session tokens on any system that installed affected versions.
3. **Supply Chain Hardening:** Implement npm package pinning, lockfile integrity checks, and CI/CD pipeline scanning.
4. **Social Engineering Awareness:** Train developers on sophisticated social engineering tactics targeting OSS maintainers.
5. **MFA + Session Controls:** Implement conditional access policies with token binding. Session tokens alone are insufficient.
6. **Monitor:** Watch for WAVESHAPER.V2 indicators across endpoints and network.

## References

- https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/
- https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package
- https://github.com/axios/axios/issues/10636
