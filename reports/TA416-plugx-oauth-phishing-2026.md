# TA416 (China-Linked) — PlugX & OAuth Phishing Campaign Targeting European Governments

**Date:** 2026-04-05
**Severity:** HIGH
**Source:** The Hacker News (2026-04-03)
**Aliases:** DarkPeony, RedDelta, Red Lich, SmugX, UNC6384, Vertigo Panda

## Summary

China-aligned threat actor TA416 resumed targeting European government and diplomatic organizations since mid-2025 after a 2-year hiatus in the region. Campaign uses PlugX malware and OAuth-based phishing techniques. Multiple infection vectors observed including social engineering with legitimate OAuth flows.

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Spearphishing Attachment | T1566.001 |
| Initial Access | Spearphishing Link | T1566.002 |
| Execution | User Execution | T1204 |
| Persistence | Registry Run Keys | T1547.001 |
| Defense Evasion | Obfuscated Files | T1027 |
| Command & Control | Application Layer Protocol | T1071 |
| Command & Control | Encrypted Channel | T1573 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## IOCs

- **Malware Family:** PlugX (aka Korplug, TDTESS, REBAL)
- **Attack Vector:** OAuth-based phishing + malicious attachments
- **Target Sector:** Government, Diplomatic organizations (Europe)
- **Attribution:** China-nexus APT (TA416 cluster)

## Brahma XDR Detection Rule (XML)

```xml
<Rule id="900101" severity="high" enabled="true">
  <name>TA416 PlugX DLL Side-Loading Activity</name>
  <description>Detects potential PlugX malware loading via DLL side-loading technique commonly used by TA416</description>
  <logic>
    <condition operator="OR">
      <rule_field name="process_name" operator="equals">svchost.exe</rule_field>
      <rule_field name="parent_process" operator="contains">Adobe\Reader</rule_field>
      <rule_field name="loaded_dll" operator="contains">oci.dll</rule_field>
    </condition>
    <condition operator="AND">
      <rule_field name="network_connection" operator="exists">true</rule_field>
      <rule_field name="process_path" operator="not_contains">System32</rule_field>
    </condition>
  </logic>
  <tags>
    <tag>APT</tag>
    <tag>TA416</tag>
    <tag>PlugX</tag>
    <tag>China-Nexus</tag>
  </tags>
</Rule>
```

## Brahma NDR Detection Rule (Suricata)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET APT TA416 PlugX C2 Beacon Pattern"; flow:established,to_server; content:"POST"; http_method; content:"User-Agent|3a| Mozilla/4.0"; http_header; content:!"Accept"; http_header; pcre:"/^[A-Za-z0-9+\/]{40,}={0,2}$/P"; reference:url,thehackernews.com; classtype:trojan-activity; sid:2900101; rev:1;)
```

## Recommendations

1. Monitor for DLL side-loading anomalies on endpoints
2. Review OAuth application grants in enterprise environments — revoke suspicious consents
3. Block known TA416 C2 infrastructure at perimeter
4. Implement conditional access policies for OAuth flows
5. Brief government/diplomatic staff on spearphishing TTPs
6. Hunt for PlugX IOCs across endpoint telemetry

## References

- https://thehackernews.com/2026/04/china-linked-ta416-targets-european.html
