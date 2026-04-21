# Device Code Phishing Surge (37x) — OAuth 2.0 Abuse via PhaaS Kits

**Date:** 2026-04-05
**Severity:** CRITICAL
**Source:** BleepingComputer / Push Security (2026-04-04)
**Impact:** Account takeover via OAuth token theft — Microsoft 365, Google, enterprise SaaS

## Summary

Device code phishing attacks abusing OAuth 2.0 Device Authorization Grant flow have surged 37.5x in 2026. At least 11 phishing kits (PhaaS) now offer device code phishing capabilities. Most prominent is **EvilTokens**, followed by VENOM, SHAREFILE, CLURE, LINKID, AUTHOV, DOCUPOLL, FLOW_TOKEN, PAPRIKA, DCSTATUS, and DOLCE. These kits use realistic SaaS-themed lures (DocuSign, SharePoint, Teams, Adobe) and abuse cloud platforms for hosting (GitHub Pages, workers.dev, AWS S3, DigitalOcean).

**How it works:**
1. Attacker sends device authorization request to service provider → receives code
2. Code sent to victim under pretext (e.g., "verify your document")
3. Victim enters code on legitimate login page
4. Attacker's device receives valid access + refresh tokens
5. Full account takeover without password theft

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing | T1566 |
| Initial Access | Valid Accounts | T1078 |
| Persistence | Valid Accounts | T1078 |
| Defense Evasion | Use Alternate Authentication Material | T1550 |
| Credential Access | Forge Identity Credentials | T1606 |
| Command & Control | Application Layer Protocol | T1071 |

## IOCs — PhaaS Kit Infrastructure

| Kit | Hosting | Lure Theme |
|-----|---------|------------|
| EvilTokens | Custom | Microsoft 365, SharePoint |
| VENOM | Custom | Microsoft 365 (AiTM + device code) |
| SHAREFILE | Node.js backend | Citrix ShareFile |
| CLURE | DigitalOcean | SharePoint |
| LINKID | Cloudflare | Microsoft Teams, Adobe |
| AUTHOV | workers.dev | Adobe document sharing |
| DOCUPOLL | GitHub Pages, workers.dev | DocuSign |
| FLOW_TOKEN | workers.dev, Tencent Cloud | HR, DocuSign |
| PAPRIKA | AWS S3 | Office 365, Okta |
| DCSTATUS | Minimal | Microsoft 365 "Secure Access" |
| DOLCE | Microsoft PowerApps | Dolce & Gabbana themed |

## Brahma XDR Detection Rule (XML)

```xml
<Rule id="900103" severity="critical" enabled="true">
  <name>Device Code Phishing — Suspicious OAuth Token Grant</name>
  <description>Detects OAuth device code flow authentication from unusual locations or devices indicating potential device code phishing</description>
  <logic>
    <condition operator="OR">
      <condition_group operator="AND">
        <rule_field name="auth_type" operator="equals">device_code</rule_field>
        <rule_field name="user_agent" operator="not_contains">Mozilla</rule_field>
      </condition_group>
      <condition_group operator="AND">
        <rule_field name="auth_type" operator="equals">device_code</rule_field>
        <rule_field name="ip_geolocation" operator="not_in">allowed_countries</rule_field>
      </condition_group>
      <condition_group operator="AND">
        <rule_field name="auth_type" operator="equals">device_code</rule_field>
        <rule_field name="new_device" operator="equals">true</rule_field>
        <rule_field name="session_duration" operator="greater_than">0</rule_field>
      </condition_group>
    </condition>
  </logic>
  <tags>
    <tag>Phishing</tag>
    <tag>OAuth</tag>
    <tag>DeviceCode</tag>
    <tag>AccountTakeover</tag>
  </tags>
</Rule>
```

## Brahma NDR Detection Rule (Suricata)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING Device Code Phishing Kit — Microsoft Login Clone"; flow:established,to_server; content:"GET"; http_method; content:"login.microsoftonline.com"; nocase; http_header; content:"/device"; http_uri; pcre:"/enter\?code=/U"; metadata:affected_product Web_Browser, attack_target Client_Endpoint; classtype:trojan-activity; sid:2900103; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING Device Code Phishing — Suspicious workers.dev OAuth Flow"; flow:established,to_server; tls_sni; content:"workers.dev"; content:!"cloudflare"; classtype:trojan-activity; sid:2900104; rev:1;)
```

## Recommendations

1. **CRITICAL:** Disable device code flow if not needed — set conditional access policies in Entra ID / Google Workspace
2. Monitor authentication logs for `authenticationProtocol = deviceCode` events
3. Alert on device code auth from new devices, unusual IPs, or geolocations
4. Block known PhaaS infrastructure (workers.dev patterns, GitHub Pages phishing)
5. Train users: never enter codes from emails/chats into Microsoft login pages
6. Implement token protection (token binding) where available
7. Review all OAuth application grants — revoke suspicious consents
8. For Indonesia/SEA orgs: this is especially critical as cloud adoption accelerates — ensure CSPM policies cover OAuth flows

## References

- https://www.bleepingcomputer.com/news/security/device-code-phishing-attacks-surge-37x-as-new-kits-spread-online/
- https://pushsecurity.com/blog/device-code-phishing/
