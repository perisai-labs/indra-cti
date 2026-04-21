# Device Code Phishing Surge — 37x Increase in 2026

**Date:** 2026-04-04
**Severity:** 🔴 HIGH
**Threat Type:** OAuth 2.0 Device Code Phishing (PhaaS)
**Key Kit:** EvilTokens (plus 10+ competing PhaaS platforms)

## Summary

Device code phishing attacks abusing the OAuth 2.0 Device Authorization Grant flow have surged **37.5x** in early 2026. At least 11 phishing-as-a-service (PhaaS) kits are now democratizing this technique for low-skilled cybercriminals. The most prominent, EvilTokens, offers ready-made device code phishing campaigns. The attack works by: (1) attacker sends device authorization request to provider, (2) receives a code, (3) tricks victim into entering code on legitimate login page, (4) attacker obtains valid access/refresh tokens — effectively bypassing MFA.

## Active PhaaS Kits

| Kit | Hosting | Lure Theme | Notes |
|-----|---------|------------|-------|
| **EvilTokens** | Various | Microsoft 365, SaaS | Most prominent, democratized the technique |
| **VENOM** | Unknown | Microsoft 365 | EvilTokens clone + AiTM capabilities |
| **SHAREFILE** | Node-based | Citrix ShareFile | Simulates file sharing flows |
| **CLURE** | DigitalOcean | SharePoint | Rotating API endpoints, anti-bot gate |
| **LINKID** | Cloudflare | MS Teams, Adobe | Self-hosted APIs |
| **AUTHOV** | workers.dev | Adobe docs | Popup-based device code entry |
| **DOCUPOLL** | GitHub Pages, workers.dev | DocuSign | Injected replicas of real pages |
| **FLOW_TOKEN** | workers.dev | HR, DocuSign | Tencent Cloud backend |
| **PAPRIKA** | AWS S3 | Office 365 | Fake Okta footer |
| **DCSTATUS** | Unknown | Microsoft 365 | Minimal kit, generic lures |
| **DOLCE** | PowerApps | Dolce & Gabbana | Likely red-team/one-off |

## Why This Matters for Indonesia/SEA

- Cloud-heavy organizations across SEA (especially those using Microsoft 365) are prime targets
- PhaaS kits lower barrier to entry — local cybercriminal groups can adopt quickly
- Indonesia's rapid digital transformation = large attack surface with OAuth-enabled SaaS
- Device code flow is rarely monitored by SOC teams in the region

## MITRE ATT&CK TTPs

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing | T1566 |
| Initial Access | Valid Accounts | T1078 |
| Credential Access | Steal Application Access Token | T1528 |
| Defense Evasion | Use Alternate Authentication Material | T1550.001 |
| Persistence | Create Account | T1136 |
| Collection | Data from Cloud Storage | T1530 |

## Brahma XDR Detection Rules (XML)

```xml
<Rule id="900111" severity="high">
  <name>OAUTH_DEVICE_CODE_AUTH_FROM_ANOMALOUS_LOCATION</name>
  <description>Detects OAuth device code authentication from unusual geographic location or IP</description>
  <pattern>
    <event>auth_success</event>
    <auth_type>device_code</auth_type>
    <condition>
      <geo_anomaly>true</geo_anomaly>
      <or>
        <new_ip>true</new_ip>
        <new_asn>true</new_asn>
      </or>
    </condition>
  </pattern>
  <action>alert</action>
  <confidence>high</confidence>
</Rule>

<Rule id="900112" severity="medium">
  <name>OAUTH_DEVICE_CODE_FLOW_RARE_CLIENT</name>
  <description>Detects device code flow usage from rarely-seen or suspicious OAuth client applications</description>
  <pattern>
    <event>oauth_device_code_start</event>
    <client_app>NOT in approved_oauth_clients</client_app>
  </pattern>
  <action>alert</action>
</Rule>

<Rule id="900113" severity="critical">
  <name>DEVICE_CODE_TOKEN_GRANT_WITHIN_SHORT_WINDOW</name>
  <description>Detects device code token granted within seconds of code generation — indicates automated/phishing flow</description>
  <pattern>
    <event>oauth_token_grant</event>
    <auth_type>device_code</auth_type>
    <condition>
      <time_delta code_generation="to" token_grant="less_than">60s</time_delta>
    </condition>
  </pattern>
  <action>alert</action>
</Rule>

<Rule id="900114" severity="high">
  <name>SUSPICIOUS_OAUTH_TOKEN_USAGE_POST_DEVICE_CODE</name>
  <description>Detects suspicious activity following device code authentication — mail forwarding rules, mass download, privilege escalation</description>
  <pattern>
    <event>oauth_token_use</event>
    <auth_type>device_code</auth_type>
    <followed_by>
      <or>
        <event>mail_rule_create</event>
        <event>mass_download</event>
        <event>admin_role_assign</event>
      </or>
      <within>30m</within>
    </followed_by>
  </pattern>
  <action>alert</action>
  <confidence>high</confidence>
</Rule>
```

## Brahma NDR Detection Rules (Suricata)

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING Device Code Phishing EvilTokens Kit Activity"; flow:established,to_server; http.host; content:"login.microsoftonline.com"; http.uri; content:"/common/oauth2/devicecode"; classtype:successful-user; sid:2026111; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING Possible Device Code Phishing via workers.dev Hosted Kit"; flow:established,to_server; tls.sni; content:".workers.dev"; reference:url,pushsecurity.com/blog/device-code-phishing/; classtype:trojan-activity; sid:2026112; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING Device Code Phishing DOCUPOLL Kit GitHub Pages"; flow:established,to_server; http.host; content:"github.io"; http.uri; content:"docusign"; nocase; classtype:trojan-activity; sid:2026113; rev:1;)
```

## Recommendations

1. **Conditional Access:** Disable Device Authorization Grant flow for all users who don't need it. In Azure AD/Entra: Conditional Access → Block device code flow for non-essential users.
2. **Log Monitoring:** Monitor `SignInLogs` and `AzureActivity` for device code authentication events (`authenticationProtocol = deviceCode`). Alert on anomalies.
3. **Token Monitoring:** Track OAuth token usage post-device-code-auth for suspicious patterns (mail forwarding, OneDrive mass downloads, admin escalation).
4. **User Training:** Educate users to NEVER enter codes from emails/chat messages on login pages.
5. **Phishing Simulation:** Include device code phishing scenarios in quarterly phishing simulations.
6. **Indonesia-specific:** Kerentanan tinggi pada organisasi yang baru migrasi ke cloud — prioritaskan audit OAuth policies.

## References

- https://www.bleepingcomputer.com/news/security/device-code-phishing-attacks-surge-37x-as-new-kits-spread-online/
- https://pushsecurity.com/blog/device-code-phishing/
- https://www.bleepingcomputer.com/news/security/new-eviltokens-service-fuels-microsoft-device-code-phishing-attacks/
