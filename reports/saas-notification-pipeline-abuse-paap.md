# SaaS Notification Pipeline Abuse (PaaP) — GitHub & Jira Phishing Campaign

**Date:** 2026-04-07
**Severity:** 🟠 HIGH
**Campaign Type:** Phishing / Credential Harvesting
**Source:** Cisco Talos (published April 7, 2026)

## Summary

Cisco Talos has identified a growing campaign abusing **SaaS notification pipelines** (Platform-as-a-Proxy / PaaP) from **GitHub** and **Jira (Atlassian)** to deliver phishing and credential harvesting emails. Because emails originate from legitimate platform infrastructure, they pass SPF, DKIM, and DMARC authentication — making them nearly impossible to block with traditional email security.

### GitHub Vector
- Attackers create repositories and push commits with malicious content in commit messages
- Commit messages contain social engineering hooks (fake billing, support numbers)
- Emails originate from `noreply@github.com` via `out-28.smtp.github.com` (192.30.252.211)
- DKIM signature: `d=github.com` — verified legitimate
- **1.20%** of all GitHub notification traffic contained "invoice" lures over 5-day observation
- **Peak (Feb 17, 2026):** 2.89% of daily GitHub email sample was abuse-related

### Jira Vector
- Attackers abuse Jira Service Management "Customer Invite" feature
- Set malicious project names and welcome messages
- Jira wraps attacker input in cryptographically signed, trusted email templates
- Exploits pre-conditioned trust in Atlassian notifications

## Strategic Significance
- Bypasses all standard email authentication (SPF/DKIM/DMARC)
- Exploits "automation fatigue" — users trust system-generated alerts
- Credential harvesting is often precursor to further attacks (ransomware, BEC)
- **Relevant to Indonesia/SEA:** High GitHub/Jira adoption in tech sector

## IOCs
- Sender: noreply@github.com (legitimate but abused)
- Sender: Atlassian/Jira Service Desk notifications (legitimate but abused)
- SMTP: out-28.smtp.github.com (192.30.252.211)
- Pattern: "invoice" lure in commit notification subject lines

## MITRE ATT&CK TTPs
| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing: Spearphishing via Service | T1566.003 |
| Resource Development | Compromise Infrastructure | T1584 |
| Credential Access | Phishing for Credentials | T1111 |

## Brahma XDR Detection Rule (XML)

```xml
<Rule id="900107" name="SaaS Notification Pipeline Abuse - GitHub Invoice Lure" severity="high">
  <Description>Detects phishing emails delivered via GitHub notification pipeline containing financial lures</Description>
  <Platform>Email</Platform>
  <Conditions>
    <EmailReceive>
      <Sender condition="contains">noreply@github.com</Sender>
      <Subject condition="contains_any">invoice, payment, billing, refund, charge, subscription, cancel</Subject>
      <Body condition="contains_any">call, phone, support, cancel, refund, http://, https://</Body>
    </EmailReceive>
  </Conditions>
  <MitreAttack>
    <Technique>T1566.003</Technique>
    <Technique>T1111</Technique>
  </MitreAttack>
</Rule>

<Rule id="900108" name="SaaS Notification Pipeline Abuse - Jira Invite Phishing" severity="high">
  <Description>Detects phishing via Jira Service Management invite with suspicious project names or external recipients</Description>
  <Platform>Email</Platform>
  <Conditions>
    <EmailReceive>
      <Sender condition="contains">atlassian.com</Sender>
      <Subject condition="contains_any">invite, project, service desk, welcome</Subject>
      <Body condition="contains_any">password, credential, verify, confirm, click here</Body>
    </EmailReceive>
  </Conditions>
  <MitreAttack>
    <Technique>T1566.003</Technique>
  </MitreAttack>
</Rule>
```

## Brahma NDR Detection Rules (Suricata)

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING Potential GitHub Notification Abuse - Financial Lure Click"; flow:established,to_server; http.host; content:"github.com"; http.uri; content:"/notifications"; http.referer; content:"invoice|7c|payment|7c|billing|7c|refund"; nocase; classtype:trojan-activity; sid:202690108; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING Potential Jira Invite Phishing - Credential Harvest"; flow:established,to_server; http.host; content:"atlassian.net"; http.uri; content:"/secure"; content:"credential|7c|password|7c|verify"; nocase; classtype:trojan-activity; sid:202690109; rev:1;)
```

## Recommendations
1. **Zero-Trust for SaaS notifications:** Treat all GitHub/Jira notification emails as untrusted until verified against internal SaaS directory
2. **API-level monitoring:** Ingest GitHub/Atlassian audit logs into SIEM — detect anomalous repo creation, mass invites, naming convention deviations
3. **Semantic profiling:** Flag notifications whose content (billing, invoice) doesn't match platform purpose (code collaboration, project management)
4. **Out-of-band verification:** For high-risk interactions, require users to verify via platform portal directly (not email links)
5. **User awareness training:** Specifically train on SaaS notification phishing — not just traditional email phishing
6. **Automated takedown:** Report malicious repos/projects to GitHub Trust & Safety / Atlassian immediately
7. **Email gateway hardening:** Implement behavioral analysis beyond authentication-based filtering
