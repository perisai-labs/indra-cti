# DPRK Social Engineering Campaign — $285M Drift Exchange Hack

## Metadata
- **Threat Actor:** DPRK (North Korea) — Lazarus Group / APT38
- **Campaign:** 6-month social engineering → Drift DEX hack
- **Severity:** CRITICAL (Financial Impact: $285M)
- **Target:** Solana-based DEX (Drift)
- **Date of Breach:** 2026-04-01
- **Campaign Start:** Fall 2025
- **Type:** Cryptocurrency theft via social engineering

## Summary
The Democratic People's Republic of Korea (DPRK) conducted a meticulously planned 6-month social engineering campaign targeting Drift, a Solana-based decentralized exchange. Beginning in Fall 2025, the operation culminated on April 1, 2026, with the theft of $285 million. The attack was described as a "six months in the making" operation involving extensive reconnaissance and targeted manipulation of key personnel.

## Attack Pattern (DPRK Standard Playbook)
1. **Reconnaissance (Months):** Identify key employees, their roles, interests, and social circles
2. **Initial Contact:** Fake recruiter, investor, or collaborator personas on LinkedIn/Twitter/Telegram
3. **Relationship Building:** Months of seemingly legitimate professional interaction
4. **Payload Delivery:** Malicious document, code review request, or "skill test" containing malware
5. **Lateral Movement:** Compromise internal systems, locate crypto wallets/keys
6. **Exfiltration:** Drain funds from hot wallets and smart contracts

## IOCs
*Campaign-specific IOCs pending detailed disclosure. Known DPRK indicators:*
- Fake recruiter/investor profiles on professional networks
- Malicious documents masquerading as coding tests or investment proposals
- C2 infrastructure typically hosted on compromised or bulletproof hosting
- Crypto wallet addresses used for fund laundering (TBD from Drift disclosure)

## MITRE ATT&CK TTPs
| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Social Media Information | T1593.001 |
| Initial Access | Phishing (Spearphishing Attachment) | T1566.001 |
| Initial Access | Trusted Relationship | T1199 |
| Execution | User Execution | T1204 |
| Defense Evasion | Masquerading | T1036 |
| Credential Access | Credentials from Password Stores | T1555 |
| Lateral Movement | Remote Services | T1021 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## Brahma XDR Detection Rule (XML)
```xml
<rule id="900105" level="high">
  <category>process</category>
  <if_sid>100100</if_sid>
  <description>DPRK-style payload execution from social engineering lure document</description>
  <match>macro|vba|powershell|cmd.exe|wscript|cscript</match>
  <program_name>WINWORD|EXCEL|POWERPNT|AcroRd32</program_name>
  <extra_data>scheduled_task|registry_run|persistence</extra_data>
  <mitre>
    <id>T1566.001</id>
    <id>T1204</id>
    <id>T1036</id>
  </mitre>
  <group>apt,dprk,lazarus,social-engineering,crypto-theft</group>
</rule>

<rule id="900106" level="critical">
  <category>authentication</category>
  <if_sid>600100</if_sid>
  <description>Anomalous crypto wallet/key access from unusual source</description>
  <match>wallet|private.key|seed.phrase|mnemonic</match>
  <program_name>node|python|curl|wget</program_name>
  <mitre>
    <id>T1555</id>
    <id>T1041</id>
  </mitre>
  <group>apt,dprk,crypto-theft,critical</group>
</rule>
```

## Brahma NDR Detection Rule (Suricata)
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET APT DPRK Lazarus C2 beacon pattern - crypto wallet exfiltration";
  flow:established,to_server;
  http.method; content:"POST";
  http.header; content:"Content-Type|3a| application/json";
  content:"wallet";
  content:"private";
  classtype:trojan-activity;
  sid:20263564;
  rev:1;
  metadata:created_at 2026_04_06, mitre_tactic_id TA0010, tag APT38;
)
```

## Recommendations
1. **Crypto/Web3 orgs:** Implement strict social media hygiene for all employees
2. Mandatory security awareness training on DPRK social engineering tactics
3. Never open documents/code from unknown or newly contacted "recruiters/investors"
4. Sandbox all incoming documents before opening
5. Use hardware wallets with multi-sig for large fund storage
6. Monitor for long-term social engineering patterns — fake profiles active for months
7. Implement air-gapped key management for production wallet operations
8. Conduct regular social engineering penetration tests

## References
- https://thehackernews.com/2026/04/285-million-drift-hack-traced-to-six.html
- Drift official post-mortem (pending full disclosure)
