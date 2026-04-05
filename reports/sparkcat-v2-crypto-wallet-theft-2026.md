# SparkCat Malware V2 — Crypto Wallet Recovery Phrase Theft via iOS & Android Apps

**Date:** 2026-04-05
**Severity:** HIGH
**Source:** The Hacker News (2026-04-03)
**Platform:** iOS (App Store) + Android (Google Play)

## Summary

New variant of SparkCat malware discovered on both Apple App Store and Google Play Store. Concealed within seemingly benign apps (enterprise messengers, food delivery services). This variant specifically targets cryptocurrency wallet recovery phrases by capturing images from device gallery/screens and exfiltrating them. Evolution from original SparkCat which focused on general credential theft.

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Supply Chain Compromise | T1195.002 |
| Execution | User Execution | T1204 |
| Collection | Data from Information Repositories | T1213 |
| Collection | Screen Capture | T1113 |
| Exfiltration | Exfiltration Over Web Service | T1567 |
| Credential Access | Credentials from Password Stores | T1555 |
| Defense Evasion | Masquerading | T1036 |

## IOCs

- **Malware Family:** SparkCat (v2)
- **Distribution:** App Store, Google Play (benign-looking apps)
- **Target:** Cryptocurrency wallet recovery phrases (seed images)
- **App Types:** Enterprise messengers, food delivery services
- **Data Exfiltrated:** Gallery images, screenshot data containing seed phrases

## Brahma XDR Detection Rule (XML)

```xml
<Rule id="900102" severity="high" enabled="true">
  <name>Suspicious Mobile App Excessive Media Access</name>
  <description>Detects mobile applications requesting excessive media/gallery access combined with network exfiltration patterns consistent with SparkCat</description>
  <logic>
    <condition operator="AND">
      <rule_field name="permission_request" operator="contains">READ_MEDIA_IMAGES</rule_field>
      <rule_field name="permission_request" operator="contains">INTERNET</rule_field>
      <rule_field name="app_category" operator="in">food_delivery,messenger</rule_field>
      <rule_field name="network_bytes_sent" operator="greater_than">10240</rule_field>
    </condition>
  </logic>
  <tags>
    <tag>Malware</tag>
    <tag>SparkCat</tag>
    <tag>Crypto</tag>
    <tag>Mobile</tag>
  </tags>
</Rule>
```

## Brahma NDR Detection Rule (Suricata)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE SparkCat Exfiltration Beacon"; flow:established,to_server; content:"POST"; http_method; content:"Content-Type|3a| multipart/form-data"; http_header; content:"filename="; http_client_body; nocase; pcre:"/filename=.*\.(png|jpg|jpeg)/i"; metadata:affected_product Mobile_OS, attack_target Client_Endpoint; classtype:trojan-activity; sid:2900102; rev:1;)
```

## Recommendations

1. Audit all installed mobile apps — especially recent downloads of messengers/food delivery apps
2. Review MDM policies to restrict excessive media access permissions
3. Never store crypto seed phrase images on any device
4. Use hardware wallets for significant crypto holdings
5. Monitor network traffic from mobile devices for bulk image uploads
6. Implement mobile threat defense solutions

## References

- https://thehackernews.com/2026/04/new-sparkcat-variant-in-ios-android.html
