# SpyNote Android RAT: TikTok Cheats Campaign (Feb 2026)

**Threat Research Report**  
**Published:** February 23, 2026  
**Classification:** TLP:WHITE  
**Analysis Type:** Android Malware  

---

## Executive Summary

Fresh SpyNote Android RAT campaign detected on February 23, 2026, masquerading as "ttcheats.apk" — a fake TikTok cheats/hacks application. The sample demonstrates classic SpyNote characteristics including extensive permissions abuse, Russian tunneling infrastructure for command-and-control, and a self-signed certificate with fake Turkish identity information.

**Threat Level:** 🔴 HIGH  
**Target:** Mobile users (primarily Chile)  
**Detection Rate:** 21/36 AV engines (58%)  
**Campaign Status:** Active (sample < 8 hours old at time of analysis)

---

## Sample Profile

| Attribute | Value |
|-----------|-------|
| **Filename** | ttcheats.apk |
| **SHA256** | `49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182` |
| **SHA1** | `117420986b52b7b4506145b6be94a161b1041c69` |
| **MD5** | `afdff63f21e7ce69cbc8ffa30db59232` |
| **File Type** | Android APK (Java Archive) |
| **Size** | 778,719 bytes |
| **First Seen** | 2026-02-23 01:39:46 UTC |
| **Malware Family** | SpyNote |
| **Origin Country** | CL (Chile) |

---

## Indicators of Compromise (IOCs)

### Network IOCs

```
Domain: tcp1.tunnel4.com
IP Address: 78.29.43.89
Port: 40918
Protocol: TCP
Infrastructure: Russian dynamic DNS (xtunnel.ru nameservers)
Registrar: REG.RU (Russia)
```

### File Indicators

```
Package Name: cmf0.c3b5bm90zq.patch
Certificate CN: Benim ismim
Certificate Email: sahte@gmail.com
Certificate Fingerprint (SHA256): BF7DCCA87A4B2EF5C91D7ECA38101BB8D0E2E91D849DAE4E8213372065846930
SSDEEP: 12288:Jb0F2a1a8LdegouJ/ik5WmpYshXZPbGwidNpgo4:Jxa1a6egnJ/ik5WmD9idNpy
```

### Infrastructure IOCs

```
Nameservers:
- ns1.xtunnel.ru
- ns2.xtunnel.ru

Related Domains:
- tunnel4.com (dynamic DNS service)
- xtunnel.ru (Russian tunneling provider)
```

---

## Threat Analysis

### Social Engineering Lure

The malware masquerades as "TikTok cheats" — an application promising hacks or advantages for the TikTok platform. This lure is particularly effective against younger demographics seeking game modifications or social media advantages.

**Delivery Method:** Sideloading (installation from untrusted sources)  
**Target Audience:** Young mobile users, TikTok enthusiasts

### Capabilities

1. **Surveillance:**
   - SMS message interception
   - Call log harvesting
   - Audio recording via microphone
   - Camera access
   - Location tracking (GPS)

2. **Data Theft:**
   - Contact list exfiltration
   - Stored credentials
   - Browser history
   - Application data

3. **Banking Trojan Features:**
   - Overlay attacks (SYSTEM_ALERT_WINDOW permission)
   - Credential phishing overlays
   - 2FA code interception

4. **Persistence:**
   - Boot receiver (auto-start on device restart)
   - Foreground service
   - Wake locks (prevent device sleep)
   - WiFi locks (maintain network connection)

### Infrastructure Analysis

**C2 Communication:**
- **Protocol:** TCP socket connection
- **Host:** tcp1.tunnel4.com (dynamic DNS)
- **Port:** 40918
- **IP:** 78.29.43.89

**Operational Security:**
- Use of Russian dynamic DNS service (xtunnel.ru) allows threat actor to change IP addresses without recompiling malware
- REG.RU registrar (Russia) provides privacy protection
- Dynamic DNS evades static IP-based blocking

---

## MITRE ATT&CK Framework

| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| **Initial Access** | T1476 | Deliver Malicious App |
| **Persistence** | T1624 | Event Triggered Execution |
| **Defense Evasion** | T1628.001 | Hide Artifacts: Suppress Application Icon |
| **Credential Access** | T1417 | Input Capture (Overlay Attacks) |
| **Discovery** | T1418 | Application Discovery |
| **Collection** | T1412 | Capture SMS Messages |
| | T1432 | Access Contact List |
| | T1429 | Capture Audio |
| | T1533 | Data from Local System |
| **Command & Control** | T1437 | Application Layer Protocol |
| | T1481 | Web Service (Dynamic DNS) |
| **Exfiltration** | T1646 | Exfiltration Over C2 Channel |

---

## Permissions Abuse

The malware requests 40+ Android permissions, including:

**Critical Permissions:**
- `READ_SMS`, `RECEIVE_SMS` — SMS interception
- `READ_CONTACTS`, `WRITE_CONTACTS` — Contact theft
- `READ_PHONE_STATE`, `CALL_PHONE`, `READ_CALL_LOG` — Call monitoring
- `CAMERA` — Camera access
- `RECORD_AUDIO` — Microphone access
- `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION` — Location tracking
- `SYSTEM_ALERT_WINDOW` — Overlay attacks (banking credential theft)
- `RECEIVE_BOOT_COMPLETED` — Boot persistence
- `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE` — File access

**Red Flag:** Legitimate TikTok-related apps should NOT require SMS, call log, or microphone permissions.

---

## Certificate Analysis

**Self-Signed Certificate (Fake Turkish Identity):**

```
Owner: CN=Benim ismim, OU=Benim Firmam, O=Benim Firmam, L=Antan, ST=SANANE, C=rb
Email: sahte@gmail.com
Validity: 2017-10-17 to 2045-03-03 (28 years)
Algorithm: SHA1withRSA (weak, deprecated)
Self-Signed: Yes
```

**Analysis:**
- "Benim ismim" = Turkish for "My name" (placeholder)
- "sahte@gmail.com" = Turkish "sahte" means "fake"
- "SANANE" = Turkish slang for "none of your business"
- 28-year validity period avoids expiration issues
- SHA1withRSA is deprecated and insecure
- Classic SpyNote signature pattern

---

## Recommendations

### For Users

1. ✅ **Never install apps from unknown sources** — Only use Google Play Store
2. ✅ **Review permissions carefully** — TikTok cheats should NOT need SMS/Call access
3. ✅ **Enable Google Play Protect** (built-in malware scanner)
4. ✅ **Be skeptical of "cheat" or "mod" apps** — Common malware lures
5. ✅ **If infected:**
   - Boot device into Safe Mode
   - Uninstall suspicious apps
   - Factory reset if persistence detected
   - Change all passwords
   - Notify financial institutions if banking data at risk

### For Organizations

1. **Mobile Device Management (MDM):**
   - Block sideloading (enforce Google Play Store only)
   - Deploy app whitelisting policies
   - Enable remote wipe capabilities

2. **Network Security:**
   - Block IOCs (domains, IPs) at firewall/proxy
   - Monitor for connections to tunnel4.com, xtunnel.ru domains
   - Alert on connections to port 40918

3. **User Education:**
   - Security awareness training on mobile threats
   - Emphasize permission scrutiny
   - Reporting procedures for suspicious apps

---

## Detection

**YARA Rule Available:** Yes (contact for access)  
**Network Signatures:** Available via threat intel feeds  
**Behavioral Indicators:**
- Excessive permissions for app category
- Self-signed certificate with placeholder identity
- Connection to dynamic DNS services
- Boot receiver + foreground service

---

## Timeline

- **2026-02-23 01:39 UTC:** Sample first submitted to MalwareBazaar
- **2026-02-23 09:00 UTC:** Analysis completed
- **Status:** Active campaign (ongoing threat)

---

## References

- MalwareBazaar: https://bazaar.abuse.ch/sample/49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182/
- Triage Analysis: https://tria.ge/reports/260223-b3s4jafz2a/
- VirusTotal: 21/36 engines (58% detection)

---

## About This Report

This report is provided by Peris.ai Threat Research Team for defensive and educational purposes only. All indicators are provided to help organizations protect against this threat.

**For more information:**
- Website: https://peris.ai
- Contact: research@peris.ai
- GitHub: https://github.com/perisai-labs/indra-cti

---

**TLP:WHITE** — May be distributed without restriction.  
**Report Version:** 1.0  
**Last Updated:** 2026-02-23
