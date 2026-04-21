# SalatStealer Analysis — Golang-Based Credential Stealer (February 2026)

**Classification:** TLP:WHITE  
**Malware Family:** SalatStealer (Salat)  
**Analysis Date:** February 26, 2026  

---

## Executive Summary

SalatStealer is a Golang-compiled credential stealer actively distributed in February 2026. This sample was first observed on February 26, 2026, and has been confirmed by multiple sandbox vendors (Intezer, Triage, VMRay, ANY.RUN) as part of the SalatStealer family. With a detection rate of 56% (20/36 engines) and a malicious score of 10/10, this infostealer demonstrates sophisticated credential theft capabilities targeting browsers, cryptocurrency wallets, Telegram sessions, and Windows credentials.

---

## Technical Analysis

### File Information

- **SHA256:** `38074efa0a6d9816d9eb8b922922006dbddfe1b24f68ba5adadc989ad7d02342`
- **MD5:** `25ce173c367106ca0ee64088f01c29a2`
- **SHA1:** `c3a1f8263519b2bc197ebc0831eda06677a2be58`
- **File Type:** PE32 executable (GUI), Intel 80386
- **Size:** 11,672,064 bytes (11.6 MB)
- **Architecture:** x86 (32-bit)
- **Compiled:** January 1, 1970 (zeroed timestamp)
- **Language:** Golang
- **Imphash:** `4f2f006e2ecf7172ad368f8289dc96c1`
- **Packing:** UPX decompressed
- **First Seen:** February 26, 2026, 01:15:52 UTC

### Vendor Intelligence

**Detection Rate:** 56% (20/36 engines)

**Vendor Identifications:**
- **Intezer:** SalatStealer (malicious, score: 1.00)
- **Triage:** SalatStealer (score: 10/10)
- **VMRay:** SalatStealer (malicious)
- **ANY.RUN:** Malicious activity (tags: salatstealer, stealer, golang)
- **ReversingLabs:** Win32.Trojan.Vidar
- **Kaspersky:** Trojan-PSW.Win64.Salat.sb, Trojan-PSW.Win32.Coins.sb

---

## Capabilities

### 1. Browser Credential Theft

Targets the following browsers:
- Google Chrome, Chrome SxS
- Mozilla Firefox
- Opera, Opera GX
- Brave Browser
- Microsoft Edge
- Waterfox, Pale Moon
- Yandex Browser
- 360 Browser, Cent Browser
- And 15+ other Chromium-based browsers

**Stolen Data:**
- Saved login credentials (`Login Data`, `logins.json`)
- Session cookies
- Autofill data
- Browser history

**Method:** Uses Windows DPAPI decryption (`CryptUnprotectData`) to access encrypted credentials.

### 2. Cryptocurrency Wallet Theft

**Targeted Wallets:**
- Exodus, Electrum, Atomic Wallet, MetaMask, Trust Wallet
- Ethereum keystore files
- Zcash, Monero, Bitcoin wallets
- 30+ cryptocurrency applications

### 3. Telegram Session Hijacking

- Steals `tdata` folder for full account access
- Allows attacker to read messages, contacts, groups

### 4. Discord Token Theft

- Steals session tokens from Local Storage databases
- Enables account takeover

### 5. System Privilege Escalation

- Uses token duplication techniques
- Attempts to elevate to SYSTEM privileges
- Can dump LSASS memory for credential extraction

### 6. Stealth C2 Communication

- **Protocol:** QUIC over UDP (encrypted)
- **DNS Evasion:** DNS over HTTPS (`dns.google`)
- **User-Agent:** `Go-http-client/1.1`, `Go-http-client/2.0`

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Procedure |
|--------|-----------|-----------|
| **Credential Access** | T1555.003 | Browser credential theft via DPAPI |
| **Credential Access** | T1555.004 | Cryptocurrency wallet theft |
| **Credential Access** | T1003.001 | LSASS memory dumping |
| **Privilege Escalation** | T1134.001 | Token impersonation/duplication |
| **Collection** | T1005 | Data from local system |
| **Exfiltration** | T1041 | C2 channel exfiltration |
| **Command and Control** | T1071.001 | Application layer protocol (HTTP) |
| **Command and Control** | T1573.002 | Encrypted channel (QUIC, TLS) |

---

## Indicators of Compromise (IOCs)

### File Hashes

```
SHA256: 38074efa0a6d9816d9eb8b922922006dbddfe1b24f68ba5adadc989ad7d02342
MD5:    25ce173c367106ca0ee64088f01c29a2
SHA1:   c3a1f8263519b2bc197ebc0831eda06677a2be58
Imphash: 4f2f006e2ecf7172ad368f8289dc96c1
```

### File Paths Targeted

```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json
%APPDATA%\Telegram Desktop\tdata\
%APPDATA%\Exodus\exodus.wallet
%APPDATA%\Electrum\wallets
%APPDATA%\Ethereum\keystore
```

### Network Indicators

- **User-Agent:** `Go-http-client/1.1`, `Go-http-client/2.0`
- **DNS over HTTPS:** `dns.google`
- **Protocol:** QUIC over UDP

---

## Recommendations

### For Organizations

1. **Endpoint Monitoring:**
   - Monitor for `Go-http-client` User-Agent in HTTP traffic
   - Alert on LSASS memory access by non-system processes
   - Block QUIC traffic on non-standard ports

2. **Browser Security:**
   - Enforce master passwords for credential storage
   - Disable password autofill in corporate environments
   - Use hardware security keys (FIDO2)

3. **Cryptocurrency Protection:**
   - Use hardware wallets (Ledger, Trezor)
   - Store wallet files in encrypted volumes

4. **Telegram Security:**
   - Enable two-factor authentication
   - Monitor `tdata` folder access

### For Incident Responders

**If infected:**

1. **Immediate Actions:**
   - Isolate machine from network
   - Terminate suspicious Go processes
   - Dump memory for forensic analysis

2. **Credential Rotation:**
   - Change ALL browser-saved passwords
   - Revoke Telegram sessions
   - Move cryptocurrency to new wallets
   - Invalidate Steam Guard tokens

3. **Forensics:**
   - Check `%TEMP%` for dropped files
   - Analyze Prefetch data
   - Review Windows Event Logs

---

## References

- **MalwareBazaar:** https://bazaar.abuse.ch/sample/38074efa0a6d9816d9eb8b922922006dbddfe1b24f68ba5adadc989ad7d02342
- **ANY.RUN:** https://app.any.run/tasks/ab8bad03-9807-4ae9-b273-e0ca943eb538
- **Intezer:** https://analyze.intezer.com/analyses/94b72fa4-3162-43e7-bd58-cd6c2bba1e9c
- **Triage:** https://tria.ge/reports/260226-bmzalsdv4f/
- **VMRay:** https://www.vmray.com/analyses/_mb/38074efa0a6d/report/overview.html

---

**Analyzed by:** Peris.ai Threat Research Team  
**Published:** February 26, 2026  
**Classification:** TLP:WHITE
