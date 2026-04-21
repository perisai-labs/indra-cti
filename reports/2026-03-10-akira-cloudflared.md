# Akira Ransomware: Weaponized Cloudflared for Persistent C2 and Data Exfiltration

**Author:** Peris.ai Threat Research Team  
**Date:** March 10, 2026  
**Severity:** High  
**MITRE ATT&CK:** T1572 (Protocol Tunneling), T1071.001 (Web Protocols), T1567.002 (Exfiltration to Cloud Storage)

---

## Executive Summary

The Peris.ai Threat Research Team has identified a sophisticated post-exploitation technique employed by Akira ransomware operators: weaponizing Cloudflare's legitimate **cloudflared** tunnel tool for command and control (C2) communication and data exfiltration. This 63MB binary, disguised as "Oracle.exe", leverages Cloudflare's infrastructure to establish encrypted, hard-to-detect tunnels that bypass traditional security controls.

**Key Findings:**
- **Sample:** 74eb23de1b2fdc7862447dddaadaa82fd5b43659b3c41205a40ea194dff373a9
- **Filename:** Oracle.exe (deceptive naming)
- **Type:** Win64 PE executable, Golang-compiled
- **Purpose:** C2 infrastructure and data exfiltration channel
- **Evasion:** Tunnels traffic through Cloudflare's trusted infrastructure
- **Version:** cloudflared 2025.2.0 (built 2025-02-05)

---

## Technical Analysis

### 1. File Information

![File Information](screenshots/file-info.png)

**Characteristics:**
- **SHA256:** 74eb23de1b2fdc7862447dddaadaa82fd5b43659b3c41205a40ea194dff373a9
- **Size:** 65,085,544 bytes (~63MB)
- **Type:** PE32+ executable (x86-64)
- **Language:** Golang (confirmed by build metadata)
- **Compiler:** GCC with CGO enabled
- **Architecture:** AMD64 (Win64)
- **Subsystem:** Windows Console (CUI)
- **Protections:** NX enabled (DEP), PIC enabled
- **Debug Symbols:** Present (unusual for malware — 40MB of debug sections)

### 2. Build Metadata

Analysis of embedded strings reveals this is a **legitimate Cloudflare tool**, compiled from official sources:

```
Path: github.com/cloudflare/cloudflared/cmd/cloudflared
Module: github.com/cloudflare/cloudflared (devel)
Version: main.Version=2025.2.0
Build Time: main.BuildTime=2025-02-05-1040 UTC
Git Revision: df5dafa6d7b51af66cf0587f5a9817152b72f0bc
Git Date: 2025-02-03T18:39:00Z
Build Mode: exe
Compiler: gc
CGO Enabled: 1
GOOS: windows
GOARCH: amd64
```

**Implication:** Akira operators are **not modifying** cloudflared source code. They are using the official tool as-is, relying on operational security (deceptive filenames, delivery methods) rather than custom malware development.

### 3. PE Structure & Sections

![Sections & Entropy](screenshots/sections-entropy.png)

The binary contains **20 sections**, significantly more than typical executables:

| Section | Size | Permissions | Purpose |
|---------|------|-------------|---------|
| `.text` | 12.3MB | r-x | Executable code |
| `.data` | 676KB | rw- | Initialized data |
| `.rdata` | 13.1MB | r-- | Read-only data (likely embedded configs/certs) |
| `.pdata` | 331KB | r-- | Exception handling data |
| `.bss` | 8MB | rw- | Uninitialized data |
| `.debug_*` | ~40MB | r-- | Debug symbols (8 debug sections) |

**Notable Observations:**
- Large `.rdata` section (13MB) contains embedded TLS certificates, configuration data, and Cloudflare infrastructure endpoints
- Debug symbols are intact — unusual for malware, but expected for a legitimate tool being abused
- No code obfuscation or packing detected

### 4. Import Analysis

![Imports](screenshots/imports.png)

The binary imports standard Windows APIs:

**KERNEL32.dll (69 imports):**
- File operations: `CreateFileA`, `WriteFile`, `ReadFile`
- Process/thread management: `CreateThread`, `TerminateProcess`
- Memory management: `VirtualAlloc`, `VirtualProtect`
- Networking: `CreateIoCompletionPort`, `GetQueuedCompletionStatusEx`
- Exception handling: `AddVectoredExceptionHandler`

**msvcrt.dll (26 imports):**
- Standard C runtime functions

**No explicit crypto APIs** — all cryptography is implemented in Go's standard library (`golang.org/x/crypto`).

### 5. String Analysis

#### Cloudflare Infrastructure References

![Cloudflare References](screenshots/strings-cloudflare.png)

The binary contains extensive references to Cloudflare infrastructure:

```
github.com/cloudflare/cloudflared
Issuer: C=US, O=CloudFlare, Inc., OU=CloudFlare Origin SSL
Tunnel, TunnelID, tunnelID
Proxy, ProxyTCP, useProxy
edgeIPs, getEdge, findEdge
.trycloudflare.com
cftunnel.com
```

#### Cryptographic Libraries

![Interesting Strings](screenshots/strings-interesting.png)

Encryption/decryption strings identified:

```
Encrypt, Decrypt, EncryptTo, DecryptTo
encryptKey, encryptPacket, decryptTicket
NewCBCEncrypter, NewCBCDecrypter
EncryptionLevel, headerEncrypter, headerDecrypter
```

**Context:** These strings are part of QUIC/TLS protocol implementation for tunnel encryption, **not ransomware encryption**. This binary is infrastructure, not the ransomware payload itself.

#### Networking & Tunneling

```
QUIC, HTTP/2, gRPC, WebSocket
OpenTelemetry, Prometheus (monitoring)
CoreDNS (DNS tunneling capability)
```

### 6. Disassembly Analysis

![Entry Point Disassembly](screenshots/disassembly-entry.png)

Entry point (`mainCRTStartup` @ 0x004014e0):

1. **Stack setup:** `sub rsp, 0x28` (allocate 40 bytes)
2. **Security initialization:** `call sym.__security_init_cookie` (buffer overflow protection)
3. **CRT startup:** `call sym.__tmainCRTStartup` (C runtime initialization)
4. **Cleanup and return**

Standard Golang Windows binary startup sequence — no code injection or anti-analysis techniques detected.

### 7. Behavioral Capabilities

Based on embedded dependencies and strings, cloudflared provides Akira operators with:

| Capability | Technique | Purpose |
|------------|-----------|---------|
| **QUIC Tunneling** | T1572 | Fast, encrypted C2 channel |
| **HTTP/2 Multiplexing** | T1071.001 | Multiple concurrent data streams |
| **DNS Tunneling** | T1071.004 | Exfiltration via DNS queries (CoreDNS) |
| **gRPC Communication** | T1071.001 | Efficient binary protocol for C2 |
| **WebSocket Proxying** | T1090.001 | Bidirectional, real-time communication |
| **TLS/SSL Encryption** | T1573.002 | End-to-end encryption with Cloudflare certs |
| **Cloudflare CDN Abuse** | T1568.002 | C2 traffic hidden in CDN infrastructure |

---

## Threat Actor Profile: Akira Ransomware

**Active Since:** March 2023  
**Target Sectors:** Education, finance, healthcare, manufacturing, technology  
**Geography:** Global, opportunistic targeting  
**Business Model:** Double-extortion (encryption + data leak threats)  

**TTPs (MITRE ATT&CK):**
- **Initial Access:** Phishing (T1566), exploiting public-facing applications (T1190)
- **Persistence:** Valid accounts (T1078), create account (T1136)
- **Defense Evasion:** Disable security tools (T1562), indicator removal (T1070)
- **Credential Access:** OS credential dumping (T1003)
- **Discovery:** Network service scanning (T1046), system information discovery (T1082)
- **Lateral Movement:** Remote services (T1021)
- **Command & Control:** **Protocol tunneling (T1572)** ← This analysis
- **Exfiltration:** Exfiltration to cloud storage (T1567.002)
- **Impact:** Data encrypted for impact (T1486)

---

## Evasion Techniques

### Why Cloudflare Tunnels Are Effective for Attackers

1. **Trusted Infrastructure:** Cloudflare is a legitimate CDN/security provider — traffic is whitelisted by default in most environments
2. **Encrypted by Design:** All tunnel traffic is TLS 1.3+ encrypted — no DPI can inspect payload
3. **No Outbound Firewall Blocks:** Cloudflare owns massive IP ranges (1.1.1.1, 1.0.0.1, etc.) — blocking would break legitimate services
4. **Dynamic Tunnel Endpoints:** `.trycloudflare.com` subdomains are randomly generated and ephemeral
5. **No Infrastructure Cost:** Attackers don't need to register C2 domains or rent VPS servers
6. **Protocol Obfuscation:** QUIC tunneling can bypass traditional HTTP/HTTPS inspection

### Detection Challenges

| Indicator | Normal Use Case | Malicious Use Case | Distinguishing Factor |
|-----------|-----------------|-------------------|----------------------|
| **cloudflared.exe** | IT admin running remote access | Malware dropping cloudflared | Execution path, parent process |
| **Large file size (63MB)** | Official binary | Same | Context: dropped by malware? |
| **Cloudflare TLS cert** | Legitimate web traffic | C2 tunneling | Traffic volume, frequency |
| **QUIC protocol** | Chrome/HTTP3 browsing | Data exfiltration | Source process, data volume |

---

## Indicators of Compromise (IOCs)

### File Hashes

| Type | Hash |
|------|------|
| **SHA256** | `74eb23de1b2fdc7862447dddaadaa82fd5b43659b3c41205a40ea194dff373a9` |
| **SHA1** | `8c7b5a3e82791123b9810b065244ad1f95a3fc6c` |
| **MD5** | `b2ee0b89ef1e8d83445e34b54c60eb58` |
| **Imphash** | `fc22e4f95641f6606222121e1a8a8508` |
| **SSDEEP** | `393216:JUwf/a8uS4dPkvKYtLNihY739FZE3CZCUh:qwf/axS2MCYtpv39FZOCZCk` |

### File Metadata

- **Filename:** Oracle.exe (deceptive)
- **Size:** 65,085,544 bytes (63MB)
- **Type:** PE32+ executable (AMD64)
- **Compiled:** 2025-02-05 10:40:00 UTC
- **Git Revision:** df5dafa6d7b51af66cf0587f5a9817152b72f0bc

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| **Domain** | `*.trycloudflare.com` | Cloudflare temporary tunnel domains |
| **Domain** | `cftunnel.com` | Cloudflare tunnel infrastructure |
| **Port** | 7844/UDP | Default QUIC tunnel port |
| **Protocol** | QUIC | Fast UDP-based tunneling |
| **TLS Certificate** | CN=origin-pull.cloudflare.net | Cloudflare Origin SSL |

---

## YARA Detection Rule

```yara
rule Akira_Cloudflared_C2_Tool {
    meta:
        description = "Detects Cloudflared tunnel tool weaponized by Akira ransomware"
        author = "Peris.ai Threat Research Team"
        date = "2026-03-10"
        reference = "SHA256: 74eb23de1b2fdc7862447dddaadaa82fd5b43659b3c41205a40ea194dff373a9"
        severity = "high"
        malware_family = "Akira Ransomware"
        mitre_attack = "T1572,T1071.001,T1567.002"
        
    strings:
        $cloudflared_path = "github.com/cloudflare/cloudflared/cmd/cloudflared" ascii
        $cloudflared_mod = "mod\tgithub.com/cloudflare/cloudflared" ascii
        
        $tunnel_1 = "TunnelID" ascii
        $tunnel_2 = "tunnelID" ascii
        $edge_1 = "edgeIPs" ascii
        $edge_2 = "getEdge" ascii
        
        $ssl_cert = "CloudFlare Origin SSL" ascii wide
        $quic_lib = "github.com/quic-go/quic-go" ascii
        $golang_indicator = "lang\tgo" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize > 60MB and
        $cloudflared_path and $cloudflared_mod and
        2 of ($tunnel_*) and 1 of ($edge_*) and
        ($ssl_cert or $quic_lib) and $golang_indicator
}

rule Akira_Cloudflared_Specific_Build {
    meta:
        description = "Detects specific Cloudflared build used by Akira"
        author = "Peris.ai Threat Research Team"
        date = "2026-03-10"
        severity = "critical"
        
    strings:
        $version = "main.Version=2025.2.0" ascii
        $build_date = "main.BuildTime=2025-02-05-1040 UTC" ascii
        $git_revision = "vcs.revision=df5dafa6d7b51af66cf0587f5a9817152b72f0bc" ascii
        $cloudflared = "github.com/cloudflare/cloudflared" ascii
        
    condition:
        all of them
}
```

![YARA Detection Test](screenshots/yara-test.png)

**Test Result:** ✅ Both rules triggered successfully on the sample

---

## Brahma XDR Detection Rules

### Rule 1: Hash-Based Detection

```xml
<rule>
  <rule_name>Akira_Cloudflared_C2_Tool_Execution</rule_name>
  <description>Detects execution of weaponized Cloudflared by Akira ransomware</description>
  <severity>high</severity>
  <mitre_attack>
    <technique>T1572</technique>
    <technique>T1071.001</technique>
  </mitre_attack>
  
  <conditions>
    <process_image_hash>74eb23de1b2fdc7862447dddaadaa82fd5b43659b3c41205a40ea194dff373a9</process_image_hash>
  </conditions>
  
  <actions>
    <alert priority="high" />
    <isolate_host />
    <collect_forensics />
  </actions>
</rule>
```

### Rule 2: Behavioral Detection

```xml
<rule>
  <rule_name>Cloudflared_Suspicious_Execution_Context</rule_name>
  <description>Detects Cloudflared execution from suspicious paths or parent processes</description>
  <severity>medium</severity>
  
  <conditions>
    <and>
      <or>
        <process_name>cloudflared.exe</process_name>
        <process_name>Oracle.exe</process_name>
      </or>
      <or>
        <parent_process_name>cmd.exe</parent_process_name>
        <parent_process_name>powershell.exe</parent_process_name>
        <path_regex>.*\\Temp\\.*</path_regex>
        <path_regex>.*\\AppData\\Local\\.*</path_regex>
      </or>
      <file_size_gt>60000000</file_size_gt>
    </and>
  </conditions>
  
  <actions>
    <alert priority="medium" />
    <log_event />
  </actions>
</rule>
```

### Rule 3: Network Activity Correlation

```xml
<rule>
  <rule_name>Cloudflared_Network_Tunneling_Activity</rule_name>
  <description>Detects network connections consistent with Cloudflared C2 tunneling</description>
  <severity>high</severity>
  
  <conditions>
    <and>
      <process_image_contains>cloudflared</process_image_contains>
      <or>
        <network_destination_domain_contains>.trycloudflare.com</network_destination_domain_contains>
        <network_destination_domain_contains>cftunnel.com</network_destination_domain_contains>
        <network_destination_port>7844</network_destination_port>
      </or>
      <network_bytes_sent_gt>10485760</network_bytes_sent_gt>
    </and>
  </conditions>
  
  <actions>
    <alert priority="high" />
    <block_network />
    <collect_pcap duration="300" />
  </actions>
</rule>
```

---

## Brahma NDR Detection Rules (Suricata)

```suricata
# Detect outbound connections to Cloudflare tunnel domains
alert tls any any -> any any (msg:"AKIRA RANSOMWARE - Cloudflared C2 Tunnel Detected"; \
  flow:established,to_server; tls.sni; content:".trycloudflare.com"; nocase; \
  classtype:trojan-activity; sid:2600001; rev:1;)

# Detect QUIC protocol tunneling
alert udp any any -> any 7844 (msg:"AKIRA RANSOMWARE - Cloudflared QUIC Tunnel on Port 7844"; \
  flow:to_server; content:"|01|"; depth:1; content:"QUIC"; distance:0; \
  classtype:trojan-activity; sid:2600003; rev:1;)

# Detect large data exfiltration
alert tls any any -> any any (msg:"AKIRA RANSOMWARE - Large Data Exfiltration via Cloudflare"; \
  flow:established,to_server; tls.sni; content:".trycloudflare.com"; nocase; \
  threshold:type both, track by_src, count 100, seconds 60; \
  classtype:trojan-activity; sid:2600004; rev:1;)

# Detect Cloudflare Origin SSL certificate
alert tls any any -> any any (msg:"AKIRA RANSOMWARE - Cloudflare Origin SSL Certificate"; \
  flow:established,to_server; tls.cert_subject; content:"CloudFlare Origin SSL"; nocase; \
  classtype:trojan-activity; sid:2600005; rev:1;)

# Detect Cloudflared user-agent
alert http any any -> any any (msg:"AKIRA RANSOMWARE - Cloudflared User-Agent String"; \
  flow:established,to_server; http.user_agent; content:"cloudflared"; nocase; \
  classtype:trojan-activity; sid:2600007; rev:1;)
```

---

## Recommendations

### Immediate Actions

1. **Search for IOCs:**
   - Hash: `74eb23de1b2fdc7862447dddaadaa82fd5b43659b3c41205a40ea194dff373a9`
   - Filename: `Oracle.exe`, `cloudflared.exe`
   - Network: `*.trycloudflare.com`, `cftunnel.com`

2. **Deploy Detection Rules:**
   - Import YARA rules into EDR/AV platforms
   - Enable Brahma XDR rules for endpoint monitoring
   - Activate Brahma NDR rules for network traffic inspection

3. **Investigate Cloudflared Processes:**
   ```powershell
   Get-Process | Where-Object {$_.ProcessName -match "cloudflared|Oracle"}
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Message -match "cloudflared|trycloudflare"}
   ```

### Long-Term Mitigations

1. **Network Segmentation:** Limit outbound access to Cloudflare IP ranges for non-IT systems
2. **Application Whitelisting:** Only allow cloudflared.exe from trusted IT-managed paths
3. **Egress Filtering:** Monitor for large data transfers to cloud storage/CDN providers
4. **User Training:** Educate on phishing tactics used by Akira operators
5. **Backup Strategy:** Maintain offline, immutable backups (3-2-1 rule)

### Hunting Queries

**Splunk:**
```spl
index=endpoint (process_name="cloudflared.exe" OR process_name="Oracle.exe")
| where process_size > 60000000
| stats count by host, parent_process, process_path, user
```

**Elastic:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"wildcard": {"process.name": "*cloudflared*"}},
        {"range": {"file.size": {"gte": 60000000}}}
      ]
    }
  }
}
```

---

## Conclusion

The weaponization of **cloudflared** by Akira ransomware operators represents a concerning trend: legitimate DevOps/IT tools being repurposed for malicious activity. This approach allows attackers to:

- **Evade traditional detection** (no malware signatures, trusted infrastructure)
- **Bypass egress filtering** (Cloudflare is ubiquitous and necessary)
- **Reduce operational costs** (no C2 infrastructure to maintain)
- **Increase resilience** (Cloudflare's global CDN provides fault tolerance)

**Defenders must shift focus** from purely signature-based detection to behavioral analytics and context-aware security. The presence of cloudflared is not inherently malicious — **context is key**:

✅ Legitimate: IT-managed deployment from `C:\Program Files\cloudflared\`  
❌ Suspicious: Execution from `%TEMP%` with parent process `cmd.exe`

By implementing the detection rules provided in this analysis, organizations can significantly improve their ability to identify and respond to Akira ransomware infrastructure components before encryption occurs.

---

**About Peris.ai**

Peris.ai is a cybersecurity company specializing in Extended Detection and Response (XDR), Threat Intelligence, and Security Orchestration. Our products include:

- **Brahma XDR** — Extended Detection & Response platform
- **Brahma NDR** — Network Detection & Response
- **Indra** — Threat Intelligence platform
- **Fusion SOAR** — Security Orchestration, Automation & Response
- **Brahma EDR** — Endpoint Detection & Response

For more threat intelligence and detection content, visit:  
🌐 https://peris.ai  
📧 contact@peris.ai  
🐦 @PerisAI

---

**Disclaimer:** This analysis is provided for educational and defensive purposes only. The sample was obtained from MalwareBazaar, a public malware repository. All analysis was conducted in an isolated environment.
