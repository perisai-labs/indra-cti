# Crysome RAT: .NET Malware Dropped by Amadey Botnet

**By Peris.ai Threat Research Team**  
**Published:** February 15, 2026  
**Severity:** High  
**Malware Family:** Crysome RAT  
**Threat Type:** Remote Access Trojan (RAT)

---

## Executive Summary

On February 15, 2026, Peris.ai Threat Research team analyzed a previously unidentified .NET-based Remote Access Trojan (RAT) designated **Crysome RAT**. This malware was distributed via the Amadey botnet infrastructure and exhibits full-featured backdoor capabilities including PowerShell execution, file operations, SOCKS proxy functionality, and active window monitoring.

The sample was obtained from MalwareBazaar and showed low detection rates across sandbox environments despite being flagged as malicious by Intezer. This analysis provides comprehensive technical details, indicators of compromise (IOCs), and detection rules for SOC/SIEM platforms.

---

## Technical Analysis

### File Information

![File Info](img/2026-02-15-crysome-rat/file-info.png)

**SHA256:** `cfe781129d8db1dcbfdce5fa3b62157bbd6e7a7e8b7f421a4767189463ef28e0`  
**MD5:** `4c84bff59b7e8b2df76e38466ba8b627`  
**SHA1:** `6a0c60cd5ebdf6c7cb88b066f928d2c46f811c34`  
**File Type:** PE32 executable (.NET assembly)  
**Architecture:** x86 (i386)  
**Language:** CIL (.NET Intermediate Language)  
**Subsystem:** Windows GUI  
**PDB Path:** `C:\Users\eve\Desktop\DzSocket-3.1 - UDP\DzSocket-3.1\pace-main\src\Crysome.Client\obj\Release\net472\Crysome.Client.pdb`

### PE Structure

![PE Sections](img/2026-02-15-crysome-rat/sections.png)

The binary contains three standard PE sections:
- `.text` (77KB) — executable code
- `.rsrc` (1.5KB) — resources
- `.reloc` (512 bytes) — relocations

### Imports Analysis

![Imports](img/2026-02-15-crysome-rat/imports.png)

The binary imports only `mscoree.dll` with `_CorExeMain`, indicating a standard .NET managed executable. All malicious functionality is implemented in managed code.

### .NET Metadata Analysis

![.NET Metadata](img/2026-02-15-crysome-rat/dotnet-metadata.png)

Analysis of the .NET metadata revealed the complete namespace structure:

**Core Modules:**
- `Crysome.Client` — main client implementation
- `Crysome.Client.Web` — web download functionality (WebFileDownloader)
- `Crysome.Client.System` — system information gathering
- `Crysome.Client.Handlers` — C2 command processing
- `Crysome.Client.Network` — TCP network communication
- `Crysome.Common.Network.Packets.Server` — C2 server packet definitions
- `Crysome.Common.Network.Packets.Client` — client response packets

### Capabilities Identified

#### 1. **PowerShell Execution**
The malware implements `RunPowerShell` method allowing arbitrary PowerShell command execution on the victim machine.

#### 2. **File Download**
`WebFileDownloader` class with `DownloadFile` method enables remote file retrieval via HTTP/HTTPS.

#### 3. **File System Enumeration**
- `GetFiles` — enumerate files
- `GetDirectories` — enumerate directories
- `HandleGetDrives` — list available drives

#### 4. **SOCKS Proxy**
- `HandleStartProxy` — initialize SOCKS proxy
- `HandleSocksClient` — handle SOCKS connections
- `SocksPort` — configurable proxy port

#### 5. **System Profiling**
Collects comprehensive system information:
- Operating System version
- Computer name
- Username
- Country code
- System uptime
- Active window title (keylogger-like behavior)

#### 6. **Network Communication**
TCP-based C2 communication with custom packet structure:
- `TcpClient` for network connectivity
- Custom packet serialization/deserialization
- Likely uses compression (Crysome.Common.Compression namespace present)

### String Analysis

![Suspicious Strings](img/2026-02-15-crysome-rat/strings-suspicious.png)

Key suspicious strings identified:
- `RunPowerShell`
- `DownloadFileRequestPacket`
- `HandleDownloadFile`
- `ProcessWindowStyle`
- `WebClient`
- `RegistryKey`
- User interaction strings: `ActiveWindow`, `ActiveWindowTitle`

### Hex Dump Analysis

![Hex Dump](img/2026-02-15-crysome-rat/hexdump-header.png)

Standard PE/COFF header with .NET CLR metadata. No evidence of packing or encryption at the PE level.

---

## Behavioral Analysis

### Initial Execution
1. .NET runtime loaded via `mscoree.dll`
2. `CrysomeClient` main class initialized
3. Establishes TCP connection to C2 server
4. Sends initial beacon with system profile

### C2 Communication
The malware implements a custom binary protocol with packet-based commands:
- `DownloadFileRequestPacket` — download file from URL
- PowerShell execution commands
- File enumeration commands
- SOCKS proxy activation
- Active window monitoring

### Persistence Mechanism
No explicit persistence mechanism identified in static analysis. Likely relies on Amadey botnet for re-infection or implements registry-based persistence at runtime.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| **Execution** | PowerShell | T1059.001 | RunPowerShell method |
| **Command and Control** | Application Layer Protocol | T1071 | Custom TCP protocol |
| **Discovery** | System Information Discovery | T1082 | OS, username, computer name |
| **Discovery** | File and Directory Discovery | T1083 | GetFiles, GetDirectories |
| **Discovery** | System Network Configuration Discovery | T1016 | Country code detection |
| **Collection** | Input Capture | T1056 | Active window title monitoring |
| **Command and Control** | Proxy | T1090.001 | SOCKS proxy implementation |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Low AV detection |

---

## Indicators of Compromise (IOCs)

### File Hashes
```
SHA256: cfe781129d8db1dcbfdce5fa3b62157bbd6e7a7e8b7f421a4767189463ef28e0
MD5:    4c84bff59b7e8b2df76e38466ba8b627
SHA1:   6a0c60cd5ebdf6c7cb88b066f928d2c46f811c34
Imphash: f34d5f2d4577ed6d9ceec516c1f5a744
```

### Network IOCs
```
Download URL: http://130.12.180.43/files/7719759462/Yd6HwRw.exe
C2 IP: 130.12.180.43
```

### YARA Rule

![YARA Test](img/2026-02-15-crysome-rat/yara-test.png)

See: `yara/malware/crysome-rat.yar`

---

## Detection Rules

### Generic SIEM/XDR Rule

```
Rule: Crysome RAT PowerShell Execution
Severity: High
Condition: process.name == "powershell.exe" AND process.parent.name CONTAINS "Crysome.Client"
MITRE: T1059.001
```

```
Rule: Crysome RAT C2 Network Connection
Severity: High
Condition: network.destination.ip == "130.12.180.43"
MITRE: T1071
```

```
Rule: Crysome RAT File Execution
Severity: Critical
Condition: file.hash.sha256 == "cfe781129d8db1dcbfdce5fa3b62157bbd6e7a7e8b7f421a4767189463ef28e0"
MITRE: T1204.002
```

### Network Detection (Suricata/Snort)

```
alert tcp any any -> any any (msg:"MALWARE Crysome RAT Download URL"; flow:established,to_server; content:"GET"; http_method; content:"/files/7719759462/Yd6HwRw.exe"; http_uri; classtype:trojan-activity; sid:5000001; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Crysome RAT C2 Communication"; flow:established,to_server; content:"|00 00 00|"; depth:3; content:"Crysome"; distance:0; within:50; classtype:trojan-activity; sid:5000002; rev:1;)
```

---

## Recommendations

### Immediate Actions
1. **Block IOCs** — Add IP 130.12.180.43 to firewall blocklist
2. **Hunt for Indicators** — Search for file hash and PDB path in your environment
3. **Monitor PowerShell** — Alert on PowerShell execution by unsigned .NET binaries
4. **Network Monitoring** — Inspect outbound connections to unknown IPs

### Long-term Mitigations
1. **Application Whitelisting** — Block execution of unsigned .NET assemblies
2. **PowerShell Logging** — Enable PowerShell script block logging
3. **EDR Deployment** — Deploy EDR solution for behavioral detection
4. **Patch Management** — Keep systems updated to prevent Amadey infection vector

---

## References

- MalwareBazaar: https://bazaar.abuse.ch/sample/cfe781129d8db1dcbfdce5fa3b62157bbd6e7a7e8b7f421a4767189463ef28e0/
- Amadey Botnet: https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey
- MITRE ATT&CK: https://attack.mitre.org/

---

## Timeline

- **2026-02-15 01:50 UTC** — First seen on MalwareBazaar
- **2026-02-15 09:00 WIB** — Analysis by Peris.ai Threat Research Team

---

**About Peris.ai Threat Research Team**

The Peris.ai Threat Research Team provides continuous threat intelligence and malware analysis to protect organizations from emerging cyber threats. Our research powers Brahma XDR, Brahma NDR, and Indra Threat Intelligence platforms.

For more threat intelligence, visit: https://peris.ai
