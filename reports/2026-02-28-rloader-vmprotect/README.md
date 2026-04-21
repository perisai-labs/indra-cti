# RLoader: VMProtect-Packed Trojan Analysis (Feb 2026)

**By Peris.ai Threat Research Team**  
**Date:** February 28, 2026  
**SHA256:** `84f77ade3d79ef5872557dd8d9c1c720b58d1d924785ab34f9fee896ea06a995`

## Executive Summary

RLoader is a VMProtect-packed trojan loader detected by Microsoft as `Trojan:Win32/Wacatac.B!ml`. The sample employs commercial-grade obfuscation (VMProtect 3.x) to evade analysis, minimal import tables to hide functionality, and fake metadata to appear legitimate. First seen on February 28, 2026, the malware demonstrates sophisticated anti-analysis techniques typical of modern loader malware used to deploy second-stage payloads.

**Key Findings:**
- **Threat Type:** Trojan Loader (Wacatac family variant)
- **Packer:** VMProtect 3.x (commercial code virtualization)
- **Detection Rate:** 18/76 engines (24%) — LOW due to advanced packing
- **C2 Infrastructure:** 162.159.36.2 (Cloudflare CDN, reputation -2)
- **Target Platform:** Windows 64-bit (PE32+, x86-64)
- **File Size:** 12 MB (bloated due to packing)

---

## Static Analysis

### File Information

**File Type:** PE32+ executable for MS Windows (GUI), x86-64, 8 sections  
**Compiled:** January 5, 2019 18:41:04 UTC (likely spoofed timestamp)  
**Architecture:** AMD64 (x86-64)  
**Protection Features:**
- Stack canary: **Enabled**
- NX (DEP): **Enabled**
- PIE: **Disabled**
- Relocs: **Enabled**

### Section Analysis

The binary contains 8 sections with highly suspicious characteristics:

| Section | Virtual Size | Raw Size | Entropy | Permissions | Notes |
|---------|-------------|----------|---------|-------------|-------|
| .text   | 217 KB      | 0        | 0.0     | rx          | Empty (VMProtect stub) |
| .rdata  | 22 KB       | 0        | 0.0     | r           | Empty |
| .data   | 45 KB       | 0        | 0.0     | rw          | Empty |
| .pdata  | 4.6 KB      | 0        | 0.0     | r           | Empty |
| **.4;8** | **7.7 MB** | **0**    | **0.0** | **rx**      | **VMProtect code** |
| .dn}    | 88 bytes    | 512      | 0.18    | rw          | Unknown |
| **.e[6** | **12 MB**   | **12 MB**| **7.83**| **rx**      | **PACKED DATA** |
| .rsrc   | 100 KB      | 99 KB    | 7.97    | r           | Resources (icons, manifest) |

**Indicators of VMProtect:**
- Unusual section names (`.4;8`, `.dn}`, `.e[6`) — characteristic of VMProtect
- Empty virtual sections (size 0) with large virtual addresses
- Large packed section (`.e[6`) with high entropy (7.83) — encrypted code
- Minimal code in standard `.text` section

### Import Analysis

**Critical Finding:** Only **2 imported functions** from **2 DLLs**

| Library | Function | Purpose |
|---------|----------|---------|
| KERNEL32.dll | `GetDiskFreeSpaceExW` | Check available disk space |
| USER32.dll | `wsprintfW` | String formatting |

This minimal import table is **highly suspicious** and confirms VMProtect usage. Real functionality is:
- Resolved dynamically at runtime via API hashing
- Hidden within virtualized code
- Loaded from secondary payloads

### String Analysis

The sample contains minimal readable strings:
- Mostly binary junk in `.rsrc` section (PNG icons, manifest)
- XML manifest declaring Windows compatibility
- **No hardcoded C2 addresses, URLs, or suspicious keywords**
- Strings are likely encrypted within VMProtect segments

**XML Manifest Extract:**
```xml
<requestedExecutionLevel level="asInvoker" uiAccess="false"/>
<supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
```

### Disassembly Analysis

**Entry Point:** `0x14086fc03`

```asm
0x14086fc03  call 0x140994282    ; VMProtect unpacking stub
0x14086fc08  mov ebx, 0xdfb3d0f4
0x14086fc0d  xchg ebx, eax
0x14086fc0f  outsd dx, [rsi]     ; Obfuscated code
0x14086fc10  mov cl, 0x49
0x14086fc12  retf 0xeb40         ; Invalid far return
0x14086fc15  jrcxz 0x14086fc28   ; Conditional jumps
0x14086fc17  retfq 0x1340        ; More junk
0x14086fc3d  hlt                 ; Anti-debugging (halt CPU)
0x14086fc8e  int3                ; Breakpoint instruction
```

**VMProtect Indicators:**
- First instruction: `call` to unpacking stub (`0x140994282`)
- Followed by **junk code**: invalid instructions, far returns, `hlt`, `int3`
- Code virtualization — real instructions decoded at runtime
- Anti-debugging techniques embedded

---

## Behavioral Analysis (VirusTotal Sandbox)

### Process Activity

**Processes Created:**
- `C:\Users\<USER>\Desktop\RLoader.exe` (self-spawn)
- `C:\Users\user\Desktop\RLoader.exe` (alternate user context)

The malware **spawns itself** with the name `RLoader.exe`, indicating:
- Process injection or hollowing
- Privilege escalation attempt
- Evasion of single-process analysis

### Network Activity

**Contacted IPs:**
- `162.159.36.2` (Cloudflare Inc., AS13335)
  - **Network:** 162.159.0.0/18
  - **Reputation:** -2 (suspicious)
  - **Purpose:** C2 communication via Cloudflare CDN (likely HTTPS/DNS over HTTPS)

**DNS Lookups:** None captured (likely DNS over HTTPS via Cloudflare)

**Analysis:** Using Cloudflare CDN for C2 provides:
- Legitimate-looking traffic (blends with normal web traffic)
- DDoS protection for C2 infrastructure
- Evasion of IP-based blocking

### File Operations

**Files Written:** None observed in sandbox (payload likely retrieved dynamically)

---

## Metadata & Versioning (Fake)

**PE Signature Info:**
- **Product Name:** "Settings Manager"
- **Internal Name:** `sdkdrv8878.exe`
- **Original Name:** `sdkdrv8878.exe`
- **Description:** "Settings Manager Runtime"
- **Copyright:** "(C) AJA Corp. 2020"
- **File Version:** 3.4.0.0

**Analysis:** This metadata is **fabricated** to:
- Appear as legitimate software (AJA Corp is a real video technology company)
- Evade heuristic detection
- Social engineering (users may trust "Settings Manager")

**Other Filenames Seen (VirusTotal):**
- `orw82st.exe`
- `RLoader.exe`
- `sdkdrv8878.exe`

---

## Threat Intelligence

### Detection Rates

**VirusTotal:** 18/76 engines (24% detection) — **LOW**

**Top Detections:**
- **Microsoft:** Trojan:Win32/Wacatac.B!ml
- **ESET-NOD32:** Win64/Packed.VMProtect.AC suspicious application
- **AhnLab-V3:** Packed/Win.VMProtect.R760658
- **Antiy-AVL:** Trojan[Packed]/Win64.VMProtect
- **Malwarebytes:** Trojan.MalPack
- **Rising:** Trojan.Kryptik@AI.82
- **Symantec:** ML.Attribute.HighConfidence
- **CrowdStrike:** win/malicious_confidence_90% (W)

**Family Classification:** Wacatac is a **generic detection family** used by Microsoft for:
- Trojans with advanced scripting and evasion techniques
- Modular malware employing PowerShell/scripting
- Loader malware with persistence mechanisms

### First Seen

- **First Submission:** February 28, 2026 02:02:23 UTC
- **Last Analysis:** February 28, 2026 03:55:28 UTC
- **Age at Analysis:** < 7 hours (very fresh sample)

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|------------|
| **Execution** | User Execution | T1204.002 | Requires user to run RLoader.exe |
| **Defense Evasion** | Obfuscated Files or Information | T1027.002 | VMProtect 3.x packing, code virtualization |
| **Defense Evasion** | Software Packing | T1027.002 | High-entropy .e[6 section |
| **Defense Evasion** | Masquerading | T1036.005 | Fake metadata ("Settings Manager") |
| **Defense Evasion** | Virtualization/Sandbox Evasion | T1497.001 | Anti-debugging (hlt, int3) |
| **Command and Control** | Web Service | T1102.001 | Cloudflare CDN (162.159.36.2) |
| **Command and Control** | Encrypted Channel | T1573.002 | Likely HTTPS/DNS over HTTPS |

---

## Indicators of Compromise (IOCs)

### File Hashes

```
SHA256: 84f77ade3d79ef5872557dd8d9c1c720b58d1d924785ab34f9fee896ea06a995
Imphash: 8739de86cd836ae1476705562c069cc0
```

### Network Indicators

```
IP: 162.159.36.2 (Cloudflare Inc., AS13335)
Network: 162.159.0.0/18
```

### Filenames

```
RLoader.exe
sdkdrv8878.exe
orw82st.exe
```

### PE Metadata

```
Product: "Settings Manager"
Internal Name: sdkdrv8878.exe
Copyright: "(C) AJA Corp. 2020"
Version: 3.4.0.0
```

---

## Conclusion

RLoader represents a sophisticated loader malware protected by commercial-grade VMProtect obfuscation. The sample demonstrates:

1. **Advanced Evasion:** VMProtect 3.x virtualization makes static analysis extremely difficult
2. **Low Detection:** Only 24% of AV engines detect the threat due to packing
3. **Fake Legitimacy:** Metadata masquerading as "Settings Manager" to fool users
4. **Modern Infrastructure:** C2 via Cloudflare CDN for stealth and resilience

**Threat Assessment:** **HIGH**
- Designed to bypass traditional AV detection
- Likely downloads/executes second-stage payloads (RAT, stealer, ransomware)
- Uses legitimate services (Cloudflare) for C2 communication

**Recommendations:**
- Block all variants by Imphash (`8739de86cd836ae1476705562c069cc0`)
- Monitor Cloudflare traffic for unusual patterns
- Enforce application whitelisting to prevent execution
- Deploy behavioral detection (endpoint + network)

---

## References

- VirusTotal: https://www.virustotal.com/gui/file/84f77ade3d79ef5872557dd8d9c1c720b58d1d924785ab34f9fee896ea06a995
- Microsoft Wacatac Threat Description: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Script/Wacatac
- VMProtect Anti-Debug Techniques: https://sachiel-archangel.medium.com/anti-debug-techniques-of-vmprotect-f1e343ee0fb2
- MalwareBazaar: https://bazaar.abuse.ch/sample/84f77ade3d79ef5872557dd8d9c1c720b58d1d924785ab34f9fee896ea06a995/

---

*Analysis performed by Peris.ai Threat Research Team on February 28, 2026.*
