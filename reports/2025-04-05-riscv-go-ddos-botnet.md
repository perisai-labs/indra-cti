# RISC-V Go DDoS Botnet: Emerging Threat in IoT Malware Landscape

**By Peris.ai Threat Research Team**  
**Published: April 5, 2025**

## Executive Summary

Our threat research team has identified a sophisticated DDoS botnet targeting RISC-V architecture systems. This malware, written in Go and statically compiled for the RISC-V platform, represents an emerging threat as IoT devices increasingly adopt this open-source instruction set architecture. The malware features HTTP/HTTPS proxy capabilities and demonstrates advanced evasion techniques.

**Key Findings:**
- **Architecture:** ELF 64-bit RISC-V (uncommon target)
- **Language:** Go (statically linked, stripped)
- **Size:** 5.1 MB
- **SHA256:** `0a65892df4903823e00869e42a58403ef4e125bcb55838016e3cd227fb5f9635`
- **Capabilities:** HTTP/HTTPS DDoS, Proxy scraping, Multi-protocol flooding

## Technical Analysis

### File Characteristics

![File Info](screenshots/file-info.png)

The malware is a 64-bit ELF executable compiled for RISC-V architecture with double-float ABI. Key characteristics include:

- **Statically linked:** No external dependencies, making it portable across RISC-V systems
- **Go BuildID:** `r_d2cS0iRCJyu30g1fkz/YicNTt1-kT0rcktDjY4L`
- **Stripped symbols:** Obfuscated to hinder reverse engineering
- **Stack protection:** No canary, making it vulnerable to buffer overflow exploitation (ironically)
- **NX enabled:** Code execution prevention on stack/heap

### Binary Structure

![Sections Entropy](screenshots/sections-entropy.png)

The binary contains typical Go sections with notable characteristics:

- **`.text` section:** 2,075,922 bytes of executable code
- **`.gopclntab`:** 2,062,426 bytes - Go program counter line table for debugging
- **`.rodata`:** 736,049 bytes of read-only data
- **No dynamic imports:** Completely self-contained

### Network Capabilities

![Network Strings](screenshots/network-strings.png)

String analysis reveals extensive HTTP/HTTPS networking capabilities:

1. **HTTP Clients:** Go-http-client/1.1 and Go-http-client/2.0 user agents
2. **Proxy Integration:** References to ProxyScrape.com for acquiring proxy lists
3. **Protocol Support:** TCP, UDP, HTTP/1.1, HTTP/2
4. **Encryption:** TLS 1.2/1.3, AES encryption for C2 communications

### Command & Control

![C2 Indicators](screenshots/c2-indicators.png)

The malware contains an embedded usage example revealing its DDoS capabilities:

```
Example: %s httpsproxy https://example.com 15000 15 -pd "key=value" -c "session=%RAND%"
```

**Command breakdown:**
- `httpsproxy`: Attack mode (HTTP/HTTPS proxy flood)
- Target URL: `https://example.com`
- `15000`: Request count or duration
- `15`: Thread count or intensity
- `-pd`: POST data parameters
- `-c`: Cookie injection with random session

### Attack Vectors

![Bot Commands](screenshots/bot-commands.png)

The malware supports multiple attack types:

1. **HTTP/HTTPS Flooding:** Volume-based application layer attacks
2. **TCP SYN Flooding:** Network layer exhaustion
3. **UDP Flooding:** Bandwidth consumption attacks
4. **Proxy-based Attacks:** Distributed attacks via scraped proxies

### Code Analysis

![Functions List](screenshots/functions-list.png)

Radare2 analysis identified **3,639 functions**, indicating a complex, feature-rich malware. The stripped binary suggests professional development practices.

![Disassembly Entry](screenshots/disassembly-entry.png)

The entry point shows standard Go runtime initialization, making dynamic analysis challenging due to the complexity of the Go runtime.

### Entropy Analysis

![Entropy](screenshots/entropy.png)

Binwalk entropy analysis shows no indicators of packing or encryption, confirming this is a standard Go-compiled binary with embedded resources.

## YARA Detection Rule

![YARA Test](screenshots/yara-test.png)

We developed and tested a YARA rule for detecting this malware family:

```yara
rule RISCV_Go_DDoS_Botnet {
    meta:
        description = "Detects RISC-V based Go DDoS botnet with HTTP/HTTPS proxy capabilities"
        author = "Peris.ai Threat Research Team"
        date = "2025-04-05"
        hash = "0a65892df4903823e00869e42a58403ef4e125bcb55838016e3cd227fb5f9635"
        severity = "high"
        
    strings:
        $buildid = "r_d2cS0iRCJyu30g1fkz/YicNTt1-kT0rcktDjY4L"
        $example_cmd = "Example: %s httpsproxy https://example.com 15000 15 -pd"
        $proxyscrape = "https://proxyscrape.com/" ascii
        $aes_key = "aesKey" ascii
        $http_client1 = "Go-http-client/1.1" ascii
        $http_client2 = "Go-http-client/2.0" ascii
        $tcp_dial = "DialTCP" ascii
        $udp_dial = "DialUDP" ascii
        $riscv_elf = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 f3 00 }
        
    condition:
        uint32(0) == 0x464c457f and
        filesize > 4MB and filesize < 10MB and
        (
            ($buildid and $riscv_elf) or
            ($example_cmd and $proxyscrape) or
            (all of ($http_client*) and all of ($tcp_dial, $udp_dial, $aes_key))
        )
}
```

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|----|-----------| 
| **Execution** | Command and Scripting Interpreter | T1059 | Executes DDoS commands via built-in interpreter |
| **Command & Control** | Application Layer Protocol - Web Protocols | T1071.001 | Uses HTTP/HTTPS for C2 communication |
| **Impact** | Network Denial of Service - Direct Network Flood | T1498.001 | TCP/UDP flooding capabilities |
| **Impact** | Endpoint Denial of Service - Service Exhaustion Flood | T1499.002 | HTTP/HTTPS application layer floods |
| **Resource Development** | Obtain Capabilities - Tool | T1588.002 | Acquires proxy lists from ProxyScrape |

## Indicators of Compromise (IOCs)

### File Hashes

| Hash Type | Value |
|-----------|-------|
| **SHA256** | `0a65892df4903823e00869e42a58403ef4e125bcb55838016e3cd227fb5f9635` |
| **File Type** | ELF 64-bit LSB executable, RISC-V |
| **Size** | 5,243,042 bytes |

### Network Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| **Domain** | `proxyscrape.com` | Proxy list source |
| **User-Agent** | `Go-http-client/1.1` | HTTP requests |
| **User-Agent** | `Go-http-client/2.0` | HTTP/2 requests |

### Behavioral Indicators

- High-volume outbound TCP/UDP connections
- Connections to ProxyScrape infrastructure
- RISC-V ELF processes with network activity
- Processes spawning multiple threads for network operations

## Detection Strategies

### Network-Based Detection (Brahma NDR)

```suricata
alert http any any -> any any (
    msg:"RISC-V Go DDoS Botnet - ProxyScrape C2 Communication";
    flow:established,to_server;
    content:"proxyscrape.com"; http_host; nocase;
    classtype:trojan-activity; sid:2900245; rev:1;
)

alert http any any -> any any (
    msg:"RISC-V Go DDoS Botnet - Suspicious Go HTTP Client User-Agent";
    flow:established,to_server;
    content:"Go-http-client/"; http_user_agent;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity; sid:2900246; rev:1;
)
```

### Endpoint Detection (Brahma XDR)

Monitor for:
1. Execution of RISC-V ELF binaries on unexpected systems
2. Processes with high network connection counts
3. Outbound connections to proxy infrastructure
4. Go-compiled binaries with statically-linked characteristics

## Recommendations

### Immediate Actions
1. **Block IOCs:** Prevent communication with ProxyScrape infrastructure
2. **Hunt for RISC-V processes:** Identify unauthorized RISC-V binaries on your network
3. **Monitor Go binaries:** Audit legitimate vs. malicious Go applications
4. **Deploy YARA rules:** Scan filesystems and network traffic

### Long-Term Mitigations
1. **Application Whitelisting:** Prevent unauthorized binary execution on RISC-V systems
2. **Network Segmentation:** Isolate IoT/embedded devices from critical infrastructure
3. **Egress Filtering:** Block outbound connections to known proxy services
4. **Firmware Updates:** Ensure RISC-V devices run latest security patches

### Detection Engineering
1. Deploy Brahma NDR rules for network visibility
2. Configure Brahma XDR for behavioral anomaly detection
3. Integrate YARA rules into scanning workflows
4. Enable threat hunting for Go-based malware

## Conclusion

The emergence of RISC-V-targeted malware represents a significant evolution in the threat landscape. As RISC-V adoption grows in IoT, edge computing, and embedded systems, we expect threat actors to increasingly develop malware for this architecture.

This DDoS botnet demonstrates sophisticated capabilities including:
- Multi-protocol attack vectors
- Proxy-based distribution for anonymity
- Encrypted C2 communications
- Professional development practices (Go, static linking, stripping)

Organizations deploying RISC-V systems should prioritize security monitoring and ensure detection capabilities extend to this emerging architecture.

---

**Detection rules, YARA signatures, and IOCs are available in our public threat intelligence repository.**

For questions or to report additional IOCs, contact: **threat-research@peris.ai**

## References

- MalwareBazaar Sample: https://bazaar.abuse.ch/sample/0a65892df4903823e00869e42a58403ef4e125bcb55838016e3cd227fb5f9635/
- MITRE ATT&CK Framework: https://attack.mitre.org/
- RISC-V Specification: https://riscv.org/specifications/

---

*© 2025 Peris.ai Threat Research Team. All rights reserved.*
