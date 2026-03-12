# Pulsar RAT Analysis: Advanced njRAT Variant with HVNC Capabilities

**By Peris.ai Threat Research Team**  
**Date:** March 12, 2026  
**Sample Hash:** `3ff05f14a134b5bc60770b15cd326719052f1c4f42bf3d6aa7bfa47116a97877`

---

## Executive Summary

Our analysis reveals a sophisticated variant of njRAT (also known as Bladabindi), branded as "Pulsar RAT." This .NET-based remote access trojan demonstrates advanced capabilities including hidden virtual network computing (HVNC) for multiple browsers, keylogging, screen/webcam streaming, and robust persistence mechanisms. The malware leverages MessagePack serialization for efficient C2 communication and employs anti-VM detection techniques.

**Severity:** High  
**Classification:** Remote Access Trojan (RAT)  
**Platform:** Windows (x86 PE32)

---

## Technical Analysis

### File Information

![File Info](screenshots/file-info.png)

**Key Metadata:**
- **File Type:** PE32 executable (.NET assembly)
- **Architecture:** x86 (32-bit)
- **Language:** CIL (Common Intermediate Language)
- **Size:** 954 KB
- **Compilation Date:** September 23, 2058 (likely tampered)
- **Stack Canary:** Enabled

### Static Analysis

#### Sections & Entropy

![Sections Entropy](screenshots/sections-entropy.png)

The binary exhibits typical .NET assembly characteristics with embedded compressed DLLs using Costura embedding framework.

#### Embedded Libraries

![Interesting Strings](screenshots/interesting-strings.png)

The malware embeds several compressed libraries:
- **MessagePack** (v3.1.4.0) - High-performance binary serialization
- **Pulsar.Common** (v2.4.5.0) - Core RAT framework
- **System.Collections.Immutable** (v8.0.0.0)
- **System.Memory** (v4.0.1.2)

These libraries indicate a modern, performance-optimized C2 protocol using MessagePack for efficient data serialization over the network.

### RAT Capabilities

![Capabilities](screenshots/capabilities.png)

#### Core Features

1. **Keylogging**
   - `KeyloggerService` - Full keystroke capture
   - `SendClipboardData` - Clipboard monitoring

2. **Screen & Webcam Surveillance**
   - `StartScreenStreaming` - Real-time screen capture
   - `StartWebcamStreaming` - Webcam access
   - `mciSendStringA` - Media control interface

3. **Hidden VNC (HVNC)**
   - `ProcessController` - Browser process manipulation
   - `StartChromeAsync` - Chrome browser control
   - `StartEdgeAsync` - Edge browser control
   - `StartBraveAsync` - Brave browser control
   - `StartOperaAsync` - Opera browser control

4. **Persistence Mechanisms**
   - `DoAddWinREPersistence` - Windows Recovery Environment persistence
   - `DoStartupItemAdd` - Startup folder persistence
   - Registry Run keys manipulation

5. **Process Manipulation**
   - `DoProcessStart` - Process creation
   - `DoProcessEnd` - Process termination
   - `DoProcessDump` - Memory dumping

6. **Registry Operations**
   - `DoChangeRegistryValue`
   - `DoCreateRegistryKey`
   - `DoDeleteRegistryKey`
   - `DoRenameRegistryValue`

7. **Command Execution**
   - `DoShellExecute` - Shell command execution
   - `DoSendQuickCommand` - Fast command dispatch

8. **Network Operations**
   - `GetReverseProxyByConnectionId` - Reverse proxy functionality
   - `UnsafeStreamCodec` - Custom network codec
   - `GetConnectionsResponse` - Connection management

### Anti-Analysis Features

![Functions List](screenshots/functions-list.png)

- `PortConnectionAntiVM` - Virtual machine detection
- Custom string obfuscation through Costura compression
- Embedded DLL loading to avoid static detection

### Disassembly Analysis

![Disassembly Entry](screenshots/disassembly-entry.png)

The entry point follows standard .NET CLR initialization patterns, with the main payload loaded dynamically from embedded resources.

---

## Behavioral Analysis

### Network Communication

The malware establishes TCP connections to remote C2 servers using MessagePack-serialized payloads. Communication characteristics:

- **Protocol:** Custom binary protocol over TCP
- **Serialization:** MessagePack
- **Encryption:** TLS/SSL capable
- **Codec:** `UnsafeStreamCodec` for performance

### Persistence Strategy

1. **Registry Run Keys:**
   ```
   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   HKLM\Software\Microsoft\Windows\CurrentVersion\Run
   ```

2. **Windows Recovery Environment (WinRE):**
   - Modifies WinRE configuration for pre-boot persistence

3. **Startup Folder:**
   - Drops copies to user/system startup directories

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| **Execution** | T1204 | User Execution |
| **Persistence** | T1547.001 | Registry Run Keys / Startup Folder |
| **Persistence** | T1542.001 | Pre-OS Boot: System Firmware |
| **Defense Evasion** | T1497 | Virtualization/Sandbox Evasion |
| **Credential Access** | T1056.001 | Input Capture: Keylogging |
| **Collection** | T1113 | Screen Capture |
| **Collection** | T1125 | Video Capture |
| **Collection** | T1115 | Clipboard Data |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols |
| **Command and Control** | T1090 | Proxy: Internal Proxy |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel |

---

## Indicators of Compromise (IOCs)

### File Hashes

| Algorithm | Hash |
|-----------|------|
| **SHA256** | `3ff05f14a134b5bc60770b15cd326719052f1c4f42bf3d6aa7bfa47116a97877` |
| **File Name** | `Client.exe` |

### Detection Strings

- `costura.messagepack.dll.compressed`
- `costura.pulsar.common.dll.compressed`
- `KeyloggerService`
- `StartWebcamStreaming`
- `StartScreenStreaming`
- `PortConnectionAntiVM`
- `DoAddWinREPersistence`
- `ProcessController`

### Registry Keys

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

### Network Indicators

- Outbound TCP connections to high ports (4000-65535)
- MessagePack binary serialization signatures in traffic

---

## Detection & Response

### YARA Rule

![YARA Test](screenshots/yara-test.png)

```yara
rule PulsarRAT_njRAT_Variant {
    meta:
        description = "Detects Pulsar RAT (njRAT variant) with MessagePack-based C2"
        author = "Peris.ai Threat Research Team"
        date = "2026-03-12"
        hash = "3ff05f14a134b5bc60770b15cd326719052f1c4f42bf3d6aa7bfa47116a97877"
        severity = "high"
        
    strings:
        // Embedded libraries
        $lib1 = "costura.messagepack.dll.compressed" ascii
        $lib2 = "costura.pulsar.common.dll.compressed" ascii
        
        // RAT capabilities
        $cap1 = "KeyloggerService" ascii
        $cap2 = "StartWebcamStreaming" ascii
        $cap3 = "StartScreenStreaming" ascii
        $cap4 = "DoAddWinREPersistence" ascii
        $cap5 = "DoShellExecute" ascii
        
        // HVNC capabilities
        $hvnc1 = "ProcessController" ascii
        $hvnc2 = "StartChromeAsync" ascii
        $hvnc3 = "StartEdgeAsync" ascii
        
        // Anti-analysis
        $anti1 = "PortConnectionAntiVM" ascii
        
    condition:
        uint16(0) == 0x5A4D and 
        filesize < 2MB and
        (
            ($lib1 and $lib2) or
            (4 of ($cap*)) or
            (all of ($hvnc*)) or
            ($anti1 and 3 of ($cap*))
        )
}
```

### Brahma XDR Detection Rule

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rule id="pulsar_rat_detection" version="1.0" severity="high">
  <name>Pulsar RAT / njRAT Variant Detection</name>
  <description>Detects Pulsar RAT activity including process creation, persistence, and C2 communication</description>
  
  <correlation>
    <and>
      <or>
        <event source="windows.process">
          <match field="image_path" pattern="(?i)Client\.exe$" />
          <match field="parent_process" pattern="(?i)(explorer|cmd|powershell)" />
        </event>
        
        <event source="windows.registry">
          <match field="path" pattern="(?i)Software\\Microsoft\\Windows\\CurrentVersion\\Run" />
          <match field="operation" value="SetValue" />
        </event>
        
        <event source="windows.module_load">
          <match field="module" pattern="(?i)MessagePack\.dll" />
        </event>
      </or>
      
      <event source="windows.network">
        <match field="direction" value="outbound" />
        <match field="protocol" value="TCP" />
        <match field="destination_port" range="4000-65535" />
      </event>
    </and>
  </correlation>
  
  <actions>
    <alert priority="high" />
    <quarantine enabled="true" />
    <collect_evidence types="process_memory,network_packet,registry" />
  </actions>
</rule>
```

### Brahma NDR Detection Rules

```suricata
# Pulsar RAT / njRAT C2 Communication Detection

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"PERIS MALWARE Pulsar RAT Outbound C2 Connection"; flow:established,to_server; content:"|1f 8b 08|"; depth:3; content:"MessagePack"; distance:0; classtype:trojan-activity; sid:1000001; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"PERIS MALWARE Pulsar RAT Keylogger Data Exfiltration"; flow:established,to_server; content:"KeyloggerService"; nocase; classtype:trojan-activity; sid:1000002; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"PERIS MALWARE Pulsar RAT Screen Streaming"; flow:established,to_server; content:"StartScreenStreaming"; nocase; classtype:trojan-activity; sid:1000003; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"PERIS MALWARE Pulsar RAT Shell Command Execution"; flow:established,to_client; content:"DoShellExecute"; nocase; classtype:trojan-activity; sid:1000004; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"PERIS MALWARE Pulsar RAT HVNC Browser Control"; flow:established,to_server; content:"ProcessController"; nocase; pcre:"/Start(Chrome|Edge|Brave|Opera)Async/i"; classtype:trojan-activity; sid:1000005; rev:1;)
```

---

## Recommendations

### Immediate Actions

1. **Hunt for IOCs** across your environment using provided signatures
2. **Block C2 communication** at network perimeter
3. **Scan for persistence** in Registry Run keys and WinRE
4. **Deploy detection rules** to Brahma XDR/NDR platforms

### Prevention Measures

1. **Application Whitelisting** - Prevent execution of unsigned .NET assemblies
2. **Network Segmentation** - Limit outbound connections to uncommon ports
3. **Endpoint Hardening** - Disable WinRE modifications for standard users
4. **User Awareness** - Train users to identify phishing/social engineering vectors

### Monitoring

1. Monitor for:
   - Process creation of `Client.exe` or similar generic names
   - Registry modifications to Run keys
   - Unusual MessagePack DLL loading
   - Outbound connections with MessagePack payloads
   - Webcam/microphone access by non-standard processes

---

## Conclusion

Pulsar RAT represents an evolution of the njRAT family, incorporating modern serialization frameworks (MessagePack), sophisticated browser control capabilities (HVNC), and robust persistence mechanisms. Its modular architecture and anti-analysis features make it a potent threat to enterprise environments.

Organizations should prioritize deploying the provided detection rules and conducting thorough threat hunts using the IOCs outlined in this analysis.

---

**Attribution:** This analysis is part of Peris.ai's ongoing threat intelligence research. For more information about Brahma XDR, Brahma NDR, and Fusion SOAR capabilities, visit [peris.ai](https://peris.ai).

**Tags:** #ThreatIntel #MalwareAnalysis #RAT #njRAT #PulsarRAT #DFIR #ReverseEngineering
