# Malware Analysis: Stage5 Final Payload — Multi-Stage Attack Component

**By Peris.ai Threat Research Team**  
**Date:** March 14, 2026  
**Severity:** High  
**Malware Family:** Unknown Loader/Injector

---

## Executive Summary

This report presents a comprehensive reverse engineering analysis of a Windows x64 PE executable discovered in the wild, identified as **stage5_final_payload.bin**. The sample demonstrates sophisticated anti-debugging techniques, code injection capabilities, and multi-threading synchronization patterns commonly associated with modern malware loaders and injectors.

### Key Findings
- **Anti-debugging techniques** using `SetUnhandledExceptionFilter`
- **Code injection preparation** via `VirtualProtect/VirtualProtectEx` APIs
- **Atomic synchronization operations** for multi-threaded execution
- **Sleep-based evasion** to bypass sandbox detection
- **Unusual PE section** named `.llc` (potential packer/obfuscation signature)

---

## Sample Information

| Attribute | Value |
|-----------|-------|
| **File Name** | stage5_final_payload.bin |
| **File Type** | PE32+ executable (Windows x64) |
| **File Size** | 2,494,092 bytes (2.4 MB) |
| **MD5** | `ec7641e10208558fc17ba4d6d990f94e` |
| **SHA1** | `2038c537e9c5045844ea5ae4c7e9513937f882e6` |
| **SHA256** | `0bc2a9d8c2aa8639da0aa5389c773f368dcf1cefbc66996c2736532afec08c04` |
| **Compile Time** | Sun Aug 16 16:29:55 2015 (potentially falsified) |
| **Source** | MalwareBazaar (abuse.ch) |
| **Origin Country** | United States |

---

## Static Analysis

### File Structure

![File Info](screenshots/file-info.png)

The sample is a 64-bit PE executable compiled for Windows 5.02 (Windows Server 2003/XP x64), though this target OS version may be falsified. Key characteristics:

- **Architecture:** x86-64
- **Subsystem:** Windows GUI
- **Sections:** 12 (unusual — typical binaries have 4-6)
- **Security Features:** Stack canary enabled, NX (DEP) enabled, PIE enabled
- **Stripped:** Yes (no debug symbols)

### PE Sections Analysis

![Sections Entropy](screenshots/sections-entropy.png)

Notable sections:

| Section | Virtual Size | Permissions | Notes |
|---------|-------------|-------------|-------|
| `.text` | 0x20B000 | r-x | Code section |
| `.data` | 0xE000 | rw- | Initialized data |
| `.rdata` | 0x3B000 | r-- | Read-only data (imports, strings) |
| `.bss` | 0x97000 | rw- | Uninitialized data (large — suspicious) |
| **`.llc`** | **0x1000** | **rw-** | **Unusual section name** |

The `.llc` section is particularly suspicious — not a standard Microsoft linker section name. This may indicate a custom packer, loader, or obfuscation tool.

### Import Analysis

![Imports](screenshots/imports.png)

**Key Imported DLLs:**
- `KERNEL32.dll` — Core Windows APIs
- `ADVAPI32.dll` — Registry access
- `msvcrt.dll` — C runtime
- `USER32.dll` — Minimal GUI (GetKeyNameTextW only)

**Suspicious Imports:**

| API Function | Purpose | MITRE Technique |
|--------------|---------|-----------------|
| `SetUnhandledExceptionFilter` | Anti-debugging | T1497.001 |
| `VirtualProtect` | Change memory permissions | T1055 (Process Injection) |
| `VirtualProtectEx` | Remote memory permission change | T1055 |
| `LoadLibraryA` | Dynamic DLL loading | T1129 |
| `GetProcAddress` | Dynamic API resolution | T1027 (Obfuscation) |
| `Sleep` | Evasion technique | T1497.003 |
| `TlsAlloc/TlsGetValue/TlsSetValue` | Thread-local storage | - |

The combination of `VirtualProtect*` and dynamic API resolution strongly suggests **code injection** capabilities.

### Strings Analysis

![Strings](screenshots/strings.png)

String analysis revealed **minimal cleartext strings** — most data appears obfuscated or encoded. This indicates:
- **Runtime string decryption** (common in modern malware)
- **Packing or compression** of payload
- **Anti-analysis technique** to hinder static analysis

---

## Reverse Engineering

### Entry Point Analysis

![Disassembly Entry](screenshots/disassembly-entry.png)

The entry point (`0x140001157`) performs a simple initialization:

```asm
push    rbp
mov     rbp, rsp
sub     rsp, 0x30
mov     dword [var_4h], 0xff
call    fcn.1400011b5          ; Main function
mov     dword [var_4h], eax
add     rsp, 0x30
pop     rbp
ret
```

Key observations:
- Standard function prologue
- Calls main function (`fcn.1400011b5`)
- Returns exit code

### Main Function Analysis

![Disassembly Main](screenshots/disassembly-main.png)

The main function (`fcn.1400011b5`) implements a **spin-lock synchronization pattern**:

```asm
; Read TLS (Thread Local Storage) data
mov     eax, 0x30
mov     rax, qword gs:[rax]      ; Get TEB (Thread Environment Block)
mov     qword [var_28h], rax
mov     rax, qword [rax + 8]     ; Read TLS slot
mov     qword [var_18h], rax

; Spin-lock loop with atomic compare-exchange
.loop:
    mov     rax, qword [var_10h]
    cmp     rax, qword [var_18h]
    jne     .sleep
    mov     dword [var_4h], 1
    jmp     .exit

.sleep:
    mov     ecx, 0x3e8            ; Sleep(1000)
    call    Sleep
    
    ; Atomic compare-exchange (synchronization)
    lock cmpxchg qword [rdx], rcx
    mov     qword [var_10h], rax
    cmp     qword [var_10h], 0
    jne     .loop
```

**Behavioral Analysis:**

1. **TLS Access:** Reads thread-local storage — multi-threading support
2. **Spin-lock:** Implements atomic `lock cmpxchg` for thread synchronization
3. **Sleep Loop:** Delays execution by 1 second per iteration (evasion)
4. **State Machine:** Checks global state variables, exits conditionally

This pattern is typical of **multi-stage loaders** that:
- Wait for a previous stage to complete
- Synchronize across multiple threads
- Evade sandbox detection via time delays

### Anti-Debugging Detection

The binary calls `SetUnhandledExceptionFilter` early in execution:

```asm
mov     rax, qword [exception_handler_ptr]
mov     rcx, rax
call    SetUnhandledExceptionFilter
```

**MITRE ATT&CK:** T1497.001 (Virtualization/Sandbox Evasion - System Checks)

This API is commonly abused by malware to:
- Detect debuggers (debuggers intercept exceptions)
- Terminate when analysis tools are detected
- Transfer control flow to anti-analysis routines

---

## Behavioral Indicators

### MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|--------|-----------|--------------|----------|
| **Defense Evasion** | Virtualization/Sandbox Evasion | T1497.003 | Sleep loops with 1000ms delays |
| **Defense Evasion** | Debugger Evasion | T1497.001 | SetUnhandledExceptionFilter usage |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Minimal strings, dynamic API resolution |
| **Execution** | Shared Modules | T1129 | LoadLibraryA/GetProcAddress |
| **Privilege Escalation / Defense Evasion** | Process Injection | T1055 | VirtualProtect/VirtualProtectEx |

### TTPs Summary

- **Anti-Analysis:** SetUnhandledExceptionFilter, stripped symbols, obfuscated strings
- **Evasion:** Sleep-based delays, TLS synchronization
- **Code Injection:** VirtualProtect APIs, dynamic API resolution
- **Multi-Stage:** Name suggests part of a larger attack chain ("stage5")

---

## Detection & Response

### YARA Rule

![YARA Test](screenshots/yara-test.png)

**Tested and validated** against the sample:

```yara
rule Win64_Stage5_FinalPayload_Mar2026 {
    meta:
        description = "Detects stage5 final payload (multi-stage attack chain component)"
        author = "Peris.ai Threat Research Team"
        date = "2026-03-14"
        hash = "0bc2a9d8c2aa8639da0aa5389c773f368dcf1cefbc66996c2736532afec08c04"
        severity = "high"
        
    strings:
        $api_anti_debug = "SetUnhandledExceptionFilter" ascii
        $api_virt_protect = "VirtualProtect" ascii
        $api_virt_protect_ex = "VirtualProtectEx" ascii
        $atomic_op = { F0 48 0F B1 }  // lock cmpxchg qword ptr
        $sleep_loop = { B9 E8 03 00 00 48 8B 05 ?? ?? ?? ?? FF D0 }
        $section_llc = ".llc" ascii
        $entry_pattern = { 55 48 89 E5 48 83 EC 30 }
        
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 3MB and
        filesize > 2MB and
        (
            ($api_anti_debug and $api_virt_protect and $atomic_op and $sleep_loop) or
            (3 of ($api_*) and $section_llc and $entry_pattern)
        )
}
```

**Validation Results:**
- ✅ All critical strings detected
- ✅ Atomic operation pattern matched at offset `0x634`
- ✅ Sleep loop pattern matched at offset `0x5ff`
- ✅ Entry point pattern detected (8 instances)

### Brahma XDR Rules

**Rule ID 100001:** SHA256 hash-based detection (highest confidence)
**Rule ID 100002:** Heuristic process behavior detection (file size + naming pattern)
**Rule ID 100003:** Anti-debugging API call detection
**Rule ID 100004:** Code injection pattern (VirtualProtect after Sleep)
**Rule ID 100005:** Composite behavioral signature (`.llc` section + API calls)

**Deployment:** Import rules to Brahma XDR Manager for endpoint detection.

### Brahma NDR Rules (Suricata Format)

**SID 9000001:** Detect PE file transfer with matching SHA256
**SID 9000002:** Detect HTTP downloads with "stage/payload" naming
**SID 9000003:** Detect PE executables in HTTP POST (C2/exfiltration)
**SID 9000004:** Detect TLS connections from suspicious processes
**SID 9000005-9000006:** DNS-based C2 detection (DGA patterns)

**Deployment:** Deploy to Brahma NDR/Suricata for network-layer detection.

### Indra Threat Intelligence Integration

**Recommended Actions:**
1. **Import IOCs** into Indra platform (hashes, file size, section names)
2. **Enable behavioral alerts** for processes exhibiting spin-lock patterns
3. **Monitor TLS/SetUnhandledExceptionFilter** API calls in suspicious executables
4. **Correlate with multi-stage attack campaigns** (search for "stage1" - "stage4" variants)

---

## IOCs (Indicators of Compromise)

### File Hashes

```
MD5:    ec7641e10208558fc17ba4d6d990f94e
SHA1:   2038c537e9c5045844ea5ae4c7e9513937f882e6
SHA256: 0bc2a9d8c2aa8639da0aa5389c773f368dcf1cefbc66996c2736532afec08c04
```

### File Characteristics

- **Size:** 2,494,092 bytes
- **PE Section:** `.llc` (unusual)
- **Compile Timestamp:** Sun Aug 16 16:29:55 2015 (likely falsified)

### Behavioral Indicators

- Process executing `SetUnhandledExceptionFilter` within first 5 seconds
- Repeated `Sleep(1000)` calls in tight loop
- `VirtualProtect/VirtualProtectEx` calls without legitimate DLL loading
- TLS access patterns combined with atomic operations

---

## Recommendations

### Immediate Actions
1. **Block execution** of the SHA256 hash across all endpoints
2. **Hunt for variants** using the YARA rule (check for other "stage*" files)
3. **Inspect parent processes** of any detected instances (how was it dropped?)
4. **Network analysis:** Search logs for unusual HTTP/TLS connections from affected hosts

### Long-Term Mitigations
1. **Deploy Brahma XDR rules** to detect behavioral patterns
2. **Enable Brahma NDR** for network-level detection
3. **Update endpoint policies** to block unsigned executables with unusual section names
4. **Implement application whitelisting** for critical systems

### Threat Intelligence
- **Monitor for variants:** Search MalwareBazaar/VirusTotal for similar samples
- **Investigate campaign:** Identify "stage1" through "stage4" components
- **Attribution:** Track TTPs to identify potential threat actor groups

---

## Conclusion

The analyzed sample represents a **sophisticated multi-stage malware component** with advanced anti-debugging and code injection capabilities. While network C2 indicators were not identified through static analysis (likely encrypted or resolved at runtime), the behavioral patterns strongly suggest this is a **loader or injector** designed to:

1. Synchronize execution with other malware stages
2. Evade sandbox and debugging environments
3. Inject code into legitimate processes
4. Maintain persistence through multi-threading

The naming convention ("stage5_final_payload") indicates this is part of a **larger attack chain**. Organizations should proactively hunt for related components and implement the provided detection rules.

**Severity Assessment:** **HIGH**  
**Recommended Response:** **Immediate containment and investigation**

---

## References

- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **MalwareBazaar Sample:** https://bazaar.abuse.ch/sample/0bc2a9d8c2aa8639da0aa5389c773f368dcf1cefbc66996c2736532afec08c04/
- **Peris.ai Products:** Brahma XDR, Brahma NDR, Indra Threat Intelligence, Fusion SOAR

---

**Analyzed by:** Peris.ai Threat Research Team  
**Tools Used:** Radare2, Ghidra, YARA, binwalk, Python (pefile, LIEF)  
**Analysis Date:** March 14, 2026  
**Report Version:** 1.0

---

*For questions or additional threat intelligence, contact: research@peris.ai*

**TLP:WHITE** — Disclosure is not limited.
