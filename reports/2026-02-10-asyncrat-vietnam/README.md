# AsyncRAT — Vietnam Campaign

**Date:** 2026-02-10
**Severity:** HIGH
**Category:** Remote Access Trojan
**Source:** MalwareBazaar

## Summary

A .NET-based AsyncRAT sample was identified originating from Vietnam, built from the publicly available AsyncRAT-C# project. The sample uses anti-analysis techniques, AES-256 encrypted command-and-control communication, and leverages Pastebin for dynamic C2 configuration retrieval.

## Sample Information

| Property | Value |
|----------|-------|
| SHA256 | `1ab4672076f63692e67555ebea72d9d7593928012ea7277776057e354d70364d` |
| MD5 | `6782b6d750b717ea2c048b8ee00ece17` |
| File Type | PE32 .NET executable |
| Family | AsyncRAT |
| Origin | Vietnam |

## Technical Analysis

### Persistence

The binary establishes persistence via a Windows Registry Run key at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, ensuring execution on user login.

### Anti-Analysis

Multiple evasion techniques are present:
- Debugger detection via `CheckRemoteDebuggerPresent` and `IsDebuggerPresent`
- Virtual machine detection through WMI queries
- Sleep prevention using `SetThreadExecutionState` to avoid sandbox timeout-based analysis

### Command and Control

C2 communication is encrypted with AES-256 and authenticated using HMAC-SHA256. Rather than hardcoding C2 addresses, the sample retrieves its configuration dynamically from Pastebin, making infrastructure takedown more difficult.

### Build Artifacts

The PDB path `D:\Cong Viec\malware\AsyncRAT-C-Sharp\` indicates a Vietnamese-language build environment. "Cong Viec" translates to "Work" in Vietnamese.

## MITRE ATT&CK

| Technique | ID | Usage |
|-----------|----|-------|
| Registry Run Keys | T1547.001 | Persistence via HKCU Run key |
| Symmetric Cryptography | T1573.001 | AES-256 encrypted C2 channel |
| System Checks | T1497.001 | VM/sandbox detection |
| Debugger Evasion | T1622 | Anti-debug API calls |
| Web Service | T1102 | Pastebin for dynamic C2 config |

## Indicators of Compromise

### Hashes

| Type | Value |
|------|-------|
| SHA256 | `1ab4672076f63692e67555ebea72d9d7593928012ea7277776057e354d70364d` |
| MD5 | `6782b6d750b717ea2c048b8ee00ece17` |

### Network

| Indicator | Context |
|-----------|---------|
| `pastebin.com` | Dynamic C2 configuration hosting |

### Artifacts

| Indicator | Context |
|-----------|---------|
| `AsyncRAT.pdb` | Debug symbol reference |

## Detection

A YARA rule for this family is available at [`yara/malware/asyncrat-vietnam-2026.yar`](../../yara/malware/asyncrat-vietnam-2026.yar).

## Recommendations

1. Block or monitor Pastebin traffic at the proxy layer if not required for business operations
2. Alert on .NET processes creating Registry Run keys with unknown binaries
3. Monitor for `SetThreadExecutionState` calls from unsigned executables
4. Deploy the provided YARA rule for endpoint scanning

---

*Indra CTI by Peris.ai*
