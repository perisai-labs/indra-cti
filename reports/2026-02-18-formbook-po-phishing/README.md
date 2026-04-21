# Formbook Infostealer: PO-Themed Phishing Campaign (Brazil) — 2026-02-18

**By Peris.ai Threat Research Team**  
**Severity:** HIGH | **TLP:** WHITE | **Family:** Formbook

---

## Summary

A Formbook infostealer campaign targeting Brazil via Purchase Order (PO)-themed phishing was analyzed on 2026-02-18. The sample uses an AutoIt3-compiled loader to decrypt and inject the Formbook payload into `svchost.exe` via process hollowing.

The campaign was delivered as `rFebOder-PO557_pdf.exe`, mimicking a PDF document. The loader was compiled approximately 24 hours before first submission.

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| SHA256 (loader) | `892bc644461156b75443af62eb4b44e88b0ad36f9c19dad0bb6064be7a612db7` |
| SHA256 (payload) | `e82cd956175c5f40ba26a0f13d06f6ead48b3b9c5623d766ec9dfdd0c26fabfa` |
| Filename | `rFebOder-PO557_pdf.exe` |
| Dropped File | `polygamodioecious` (%TEMP%) |
| C2 Domain | `rogsidus.store` |
| C2 Domain | `iaoqiaonet.com` |
| Mutex | `\BaseNamedObjects\6-450OAE02468WZz` |
| Mutex | `\BaseNamedObjects\5N0NO7658UY-E89K` |

---

## Infection Chain

1. Victim receives PO-themed email with `.exe` attachment disguised as PDF
2. AutoIt3 EA06 compiled loader executes
3. Embedded payload `polygamodioecious` dropped to `%TEMP%`
4. XOR-encrypted shellcode decrypted (key: `Tc55s2WqM`)
5. VirtualAlloc + shellcode execution at offset `+0x23b0`
6. Formbook DLL injected into `svchost.exe` (SysWOW64) via process hollowing
7. Formbook establishes HTTP C2 to `rogsidus.store` / `iaoqiaonet.com`

---

## MITRE ATT&CK Mapping

| ID | Technique |
|----|-----------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1059 | AutoIT Compiled Script |
| T1027 | Obfuscated Files (XOR, AutoIt bytecode encryption) |
| T1036.007 | Masquerading: Double Extension |
| T1055.012 | Process Hollowing → svchost.exe |
| T1555.003 | Credentials from Web Browsers |
| T1056.001 | Keylogging |
| T1071.001 | HTTP C2 |
| T1041 | Exfiltration Over C2 Channel |

---

## Detection

- **YARA:** See `/yara/malware/formbook-po-phishing-feb2026.yar`
- **IOC CSV:** See `/feeds/daily/2026-02-18.csv`
- **VT Detections:** 42/76 engines

---

## References

- [MalwareBazaar](https://bazaar.abuse.ch/sample/892bc644461156b75443af62eb4b44e88b0ad36f9c19dad0bb6064be7a612db7/)
- [VirusTotal](https://www.virustotal.com/gui/file/892bc644461156b75443af62eb4b44e88b0ad36f9c19dad0bb6064be7a612db7)
- [MITRE Formbook](https://attack.mitre.org/software/S0401/)

---

*Peris.ai Threat Research | TLP: WHITE — may be shared freely*
