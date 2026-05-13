# Snake Keylogger - PO Phishing Campaign (Feb 2026)

## Overview
- **Malware:** Snake Keylogger
- **Campaign:** PayPal (PO) phishing, Feb 2026
- **Delivery:** Phishing emails targeting Indonesian users

## Analysis Summary

Snake Keylogger detected in phishing campaign targeting PayPal users. The malware was distributed via phishing emails impersonating PayPal notifications.

### Key Findings
- Phishing emails impersonating PayPal payment confirmations
- Attachments contained Snake Keylogger payload
- Targeted credential harvesting capabilities

### Detection Rules
Refer to:
- `perisai-rules/ndr/malware/20260201-malware-snakekeylogger-po-phishing-feb2026.rules`
- `perisai-rules/xdr/malware/20260201-malware-snakekeylogger-po-phishing-feb2026.xml`

## MITRE ATT&CK Mapping
- T1566.001 - Spearphishing Attachment
- T1056.001 - Keylogging
- T1555 - Credentials from Password Stores

## IOCs
See rule files for IOC details.

## Date Analyzed
2026-02-01

## Tags
#snake-keylogger #phishing #keylogger #indonesia #paypal #credential-theft
