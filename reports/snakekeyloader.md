# Snake Keylogger - Credential Theft

## Description
Snake Keylogger is a commercial keylogger malware sold on underground forums. Capable of:
- Keylogging (all keyboard input)
- Taking screenshots
- Clipboard monitoring
- Stealing saved passwords from browsers
- Webcam access

## Distribution
Primarily via phishing emails with malicious attachments.

## Detection
- YARA rules for Snake Keylogger variants
- Network signatures (C2 communication)
- Behavioral detection (keylogging, screenshot capture)

## MITRE ATT&CK
- T1056.001 - Keylogging
- T1113 - Screen Capture
- T1555 - Credentials from Password Stores

## Tags
#snake-keylogger #keylogger #infostealer #credential-theft
