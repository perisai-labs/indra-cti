# Phishing Campaign: Fake Ministry of Transportation Portal

**Campaign:** Government Service Impersonation (SRUT Vehicle Type Testing)  
**Target:** Indonesian Transportation & Logistics Companies  
**First Seen:** 2026-01-12 (domain registration)  
**Status:** 🔴 **ACTIVE**  
**Severity:** CRITICAL  
**Classification:** TLP:WHITE

---

## Executive Summary

Sophisticated phishing campaign impersonating Indonesia's Ministry of Transportation (Kementerian Perhubungan) vehicle type testing registration system (SRUT - Sistem Registrasi Uji Tipe). The fake portal targets transportation companies, collecting employee credentials and potentially sensitive business documents.

**Impact:**
- Business email compromise (BEC)
- Unauthorized government portal access
- Credential stuffing attacks
- Targeted spear-phishing

---

## Technical Details

### Phishing Infrastructure

**Malicious Domain:**
```
ujitiperb-dehub-go.id
```

**Typosquatting Pattern:**
- Legitimate (expected): `ujitipe.kemenhub.go.id`
- Phishing: `ujitiperb-dehub-go.id`
- Technique: Letter substitution (`ujitipe` → `ujitiperb`) + abbreviation (`kemenhub` → `dehub`)

**Domain Registration:**
```
Registrar: PT Web Media Technology Indonesia (Hostinger)
Creation Date: 2026-01-12 08:32:36 UTC
Expiry: 2027-01-12 23:59:59 UTC
Age: ~6 weeks (newly registered)
Registrar Abuse: domains@hostinger.com
```

**Hosting Infrastructure:**
```
Provider: Hostinger International (AS47583)
Location: Jakarta, Indonesia
IPs:
  - 88.223.91.190    (Primary)
  - 185.124.137.191  (Secondary)
  - 91.108.119.14    (Historical)
  - 185.124.137.32   (Historical)
IPv6:
  - 2a02:4780:1c:90a:4b1e:acab:821e:a117
  - 2a02:4780:3b:1252:433a:52b6:9357:aad
Name Servers:
  - NS1.DNS-PARKING.COM
  - NS2.DNS-PARKING.COM
```

---

### Application Analysis

**Technology Stack:**
- Framework: Laravel (PHP)
- Frontend: Bootstrap, jQuery
- Authentication: Email + Password + CAPTCHA
- CSRF Protection: Enabled

**Login Endpoint:**
```
URL: https://ujitiperb-dehub-go.id/login
Method: POST
Parameters:
  - email (text input)
  - password (plaintext)
  - captcha (image-based)
  - _token (CSRF token)
```

**Credentials Collected:**
- Company/personal email addresses
- Passwords (likely reused across systems)
- CAPTCHA solutions

---

## IOC List

### Network Indicators

**Domains:**
```
ujitiperb-dehub-go.id
```

**IPv4 Addresses:**
```
88.223.91.190
185.124.137.191
91.108.119.14
185.124.137.32
```

**IPv6 Addresses:**
```
2a02:4780:1c:90a:4b1e:acab:821e:a117
2a02:4780:3b:1252:433a:52b6:9357:aad
```

**URLs:**
```
https://ujitiperb-dehub-go.id/
https://ujitiperb-dehub-go.id/login
https://ujitiperb-dehub-go.id/lupa-password
https://ujitiperb-dehub-go.id/captcha/default
```

### Name Servers
```
NS1.DNS-PARKING.COM
NS2.DNS-PARKING.COM
```

---

## MITRE ATT&CK Mapping

### Initial Access
- **T1566.002** — Phishing: Spearphishing Link

### Credential Access
- **T1056.003** — Input Capture: Web Portal Capture
- **T1589.001** — Gather Victim Identity Information: Credentials

### Collection
- **T1114** — Email Collection

### Exfiltration
- **T1041** — Exfiltration Over C2 Channel

---

## Detection Opportunities

### Network Indicators
- DNS queries for `ujitiperb-dehub-go.id`
- HTTP/HTTPS connections to listed IP addresses
- POST requests to `/login` endpoint
- Captcha image requests to `/captcha/default`

### Behavioral Indicators
- Users arriving from email/SMS links (not organic search)
- POST body contains `email=`, `password=`, `_token=` parameters
- Laravel session cookies (`laravel_session`)
- CSRF meta tags in HTML response

---

## Mitigation Recommendations

### Immediate Actions

1. **Network Blocking:**
   - Block domain at DNS/firewall: `ujitiperb-dehub-go.id`
   - Block IP addresses (all 4 IPv4 addresses listed)
   - Update email gateway URL blacklist

2. **User Notification:**
   - Alert users about phishing campaign
   - Warn against entering credentials on suspicious domains
   - Provide legitimate government domain for verification

3. **Hunt for Compromise:**
   - Check proxy/DNS logs for domain access
   - Identify users who visited the phishing site
   - Force password reset for compromised accounts

### Victim Response

**If credentials were submitted:**
1. **Immediate password reset** on all accounts using same password
2. **Enable MFA** on email and government portal accounts
3. **Monitor for suspicious activity** (unauthorized logins, BEC attempts)
4. **Report to IT security** for incident investigation

---

## Reporting Channels

**Abuse Reports:**
1. Hostinger Abuse: abuse@hostinger.com, report@abuseradar.com
2. PANDI (ID Domain Registry): abuse@pandi.id
3. Indonesian Ministry of Communication (Kominfo): aduankonten.id
4. Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/

---

## References

- Domain WHOIS: PANDI (ujitiperb-dehub-go.id)
- Hosting Provider: Hostinger International (AS47583)
- Legitimate Service: Ministry of Transportation SRUT System

---

## Timeline

| Date | Event |
|------|-------|
| 2026-01-12 | Domain `ujitiperb-dehub-go.id` registered |
| 2026-02-24 | Campaign identified and analyzed |
| 2026-02-24 | IOCs published to Indra CTI |

---

**Analysis:** Peris.ai Threat Research  
**Classification:** TLP:WHITE (Public sharing authorized)  
**Last Updated:** 2026-02-24
