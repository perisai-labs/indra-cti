# Weekly Deep-Dive: FIRESTARTER Backdoor — UAT-4356 (ArcaneDoor) Persistence on Cisco Firewalls

> **Date:** 2026-04-27 | **Analyst:** Xhavero | **Classification:** HIGH
> **Category:** Malware Analysis / APT Persistence / Network Infrastructure
> **Threat Actor:** UAT-4356 (Cisco Talos) — tracked as ArcaneDoor

---

## Executive Summary

FIRESTARTER is a sophisticated Linux ELF backdoor deployed on compromised Cisco Firepower and Secure Firewall devices running ASA or FTD software. Jointly analyzed by CISA and the UK's NCSC and published April 23, 2026, it represents one of the most advanced persistence mechanisms ever discovered on network perimeter infrastructure.

**What makes FIRESTARTER notable:**
- **Post-patching persistence** — survives firmware updates, security patches, and soft reboots
- **LINA process hooking** — injects shellcode into Cisco's core network processing engine
- **Signal-based resurrection** — registers handlers for 6 termination signals to relaunch on any graceful shutdown
- **Transient on-disk footprint** — deletes its own binary after hook installation
- **WebVPN C2 channel** — triggered via crafted WebVPN XML with hardcoded auth tokens
- **ArcaneDoor lineage** — same APT group (UAT-4356) behind perimeter device espionage

**Kill chain (CISA FCEB case):**
1. Sept 2025: Initial exploit via CVE-2025-20333 and/or CVE-2025-20362
2. LINE VIPER deployed as post-exploitation VPN session creator
3. FIRESTARTER installed as persistence backdoor
4. Oct 2025: Cisco patches issued (ED 25-03) — FIRESTARTER **survived**
5. March 2026: FIRESTARTER used to redeploy LINE VIPER — 6 months later

**Severity:** CRITICAL — Infrastructure-level persistence on network perimeter devices

---

## Technical Deep-Dive

### Execution Flow

```
1. Read /usr/bin/lina_cs into heap
2. Register signal handlers (SIGTERM, SIGINT, SIGQUIT, SIGABRT, SIGHUP, SIGTSTP)
3. Self-cleanup: restore CSP_MOUNT_LIST, delete lina_cs, wipe traces
4. On shutdown/reboot (runlevel 6 or signals):
   a. mkdir -p /opt/cisco/platform/logs/var/log/
   b. Write self to svc_samcore.log
   c. Append boot commands to CSP_MOUNT_LIST
5. On next boot: FXOS runs CSP_MOUNT_LIST -> lina_cs restarted
6. Enumerate LINA /proc/[pid]/maps -> find rw-p segment
7. Locate XML Handler element table (0x260-byte entries) -> element 17 pointer
8. Find libstdc++.so r-xp segment -> inject Stage 2 shellcode at -0x200
9. Overwrite XML handler pointer -> detour to shellcode
10. WebVPN XML request with magic bytes -> exec attacker payload in LINA
```

### Phase 1: Initialization & Signal Registration

FIRESTARTER opens `/usr/bin/lina_cs`, maps into heap, registers callback for 6 signals:
SIGTERM(15), SIGINT(2), SIGQUIT(3), SIGABRT(6), SIGHUP(1), SIGTSTP(20)

ANY graceful process termination triggers persistence callback.

### Phase 2: Anti-Forensics

```bash
rm /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST
cp /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST.tmp /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST
chmod 755 /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST
chown --reference=/opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST.tmp /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST
touch -r /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST.tmp /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST
rm /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST.tmp
rm /usr/bin/lina_cs
```

All stderr -> /dev/null. File ownership + timestamps preserved. Binary deleted after hooking.

### Phase 3: Transient Persistence

On termination signal or runlevel 6 (reboot):
1. Creates `/opt/cisco/platform/logs/var/log/` (rwx)
2. Writes self to `svc_samcore.log`
3. Appends to `CSP_MOUNT_LIST`:
```bash
mv /opt/cisco/platform/logs/var/log/svc_samcore.log /usr/bin/lina_cs
chmod 755 /usr/bin/lina_cs
lina_cs &
```

Survives because log dir + mount list are config storage, not overwritten by firmware. Only **cold reboot (power cycle)** clears in-memory hooks.

### Phase 4: LINA Memory Hooking

Scans `/proc/[pid]/maps` for LINA's `rw-p` segment. Parses XML Handler element table (0x260-byte entries). Finds 5 element IDs at correct offsets. Stores pointer to 17th element handler.

Scans for `libstdc++.so` `r-xp` segment. Injects Stage 2 shellcode at `text_end - 0x200`. Overwrites XML handler pointer with shellcode address. Uses `mprotect()` for execution.

### Phase 5: C2 via WebVPN

WebVPN XML request triggers detoured handler:
1. Checks `<group-select>` for hardcoded 8-byte victim ID
2. Checks 8-byte authentication marker
3. If match -> copies payload to LINA memory, `mprotect()`, executes
4. Runs inside trusted LINA process — no separate C2 visible

### RayInitiator Stage 3 Comparison

| Feature | RayInitiator S3 | FIRESTARTER |
|---------|----------------|-------------|
| Target | ASA boot sequence | FXOS CSP_MOUNT_LIST |
| Hook | LINA XML handler | LINA XML handler |
| Persistence | Boot stage | Signals + runlevel 6 |
| C2 | WebVPN shellcode | WebVPN shellcode |
| Auth | Hardcoded magic | Hardcoded magic |
| Inject | libstdc++.so text | libstdc++.so text |

### Affected Platforms

**Affected:**
- Firepower 1000, 2100, 4100, 9300 Series
- Secure Firewall 1200, 3100, 4200 Series

**Not Affected:**
- ASA 5500-X Series
- Secure Firewall 200, 6100 Series (FTD 10.0.0+ only)
- ASA Virtual, ISA3000, FTD Virtual

---

## MITRE ATT&CK (v18)

| Tactic | Technique | ID | Details |
|--------|-----------|-----|---------|
| Initial Access | Exploit Public-Facing App | T1190 | CVE-2025-20333/20362 WebVPN |
| Execution | Cmd & Scripting Interpreter | T1059 | Shell commands via callback |
| Execution | In-Memory Execution | T1620 | mprotect payload exec in LINA |
| Persistence | Event Triggered: Trap | T1546.004 | 6 signal handlers |
| Persistence | Component Firmware | T1542.002 | FXOS boot via CSP_MOUNT_LIST |
| Persistence | Boot Autostart | T1547 | Mount list execution on boot |
| Persistence | Valid Accounts | T1078 | Dormant accounts for VPN |
| Priv Esc | Abuse Elevation Control | T1548 | LINA hook for priv exec |
| Defense Evasion | Process Injection | T1055 | Shellcode into libstdc++.so |
| Defense Evasion | File Deletion | T1070.004 | Wipes lina_cs, tmp files |
| Defense Evasion | Timestomp | T1070.006 | touch -r timestamp preserve |
| Defense Evasion | Hide Artifacts | T1564 | stderr /dev/null |
| Credential Access | OS Credential Dumping | T1082 | Admin creds, certs, keys |
| Discovery | Process Discovery | T1057 | /proc/[pid]/maps enum |
| Discovery | File/Dir Discovery | T1083 | Log dir existence checks |
| Lateral Movement | External Remote Services | T1133 | VPN bypass auth |
| C2 | Non-App Layer Protocol | T1095 | WebVPN XML C2 transport |
| C2 | Remote Access Software | T1219 | Full backdoor capability |
| Collection | Data from Repositories | T1213 | All device configurations |

---

## Indicators of Compromise (IOCs)

### File IOCs
| Path | Description |
|------|-------------|
| `/usr/bin/lina_cs` | Malicious binary (deleted post-hook, recreated on reboot) |
| `/opt/cisco/platform/logs/var/log/svc_samcore.log` | Staged binary in persistent log dir |

### Process Check
```
show kernel process | include lina_cs
```
Compromised: `68081 29428 20 0 249856 100 1 S 3 0 0 lina_cs`
Clean: no output

### YARA Rules (CISA-Provided)

**CISA_261290_01 — FIRESTARTER Backdoor:**
```yara
rule CISA_261290_01 : FIRESTARTER backdoor {
  meta: author = "CISA"; incident = "261290"; date = "2026-4-3"
  strings:
    $s1 = { 57 48 C1 EF 0C 48 C1 E7 0C BA 07 00 00 00 48 C7 C6 00 20 00 00 }
    $s2 = { 2f 6f 70 74 2f 63 69 73 63 6f 2f 70 6c 61 74 66 6f 72 6d 2f 6c 6f 67 73 2f 76 61 72 2f 6c 6f 67 2f }
    $s3 = { 2f 6f 70 74 2f 63 69 73 63 6f 2f 63 6f 6e 66 69 67 2f 70 6c 61 74 66 6f 72 6d 2f 72 6d 64 62 2f }
    $s4 = { 2f 76 61 72 2f 72 75 6e 2f 72 75 6e 6c 65 76 65 6c }
    $s5 = { 2f 70 72 6f 63 2f 25 73 2f 63 6f 6d 6d }
    $s6 = { 2f 70 72 6f 63 2f 25 64 2f 6d 61 70 73 }
    $s7 = { 2f 61 73 61 2f 62 69 6e 2f 6c 69 6e 61 }
  condition: 5 of them
}
```

**CISA_261290_02 — FIRESTARTER Shellcode:**
```yara
rule CISA_261290_02 : FIRESTARTER_shellcode backdoor {
  meta: author = "CISA"; incident = "261290"; date = "2026-4-3"
  strings:
    $1 = { 57 4C 8B 47 18 4D 85 C0 0F 84 C7 01 00 00 49 8B 38 48 85 FF }
    $2 = { 48 83 C6 08 4C 39 C6 0F 87 7A 01 00 00 4C 8B 0E }
    $3 = { 48 89 D7 4C 89 CE B9 D0 01 00 F3 A4 48 89 D7 57 48 C1 EF 0C 48 C1 E7 0C }
    $4 = { 0F 05 58 5F FF E0 90 90 }
  condition: 3 of them
}
```

### Other Signatures
| Type | Signature | Description |
|------|-----------|-------------|
| ClamAV | `Unix.Malware.Generic-10059965-0` | FIRESTARTER detection |
| Snort | 62949 | FIRESTARTER network detection |
| Snort | 65340 | CVE-2025-20333 exploitation |
| Snort | 46897 | CVE-2025-20362 exploitation |

### Behavioral IOCs
| Check | Method |
|-------|--------|
| `lina_cs` process | `show kernel process \| include lina_cs` |
| Unexpected runlevel 6 | Process monitoring |
| Modified CSP_MOUNT_LIST | Config file audit |
| svc_samcore.log existence | Directory listing |
| Log dir modifications | File integrity monitoring |

---

## Brahma XDR Rules (XML Format)

### Rule 900100 — FIRESTARTER Process Detection
```xml
<rule id="900100" name="FIRESTARTER Backdoor Process Detection" severity="CRITICAL" category="malware">
  <description>Detects FIRESTARTER backdoor lina_cs process on Cisco Firepower/Secure Firewall. Associated with UAT-4356 (ArcaneDoor).</description>
  <metadata>
    <tag value="FIRESTARTER"/><tag value="UAT-4356"/><tag value="ArcaneDoor"/>
    <tag value="cisco-firewall"/><tag value="persistence"/><tag value="backdoor"/>
  </metadata>
  <condition>
    <operator type="AND">
      <field name="process.name" operator="regex" value="lina_cs"/>
      <field name="device.type" operator="in" value="cisco_firepower,cisco_ftd,cisco_asa"/>
    </operator>
  </condition>
  <action>
    <alert severity="CRITICAL" message="FIRESTARTER backdoor process detected: lina_cs running on Cisco firewall"/>
    <response type="isolate_endpoint"/><response type="notify_soc"/>
  </action>
</rule>
```

### Rule 900101 — FIRESTARTER File Artifact Detection
```xml
<rule id="900101" name="FIRESTARTER File Artifact Detection" severity="CRITICAL" category="malware">
  <description>Detects FIRESTARTER file artifacts: malicious binary lina_cs and staged copy svc_samcore.log.</description>
  <metadata>
    <tag value="FIRESTARTER"/><tag value="file-artifact"/><tag value="cisco-firewall"/><tag value="persistence"/>
  </metadata>
  <condition>
    <operator type="OR">
      <operator type="AND">
        <field name="file.path" operator="equals" value="/usr/bin/lina_cs"/>
        <field name="device.type" operator="in" value="cisco_firepower,cisco_ftd,cisco_asa"/>
      </operator>
      <operator type="AND">
        <field name="file.path" operator="equals" value="/opt/cisco/platform/logs/var/log/svc_samcore.log"/>
        <field name="device.type" operator="in" value="cisco_firepower,cisco_ftd,cisco_asa"/>
      </operator>
      <operator type="AND">
        <field name="file.path" operator="contains" value="/opt/cisco/platform/logs/var/log/"/>
        <field name="file.name" operator="regex" value="svc_samcore\.log"/>
        <field name="device.type" operator="in" value="cisco_firepower,cisco_ftd,cisco_asa"/>
      </operator>
    </operator>
  </condition>
  <action>
    <alert severity="CRITICAL" message="FIRESTARTER file artifact detected on Cisco firewall"/>
    <response type="notify_soc"/><response type="collect_forensic_artifacts"/>
  </action>
</rule>
```

### Rule 900102 — CSP_MOUNT_LIST Persistence
```xml
<rule id="900102" name="FIRESTARTER CSP_MOUNT_LIST Persistence" severity="HIGH" category="persistence">
  <description>Detects CSP_MOUNT_LIST modifications containing FIRESTARTER persistence commands.</description>
  <metadata>
    <tag value="FIRESTARTER"/><tag value="persistence"/><tag value="config-modification"/><tag value="cisco-firewall"/>
  </metadata>
  <condition>
    <operator type="AND">
      <field name="file.path" operator="contains" value="CSP_MOUNT_LIST"/>
      <field name="file.modification.content" operator="regex" value="(svc_samcore\.log.*lina_cs|lina_cs\s+\&amp;)"/>
      <field name="device.type" operator="in" value="cisco_firepower,cisco_ftd"/>
    </operator>
  </condition>
  <action>
    <alert severity="HIGH" message="FIRESTARTER persistence via CSP_MOUNT_LIST modification"/>
    <response type="notify_soc"/>
  </action>
</rule>
```

### Rule 900103 — WebVPN C2 Trigger
```xml
<rule id="900103" name="FIRESTARTER WebVPN C2 Trigger" severity="HIGH" category="command-and-control">
  <description>Detects anomalous WebVPN XML requests that may trigger FIRESTARTER shellcode execution.</description>
  <metadata>
    <tag value="FIRESTARTER"/><tag value="c2-channel"/><tag value="webvpn"/><tag value="shellcode"/>
  </metadata>
  <condition>
    <operator type="AND">
      <field name="protocol" operator="equals" value="webvpn"/>
      <field name="http.request.content_type" operator="contains" value="xml"/>
      <field name="http.request.body" operator="regex" value="group-select"/>
      <field name="device.type" operator="in" value="cisco_firepower,cisco_ftd,cisco_asa"/>
    </operator>
  </condition>
  <action>
    <alert severity="HIGH" message="Anomalous WebVPN XML request — possible FIRESTARTER C2 activation"/>
    <response type="notify_soc"/><response type="capture_traffic"/>
  </action>
</rule>
```

### Rule 900104 — Post-Patch Persistence Anomaly
```xml
<rule id="900104" name="Post-Patch Persistence Anomaly" severity="CRITICAL" category="anomaly">
  <description>Detects FIRESTARTER surviving firmware patches — confirms pre-patch compromise.</description>
  <metadata>
    <tag value="FIRESTARTER"/><tag value="post-patch"/><tag value="persistence"/><tag value="arcane-door"/>
  </metadata>
  <condition>
    <operator type="AND">
      <field name="event.type" operator="equals" value="firmware_update"/>
      <field name="event.severity" operator="equals" value="completed"/>
      <operator type="OR">
        <field name="process.name" operator="regex" value="lina_cs"/>
        <field name="file.path" operator="equals" value="/opt/cisco/platform/logs/var/log/svc_samcore.log"/>
      </operator>
      <field name="device.type" operator="in" value="cisco_firepower,cisco_ftd,cisco_asa"/>
    </operator>
  </condition>
  <action>
    <alert severity="CRITICAL" message="FIRESTARTER survived firmware update — DEVICE COMPROMISED BEFORE PATCHING"/>
    <response type="notify_soc"/><response type="isolate_endpoint"/><response type="escalate_to_ir"/>
  </action>
</rule>
```

---

## Brahma NDR Rules (Suricata Format)

```
# FIRESTARTER Backdoor — NDR Rules (Brahma NDR / Suricata)
# Analyst: Xhavero | 2026-04-27

# Rule 1: CVE-2025-20333 — WebVPN RCE exploitation
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"EXPLOIT Cisco ASA/FTD WebVPN RCE CVE-2025-20333"; flow:to_server,established; content:"POST"; http_method; content:"/+webvpn+/"; http_uri; content:"Connection"; http_header; content:"Transfer-Encoding"; http_header; content:"chunked"; http_client_body; classtype:exploit; priority:1; sid:1000100; rev:1;)

# Rule 2: CVE-2025-20362 — WebVPN Unauthorized Access
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"EXPLOIT Cisco ASA/FTD WebVPN Unauthorized Access CVE-2025-20362"; flow:to_server,established; content:"POST"; http_method; content:"/+webvpn+/"; http_uri; content:"Cookie"; http_header; pcre:"/group-select/s"; classtype:exploit; priority:1; sid:1000101; rev:1;)

# Rule 3: FIRESTARTER C2 trigger — WebVPN XML
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MALWARE FIRESTARTER C2 Trigger via WebVPN XML"; flow:to_server,established; content:"POST"; http_method; content:"/+webvpn+/"; http_uri; content:"group-select"; http_client_body; content:"Connection"; http_header; classtype:trojan-activity; priority:1; sid:1000102; rev:1;)

# Rule 4: FIRESTARTER large XML payload — shellcode delivery
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MALWARE FIRESTARTER Large XML Payload Shellcode Delivery"; flow:to_server,established; content:"POST"; http_method; content:"/+webvpn+/"; http_uri; content:"<?xml"; distance:0; within:20; dsize:>4096; classtype:trojan-activity; priority:1; sid:1000103; rev:1;)

# Rule 5: LINE VIPER VPN session — UAT-4356
alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"MALWARE LINE VIPER VPN Session UAT-4356"; flow:to_server,established; content:"CONNECT"; depth:7; content:"Host:"; distance:0; within:10; content:"webvpn"; nocase; flowbits:set,line_viper_session; classtype:trojan-activity; priority:1; sid:1000104; rev:1;)

# Rule 6: CSP_MOUNT_LIST exfiltration attempt
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SUSPICIOUS Cisco CSP_MOUNT_LIST Content Outbound"; flow:to_client,established; content:"CSP_MOUNT_LIST"; nocase; content:"svc_samcore.log"; nocase; content:"lina_cs"; nocase; classtype:suspicious; priority:2; sid:1000105; rev:1;)
```

---

## Fusion SOAR Playbook

```yaml
playbook:
  name: "FIRESTARTER Cisco Firewall Incident Response"
  version: "1.0"
  severity: "CRITICAL"
  trigger:
    - "Brahma XDR Rule 900100-900104"
    - "Manual SOC trigger"

  steps:
    - id: S1
      name: "Triage & Validation"
      actions:
        - execute_cli
            command: "show kernel process | include lina_cs"
            target: "affected_firewalls"
        - check_log
            path: "/opt/cisco/platform/logs/var/log/svc_samcore.log"
        - correlate_events
            timeframe: "-30d"
            keywords: ["lina_cs", "CSP_MOUNT_LIST", "svc_samcore"]

    - id: S2
      name: "Preserve Evidence (DO NOT REBOOT)"
      actions:
        - execute_cli
            command: "show checkheaps"
            save: "/evidence/checkheaps_{{hostname}}.txt"
        - execute_cli
            command: "show tech-support detail"
            save: "/evidence/techsupport_{{hostname}}.txt"
        - collect_core_dump
            target: "affected_firewalls"
            upload: "CISA_MNG_platform"
        - create_incident_ticket
            severity: "CRITICAL"
            title: "FIRESTARTER Backdoor — {{hostname}}"
            notify: ["SOC_L3", "IR_TEAM", "CISO"]
        - notify_cisa
            contact: "report@cisa.dhs.gov"

    - id: S3
      name: "Containment"
      actions:
        - network_isolate
            targets: "affected_firewalls"
            mode: "management_only"
            note: "DO NOT soft reboot — preserve volatile evidence"
        - block_external_webvpn
            targets: "compromised_firewalls"
        - revoke_credentials
            scope: "all_admin_accounts_on_affected_device"
        - audit_vpn_sessions
            look_for: "authenticated_but_inactive_accounts"

    - id: S4
      name: "Eradication"
      actions:
        - schedule_maintenance_window
        - reimage_firewall
            method: "complete_reimage"
            upgrade_to: "fixed_release"
        - regenerate_certificates
            scope: "all_device_certs"
        - regenerate_keys
            scope: "all_device_keys"
        - rebuild_configuration
            from: "trusted_backup"
            note: "Do NOT import config from compromised device"

    - id: S5
      name: "Recovery & Monitoring"
      actions:
        - verify_clean
            checks:
              - "show kernel process | include lina_cs (expect: no output)"
              - "ls /opt/cisco/platform/logs/var/log/ (expect: no svc_samcore.log)"
              - "cat /opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST (verify clean)"
        - deploy_monitoring
            xdr_rules: [900100, 900101, 900102, 900103, 900104]
            nd_rules: [1000100, 1000101, 1000102, 1000103, 1000104, 1000105]

---

## Sources & References

- CISA Malware Analysis Report AR26-113A: https://www.cisa.gov/news-events/analysis-reports/ar26-113a
- Cisco Security Advisory: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-persist-CISAED25-03
- Cisco Talos Blog: https://blog.talosintelligence.com/uat-4356-firestarter/
- CISA Emergency Directive ED 25-03: https://www.cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices
- CVE-2025-20333: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-z5xP8EUB
- CVE-2025-20362: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-YROOTUW
- NCSC LINE VIPER Report: https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-rayinitiator-line-viper.pdf
- BleepingComputer: https://www.bleepingcomputer.com/news/security/firestarter-malware-survives-cisco-firewall-updates-security-patches/

---

## Summary

FIRESTARTER represents a new class of network device persistence that challenges traditional incident response approaches. The key takeaway for defenders: **patching alone is not sufficient** for devices that were compromised before the patch was applied. Any Cisco Firepower or Secure Firewall device that was vulnerable to CVE-2025-20333/20362 and was exploited prior to September 2025 must be treated as potentially compromised, regardless of current patch level.

**Immediate actions required:**
1. Run `show kernel process | include lina_cs` on all affected Cisco devices
2. Collect and analyze core dumps using YARA rules CISA_261290_01/02
3. Deploy Brahma XDR rules 900100-900104 for ongoing monitoring
4. Deploy Brahma NDR rules 1000100-1000105 for network-level detection
5. For confirmed compromises: reimage, regenerate all certs/keys, rebuild config from trusted backup
6. Coordinate with CISA for FCEB agencies
