# TeamPCP - DPRK Supply Chain Attack (LiteLLM/npm/PyPI)

**Date:** 2026-04-02  
**Analyst:** Xhavero  
**Severity:** 🔴 CRITICAL  
**Status:** Active Campaign (Ongoing)  

---

## Executive Summary

**TeamPCP** (tracked as **UNC6780** by Google Threat Intelligence Group) is a financially motivated threat actor with North Korean ties conducting coordinated supply chain attacks across multiple ecosystems: PyPI, npm, Docker Hub, GitHub Actions, and OpenVSX. The campaign targets developer tools and AI infrastructure for credential theft, cloud compromise, and extortion.

Key compromises include:
- **LiteLLM** (PyPI) — AI proxy service handling API keys/cloud credentials
- **Trivy** / **Checkmarx KICS** — Security scanning tools
- **Axios** (npm) — Distinct DPRK actor UNC1069, related campaign

This represents a **cascading supply chain attack** with three-stage payloads: credential harvesting, Kubernetes lateral movement, and persistent backdoors. Stolen credentials (hundreds of thousands) are weaponized for ransomware, SaaS compromise, and cryptocurrency theft.

**Impact:** Developers, AI/ML teams, DevOps pipelines, cloud environments globally affected.

---

## Technical Details

### Threat Actor Profile
- **Primary Name:** TeamPCP
- **Aliases:** Shellforce, PersyPCP, PCPcat, DeadCatx3, @pcpcats (X/Twitter)
- **Tracking IDs:** UNC6780 (GTIG)
- **Attribution:** North Korea (financial motivation, state nexus)
- **Active Since:** 2025 (recent emergence)
- **Motivation:** Financial (credential theft, extortion, ransomware, crypto theft)
- **Extortion Platform:** Telegram channel + onion site for negotiations

### Related Actor
- **UNC1069:** Distinct DPRK-nexus actor behind **Axios npm compromise** (March 31, 2026)
- **Malware:** WAVESHAPER.V2
- **Versions:** 1.14.1, 0.30.4
- **Overlap:** Both actors demonstrate DPRK supply chain targeting trend

### Campaign Overview (March 2026)
TeamPCP orchestrated a multi-ecosystem attack targeting developer security tools:

| Ecosystem | Package/Tool | Compromise Date | Impact |
|-----------|-------------|-----------------|--------|
| PyPI | LiteLLM | March 2026 | AI proxy credential theft |
| GitHub Actions | trivy-action | March 19, 2026 | 76/77 release tags compromised |
| GitHub Actions | setup-trivy | March 19, 2026 | All tags force-pushed |
| PyPI/GitHub | Checkmarx KICS | March 2026 | Security tool backdoored |
| Docker Hub | (Various) | March 2026 | Container poisoning |
| OpenVSX | (Various) | March 2026 | VS Code extension supply chain |

**Attack Method:** Force-pushed malicious commits to trusted repositories, flooded issue trackers with spam to delay detection.

---

## Malware Arsenal & TTPs

### Three-Stage Payload Architecture

#### Stage 1: Credential Harvester
- **Target:** 50+ secret types (API keys, cloud credentials, tokens)
- **Exfiltration:** AES-256-CBC + RSA-4096-OAEP encrypted archives
- **Archive Name:** `tpcp.tar.gz`
- **Scope:** AWS, Azure, GCP, GitHub, CI/CD secrets

#### Stage 2: Kubernetes Lateral Movement Toolkit
- **Function:** Cluster compromise and privilege escalation
- **Techniques:**
  - Service account token theft
  - RBAC abuse
  - Container escape
  - Pod-to-pod lateral movement

#### Stage 3: Persistent Backdoor
- **Name:** SANDCLOCK stealer
- **Function:** Remote code execution, persistent access
- **Features:**
  - Remote shell capability
  - Continuous credential monitoring
  - Environment variable harvesting

### Code Artifacts
- **Branding:** "TeamPCP" strings in payloads
- **Comment:** `"ICP y u no radio? ;w;"` (internet meme reference)
- **Encryption:** AES-256-CBC + RSA-4096-OAEP across all stages
- **Technique:** Deep Python execution knowledge for evasion

---

## Indicators of Compromise (IOCs)

### npm (Axios) - UNC1069 Campaign
**Malicious Versions:**
- `axios@1.14.1`
- `axios@0.30.4`
- Released: March 31, 2026

**Detection:**
```bash
# Check installed axios versions
npm list axios

# Search in package-lock.json
grep -E '"axios".*"1\.14\.1"|"axios".*"0\.30\.4"' package-lock.json

# Scan globally
npm list -g axios
```

### PyPI (LiteLLM) - TeamPCP Campaign
**Compromised Package:** `litellm` (specific versions TBD from threat intel)

**Detection:**
```bash
# Check installed versions
pip list | grep litellm

# Review requirements files
grep litellm requirements.txt

# Check virtual environments
find . -name "site-packages" -exec ls {}/litellm* \;
```

### GitHub Actions - Trivy Compromises
**Affected:**
- `aquasecurity/trivy-action` — 76 of 77 release tags force-pushed (March 19)
- `aquasecurity/setup-trivy` — All tags force-pushed (March 19)

**Detection:**
```bash
# Review workflow files
grep -r "aquasecurity/trivy-action\|setup-trivy" .github/workflows/

# Check git history for force-pushes around March 19, 2026
git log --all --since="2026-03-18" --until="2026-03-20" --oneline
```

### Network IOCs (SANS ISC - April 1 Update)
**Command & Control:**
- **Domain:** `sfrclak[.]com`
- **IP:** `142.11.206[.]73`

**Detection:**
```bash
# DNS queries
grep "sfrclak\.com" /var/log/dns.log

# Firewall/proxy logs
grep "142.11.206.73" /var/log/firewall.log
```

### File System IOCs (Platform-Specific)

**macOS:**
```bash
# Check for malicious files
ls -la /Library/Caches/com.apple.act.mond
```

**Windows:**
```powershell
# Check for malicious executable
Get-Item $env:PROGRAMDATA\wt.exe -ErrorAction SilentlyContinue
```

**Linux:**
```bash
# Check for malicious Python script
ls -la /tmp/ld.py
```

### Behavioral IOCs
- Unusual CI/CD pipeline modifications (force-pushes to release tags)
- Spike in GitHub issue creation (noise/spam)
- Outbound connections to `sfrclak[.]com` or `142.11.206.73`
- Unexplained `tpcp.tar.gz` file creation
- AES-encrypted archives in temporary directories
- Credential access from non-interactive sessions

---

## MITRE ATT&CK TTPs

### Initial Access
| Technique | ID | Description |
|-----------|-----|-------------|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Trojanized PyPI/npm packages |
| Valid Accounts | T1078 | Compromised developer/CI credentials |

### Execution
| Technique | ID | Description |
|-----------|-----|-------------|
| Command and Scripting Interpreter: Python | T1059.006 | Malicious Python code in packages |
| Command and Scripting Interpreter: JavaScript | T1059.007 | Malicious JavaScript in npm packages |

### Persistence
| Technique | ID | Description |
|-----------|-----|-------------|
| Supply Chain Compromise | T1195 | Persistent backdoors in dependencies |
| Account Manipulation | T1098 | Compromised package maintainer accounts |

### Credential Access
| Technique | ID | Description |
|-----------|-----|-------------|
| Unsecured Credentials: Credentials In Files | T1552.001 | Harvesting secrets from environment/config |
| Steal Application Access Token | T1528 | API key/token theft (50+ types) |

### Discovery
| Technique | ID | Description |
|-----------|-----|-------------|
| Cloud Infrastructure Discovery | T1580 | AWS/Azure/GCP enumeration |
| Container and Resource Discovery | T1613 | Kubernetes cluster reconnaissance |

### Lateral Movement
| Technique | ID | Description |
|-----------|-----|-------------|
| Exploitation of Remote Services | T1210 | Kubernetes lateral movement |
| Use Alternate Authentication Material | T1550 | Stolen service account tokens |

### Collection
| Technique | ID | Description |
|-----------|-----|-------------|
| Data from Local System | T1005 | Credential file harvesting |
| Data from Cloud Storage Object | T1530 | Cloud credential/config theft |

### Exfiltration
| Technique | ID | Description |
|-----------|-----|-------------|
| Exfiltration Over C2 Channel | T1041 | Data to `sfrclak[.]com` |
| Automated Exfiltration | T1020 | SANDCLOCK automated credential theft |

### Impact
| Technique | ID | Description |
|-----------|-----|-------------|
| Data Encrypted for Impact | T1486 | Ransomware (Vect RaaS) post-compromise |

---

## Brahma XDR Detection Rules

```xml
<!-- TeamPCP: Axios Malicious Version Detection -->
<rule id="900250" level="12">
  <if_sid>60000</if_sid>
  <field name="file.name">package\.json|package-lock\.json</field>
  <field name="file.content" type="pcre2">"axios".*"(1\.14\.1|0\.30\.4)"</field>
  <description>TeamPCP compromised Axios version detected (UNC1069)</description>
  <mitre>
    <id>T1195.002</id>
  </mitre>
</rule>

<!-- TeamPCP: LiteLLM Suspicious Activity -->
<rule id="900251" level="11">
  <if_sid>60000</if_sid>
  <field name="process.name">python|python3</field>
  <field name="process.command_line">litellm</field>
  <field name="network.direction">outbound</field>
  <field name="destination.domain">sfrclak\.com</field>
  <description>TeamPCP LiteLLM C2 communication to sfrclak.com</description>
  <mitre>
    <id>T1041</id>
    <id>T1195.002</id>
  </mitre>
</rule>

<!-- TeamPCP: File System IOC Detection (Multi-Platform) -->
<rule id="900252" level="13">
  <if_sid>60000</if_sid>
  <field name="file.path" type="pcre2">^/Library/Caches/com\.apple\.act\.mond$|^C:\\ProgramData\\wt\.exe$|^/tmp/ld\.py$</field>
  <description>TeamPCP malicious file detected (macOS/Windows/Linux)</description>
  <mitre>
    <id>T1195.002</id>
  </mitre>
</rule>

<!-- TeamPCP: SANDCLOCK Backdoor Activity -->
<rule id="900253" level="12">
  <if_sid>60000</if_sid>
  <field name="process.name">python|node</field>
  <field name="process.command_line" type="pcre2">SANDCLOCK|tpcp\.tar\.gz</field>
  <description>TeamPCP SANDCLOCK backdoor execution detected</description>
  <mitre>
    <id>T1059</id>
    <id>T1041</id>
  </mitre>
</rule>

<!-- TeamPCP: Kubernetes Credential Harvesting -->
<rule id="900254" level="13">
  <if_sid>60000</if_sid>
  <field name="file.path" type="pcre2">/var/run/secrets/kubernetes\.io|\.kube/config</field>
  <field name="event.action">read|access</field>
  <field name="process.name" type="pcre2">python|node|curl|wget</field>
  <description>TeamPCP Kubernetes credential theft attempt</description>
  <mitre>
    <id>T1552.001</id>
    <id>T1613</id>
  </mitre>
</rule>

<!-- TeamPCP: AES-Encrypted Credential Archive -->
<rule id="900255" level="12">
  <if_sid>60000</if_sid>
  <field name="file.name">tpcp\.tar\.gz</field>
  <field name="event.action">created|modified</field>
  <description>TeamPCP credential exfiltration archive created</description>
  <mitre>
    <id>T1020</id>
    <id>T1560</id>
  </mitre>
</rule>

<!-- TeamPCP: GitHub Actions Force Push Detection -->
<rule id="900256" level="11">
  <if_sid>60000</if_sid>
  <field name="event.module">git</field>
  <field name="event.action">push_force</field>
  <field name="git.repository" type="pcre2">trivy-action|setup-trivy</field>
  <description>TeamPCP-style force push to security tool repository</description>
  <mitre>
    <id>T1195.002</id>
  </mitre>
</rule>

<!-- TeamPCP: Multi-Secret Type Harvesting -->
<rule id="900257" level="13">
  <if_sid>60000</if_sid>
  <field name="process.command_line" type="pcre2">AWS_ACCESS_KEY|AZURE_CLIENT|GCP_SERVICE_ACCOUNT|GITHUB_TOKEN|NPM_TOKEN</field>
  <field name="process.name">python|node|bash</field>
  <field name="frequency">5</field>
  <timeframe>60</timeframe>
  <description>TeamPCP mass credential harvesting detected (50+ secret types)</description>
  <mitre>
    <id>T1552.001</id>
    <id>T1528</id>
  </mitre>
</rule>
```

---

## Brahma NDR Detection Rules

```suricata
# TeamPCP: C2 Communication to sfrclak.com
alert dns any any -> any any (msg:"PERISAI MALWARE TeamPCP C2 DNS Query - sfrclak.com"; dns_query; content:"sfrclak.com"; nocase; reference:url,isc.sans.edu; classtype:trojan-activity; sid:9000250; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02, attack_target Client_and_Server, deployment Perimeter;)

alert ip $HOME_NET any -> 142.11.206.73 any (msg:"PERISAI MALWARE TeamPCP C2 IP Communication"; reference:url,isc.sans.edu; classtype:trojan-activity; sid:9000251; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# TeamPCP: SANDCLOCK Backdoor Exfiltration
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI MALWARE TeamPCP SANDCLOCK Credential Exfiltration"; flow:established,to_server; content:"POST"; http_method; content:"tpcp.tar.gz"; http_client_body; classtype:trojan-activity; sid:9000252; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# TeamPCP: Python Package Download Anomaly
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI MALWARE TeamPCP Malicious PyPI Package Download"; flow:established,to_server; content:"GET"; http_method; content:"/simple/litellm/"; http_uri; content:"files.pythonhosted.org"; http_host; classtype:trojan-activity; sid:9000253; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# TeamPCP: npm Axios Malicious Version
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI MALWARE TeamPCP Axios Compromised Version Download"; flow:established,to_server; content:"GET"; http_method; content:"/axios/-/axios-1.14.1.tgz"; http_uri; content:"registry.npmjs.org"; http_host; classtype:trojan-activity; sid:9000254; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# TeamPCP: Kubernetes API Credential Theft
alert http $HOME_NET any -> any any (msg:"PERISAI MALWARE TeamPCP Kubernetes Service Account Token Access"; flow:established,to_server; content:"GET"; http_method; content:"/api/v1/namespaces/"; http_uri; content:"Authorization|3a 20|Bearer "; http_header; content:"/var/run/secrets"; http_client_body; classtype:attempted-recon; sid:9000255; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# TeamPCP: Mass Environment Variable Harvesting
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI MALWARE TeamPCP Environment Variable Exfiltration"; flow:established,to_server; content:"POST"; http_method; pcre:"/AWS_ACCESS_KEY|AZURE_CLIENT|GCP_SERVICE|GITHUB_TOKEN|NPM_TOKEN/i"; http_client_body; classtype:trojan-activity; sid:9000256; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# TeamPCP: AES-Encrypted Archive Upload
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PERISAI MALWARE TeamPCP Encrypted Credential Archive Upload"; flow:established,to_server; content:"POST"; http_method; content:"Content-Type|3a| application/octet-stream"; http_header; content:"|00 00 00|"; depth:100; byte_test:4,>,1000,0,relative; classtype:trojan-activity; sid:9000257; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)

# TeamPCP: GitHub Force Push Activity
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"PERISAI MALWARE TeamPCP GitHub Force Push to Trivy Repositories"; flow:established,to_server; tls.sni; content:"github.com"; content:"git-receive-pack"; content:"trivy"; nocase; classtype:trojan-activity; sid:9000258; rev:1; metadata:created_at 2026_04_02, updated_at 2026_04_02;)
```

---

## Recommendations

### Immediate Actions (P0)
1. **Audit Package Dependencies:**
   ```bash
   # npm
   npm audit
   npm list axios | grep -E "1\.14\.1|0\.30\.4"
   
   # Python
   pip list | grep -i litellm
   pip audit  # or safety check
   
   # Update all dependencies
   npm update axios
   pip install --upgrade litellm
   ```

2. **Remove Malicious Packages:**
   ```bash
   # npm
   npm uninstall axios
   npm install axios@latest
   
   # PyPI
   pip uninstall litellm
   pip install litellm --upgrade
   ```

3. **Scan for File System IOCs:**
   ```bash
   # macOS
   sudo find /Library/Caches -name "com.apple.act.mond"
   
   # Windows (PowerShell as Admin)
   Get-ChildItem -Path $env:PROGRAMDATA -Filter wt.exe -Recurse
   
   # Linux
   find /tmp -name "ld.py" -o -name "tpcp.tar.gz"
   ```

4. **Block C2 Infrastructure:**
   - Domain: `sfrclak[.]com`
   - IP: `142.11.206.73`
   - Add to firewall/DNS blocklists

5. **Credential Rotation (Critical):**
   - **Assume breach:** Rotate ALL credentials if vulnerable packages were used
   - Priority secrets:
     - AWS Access Keys / IAM credentials
     - Azure Service Principals
     - GCP Service Accounts
     - GitHub Personal Access Tokens / Deploy Keys
     - npm Tokens
     - API keys in environment variables

### Detection & Monitoring (P1)
1. **Deploy Detection Rules:**
   - Brahma XDR: Rules 900250-900257
   - Brahma NDR: Rules 9000250-9000258

2. **CI/CD Pipeline Monitoring:**
   - Enable GitHub Actions audit logging
   - Monitor for force-pushes to release tags
   - Alert on workflow file modifications
   - Review recent pipeline executions (March 19-present)

3. **Network Monitoring:**
   - Monitor DNS queries for `sfrclak.com`
   - Track connections to `142.11.206.73`
   - Alert on unusual outbound traffic from CI/CD systems

4. **Credential Access Monitoring:**
   - AWS CloudTrail for IAM credential usage
   - Azure AD audit logs
   - GCP Cloud Audit Logs
   - GitHub audit log for token usage

5. **SIEM Correlation:**
   - Package installation + outbound C2 connection
   - Kubernetes token access + external data transfer
   - Mass environment variable access + encrypted archive creation

### Hardening (P2)
1. **Supply Chain Security:**
   - Implement **package lock files** (package-lock.json, Pipfile.lock)
   - Use **private npm/PyPI registries** for vetted packages
   - Enable **dependency signing** (Sigstore/npm provenance)
   - Audit package maintainer changes (GitHub notifications)

2. **Least Privilege:**
   - Limit CI/CD pipeline access to secrets
   - Use short-lived credentials (OIDC for GitHub Actions)
   - Kubernetes RBAC hardening (minimal service account permissions)
   - Rotate secrets regularly (automated)

3. **Runtime Protection:**
   - Deploy AppArmor/SELinux profiles for containers
   - Use read-only filesystems where possible
   - Monitor `/tmp` directory for unusual files
   - Block execution from temporary directories

4. **Code Review:**
   - Review recent package updates (especially around March 19, 2026)
   - Check git history for anomalous force-pushes
   - Audit GitHub Actions workflow files for malicious steps

5. **Air-Gap Sensitive Environments:**
   - Use offline/mirrored package repositories for critical systems
   - Scan all packages before internal distribution
   - Implement network segmentation for build systems

### Incident Response (P1)
1. **If Compromise Suspected:**
   - Immediately rotate ALL credentials
   - Isolate affected systems from network
   - Preserve forensic evidence (logs, disk images)
   - Review cloud resource usage for unauthorized activity
   - Check for ransomware deployment (Vect RaaS)

2. **Forensic Collection:**
   ```bash
   # Collect package installation logs
   npm ls --json > npm-packages.json
   pip freeze > requirements.txt
   
   # Collect environment variables (redact before sharing)
   env > environment-vars.txt
   
   # Collect network connections
   netstat -tulpn > active-connections.txt
   
   # Collect process list
   ps auxf > process-tree.txt
   ```

3. **Kubernetes Incident Response:**
   ```bash
   # Check for unauthorized service accounts
   kubectl get serviceaccounts -A
   
   # Review RBAC bindings
   kubectl get clusterrolebindings -o wide
   
   # Check for suspicious pods
   kubectl get pods -A -o wide
   
   # Export audit logs
   kubectl logs -n kube-system kube-apiserver-* > k8s-audit.log
   ```

### Long-Term Strategy (P3)
1. **Security Tooling:**
   - Deploy **Snyk** / **Dependabot** for continuous dependency scanning
   - Use **Socket.dev** or **Phylum** for real-time supply chain threat detection
   - Implement **SLSA Framework** for build provenance

2. **Developer Training:**
   - Supply chain attack awareness
   - Secure package installation practices
   - Credential hygiene (avoid hardcoding, use secret managers)

3. **Threat Intelligence:**
   - Subscribe to SANS ISC Diary for supply chain IOCs
   - Monitor DPRK threat actor activity (UNC6780, UNC1069)
   - Follow TeamPCP Telegram/onion site (intelligence purposes only)

4. **Vendor Coordination:**
   - Contact affected package maintainers for status updates
   - Report suspicious packages to npm/PyPI security teams
   - Share IOCs with Information Sharing and Analysis Centers (ISACs)

---

## Affected Organizations

### High-Risk Profiles
- **AI/ML Development Teams:** LiteLLM users handling API keys for OpenAI, Anthropic, etc.
- **DevOps/Platform Teams:** Using Trivy, KICS for container/IaC security scanning
- **Cloud-Native Applications:** Kubernetes deployments with service accounts
- **npm/JavaScript Developers:** Axios is one of the most popular HTTP libraries (~50M weekly downloads normally)

### Impact Scenarios
1. **Credential Theft → Cloud Takeover:**
   - Stolen AWS keys → EC2 cryptocurrency mining
   - Azure credentials → ransomware deployment
   - GCP service accounts → data exfiltration

2. **Kubernetes Cluster Compromise:**
   - Lateral movement across pods
   - Container escape to host
   - Data theft from cluster secrets

3. **Supply Chain Ripple Effect:**
   - Downstream projects using compromised dependencies
   - CI/CD pipelines executing malicious code
   - Trusted builds distributing backdoors

4. **Extortion:**
   - Stolen credentials sold to ransomware operators
   - Direct extortion via Telegram/onion site
   - SaaS account compromise for further attacks

---

## References

- SANS ISC Diary: TeamPCP IOCs (April 1, 2026 Update)
- Google Threat Intelligence Group: UNC6780 Analysis
- Trend Micro: TeamPCP Supply Chain Campaign
- npm Security Advisory: Axios Compromise
- PyPI Security: LiteLLM Incident Report
- Aqua Security: Trivy Action Compromise Notice

---

## Threat Intelligence Summary

**Attribution:** North Korea (UNC6780 / TeamPCP, financial motivation with state nexus)  
**Confidence:** High  
**Target Profile:** Global — developers, AI/ML teams, DevOps, cloud environments  
**Campaign Status:** Active (March 2026 - present)  
**Sophistication:** Advanced (multi-ecosystem coordination, deep evasion knowledge)  
**Risk Level:** CRITICAL for organizations using affected packages  

**DPRK Supply Chain Trend:**
- TeamPCP (UNC6780): LiteLLM, Trivy, PyPI/npm
- UNC1069: Axios (separate but concurrent)
- Escalating DPRK focus on developer tools since early 2026

**Monetization Chain:**
1. Supply chain compromise → credential theft
2. Stolen credentials → cloud resource abuse (crypto mining, ransomware)
3. Extortion via Telegram + onion site
4. Credential sales to other actors

**Recommended Response Level:** Tier 1 (immediate action required for affected environments)

---

**Last Updated:** 2026-04-02 10:00 WIB  
**Next Review:** Daily monitoring for new IOCs, weekly package ecosystem scanning  
**Analyst Contact:** Xhavero (L3 Blue Team)
