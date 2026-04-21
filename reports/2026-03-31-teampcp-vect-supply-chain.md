# TeamPCP → Vect Ransomware: Supply Chain Campaign (March 2026)

**Threat ID:** CVE-2026-33634  
**Severity:** 🔴 **CRITICAL** (CVSS 9.4)  
**Campaign Name:** TeamPCP Supply Chain Poisoning → Vect RaaS  
**Active Period:** March 19-27, 2026 (8-day evolution)  
**Threat Actor:** TeamPCP (likely UTC+3 timezone)  
**Ransomware Affiliate:** Vect RaaS (BreachForums partnership)  
**Status:** 🚨 **Actively Exploited** | Distribution to 300,000+ BreachForums users  

---

## Executive Summary

TeamPCP represents an **unprecedented convergence of supply chain compromise, ransomware-as-a-service (RaaS), and dark web mobilization**. The campaign poisoned multiple widely-used security tools and package registries, harvested **300 GB of credentials**, and partnered with **Vect ransomware** affiliates to deploy ransomware using stolen access.

### Attack Highlights

- **Supply chain victims:** Trivy, Checkmarx KICS, LiteLLM, Telnyx
- **Attack evolution:** 8-day campaign with rapidly evolving TTPs
- **Credential harvest:** 300 GB trove distributed to 300,000 BreachForums users via Vect affiliate keys
- **Infrastructure:** First documented abuse of **Internet Computer Protocol (ICP) blockchain** for C2
- **Lateral movement:** Self-propagating worm that auto-weaponizes stolen npm tokens
- **Dual-platform targeting:** Linux + Windows payloads
- **Ransomware deployment:** Confirmed Vect ransomware deployment using TeamPCP-sourced credentials

---

## Technical Analysis

### Attack Timeline

| Date | Event | Details |
|------|-------|---------|
| **Weeks before March 2026** | Initial Trivy compromise | Retained credentials used as pivot point |
| **March 19, 2026** | Trivy (GitHub) | 76 of 77 version tags force-pushed with malicious code |
| **March 20-22, 2026** | Checkmarx KICS | GitHub Actions compromise |
| **March 24, 2026** | LiteLLM (PyPI) | `.pth` auto-execution payload (34 KB) |
| **March 27, 2026 03:51 UTC** | Telnyx Python SDK | Malicious versions `4.87.1` and `4.87.2` published |
| **March 27, 2026 05:03 UTC** | Telnyx quarantine | 72 minutes after compromise detected |
| **Ongoing** | Vect ransomware deployment | Using TeamPCP-sourced credentials |

---

## Tactics, Techniques, and Procedures (TTPs)

### Initial Access

**Supply Chain Poisoning**
- Compromised security tools: **Trivy**, **Checkmarx KICS**
- Package registries: **PyPI**, **npm**, **Docker Hub**
- **Stolen credentials** (service accounts, PyPI tokens) — **NOT repository compromises**
- Published malicious packages directly via compromised publishing credentials

**Exposed Service Exploitation**
- Misconfigured Docker APIs
- Kubernetes clusters
- Ray dashboards
- Redis servers

### Credential Harvesting

**Memory Scraping**
- `/proc/[pid]/mem` — direct memory access to extract credentials from running processes

**Filesystem Sweeping**
- Targeted **50+ credential storage paths simultaneously**:
  - SSH keys (`.ssh/id_rsa`, `.ssh/id_ed25519`)
  - AWS credentials (`.aws/credentials`)
  - GCP credentials (`.config/gcloud/`)
  - Azure credentials (`.azure/`)
  - Kubernetes tokens (`/var/run/secrets/kubernetes.io/serviceaccount/token`)
  - `.env` files
  - Database passwords
  - Crypto wallets
  - Shell history (`.bash_history`, `.zsh_history`)

**Cloud Metadata Service (IMDS) Theft**
- Harvested credentials from cloud provider metadata services

### Persistence and Execution

**`.pth` File Exploitation** (LiteLLM payload)
- Exploited Python's automatic `.pth` site-packages execution
- File: `litellm_init.pth` (34 KB)
- Triggered on **every Python interpreter startup** across all Python processes
- **NOT limited to package imports** — executes globally in environment

**WAV Steganography** (Telnyx compromise)
- Evolved delivery mechanism embedding malicious payloads in WAV files
- Replaced earlier Base64 inline encoding method

**Dual-Platform Targeting**
- Expanded from Linux-only to **Windows** support
- Windows persistence mechanisms deployed alongside Linux payloads

### Lateral Movement and Privilege Escalation

**Kubernetes Lateral Movement**
- Attempted to create privileged `alpine:latest` pods
- Harvested service account tokens: `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Pod naming: `node-setup-*` (mimics legitimate infrastructure)

**Self-Propagating Worm**
- Stolen **npm tokens** automatically weaponized
- Infected victim-maintained packages
- Created **exponential upstream compromises** without attacker intervention

### Command and Control (C2)

**Blockchain-Based C2**
- **Internet Computer Protocol (ICP) canisters** as dead-drop C2
- **First documented abuse of decentralized blockchain infrastructure** for C2 purposes

**Fallback Infrastructure**
- Typosquatted domains (exfiltration)
- **Cloudflare Tunnels** (ephemeral C2)
- **GitHub dead drops** (`tpcp-docs` repositories)
- ICP-hosted fallback infrastructure

### Exfiltration and Monetization

**Credential Theft and Sale**
- Estimated **300 GB trove** of stolen credentials
- Distributed to **300,000 BreachForums users** via Vect affiliate keys

**Ransomware Deployment**
- Partnered with **Vect RaaS** affiliates
- Converts initial access into ransomware campaigns
- **First confirmed Vect deployment** already observed using TeamPCP-sourced credentials

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|----|----|
| **Initial Access** | Supply Chain Compromise | T1195 | Poisoned Trivy, Checkmarx, LiteLLM, Telnyx |
| **Initial Access** | Compromise Software Repository | T1195.003 | PyPI, npm, Docker Hub poisoning |
| **Persistence** | Boot or Logon Autostart Execution | T1547.010 | Python `.pth` auto-execution |
| **Credential Access** | Input Capture | T1056 | Memory scraping via `/proc/[pid]/mem` |
| **Credential Access** | Steal Application Access Token | T1528 | Cloud IMDS credential theft |
| **Credential Access** | Unsecured Credentials | T1552 | Filesystem credential sweeping (50+ paths) |
| **Defense Evasion** | Masquerading | T1036 | `node-setup-*` pod naming |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | WAV steganography, Base64 encoding |
| **Discovery** | Cloud Service Discovery | T1526 | AWS/GCP/Azure metadata enumeration |
| **Discovery** | Cloud Infrastructure Discovery | T1580 | Kubernetes cluster enumeration |
| **Lateral Movement** | Lateral Tool Transfer | T1570 | Self-propagating worm via npm tokens |
| **Collection** | Data from Information Repositories | T1213 | Credential harvest across 50+ paths |
| **Exfiltration** | Exfiltration Over Web Service | T1567 | ICP canisters, Cloudflare Tunnels |
| **Impact** | Data Encrypted for Impact | T1486 | Vect ransomware deployment |

---

## Indicators of Compromise (IOCs)

### Compromised Packages

| Package | Registry | Malicious Versions | Published Date |
|---------|----------|-------------------|----------------|
| **Trivy** | GitHub | 76 of 77 tags force-pushed | March 19, 2026 |
| **Checkmarx KICS** | GitHub | GitHub Actions compromise | March 20-22, 2026 |
| **LiteLLM** | PyPI | (version TBD) | March 24, 2026 |
| **Telnyx Python SDK** | PyPI | `4.87.1`, `4.87.2` | March 27, 2026 03:51 UTC |

### File Indicators

| Type | Filename | Size | Description |
|------|----------|------|-------------|
| **Python .pth** | `litellm_init.pth` | 34 KB | Auto-execution payload (LiteLLM) |
| **WAV file** | (filename TBD) | TBD | Steganography payload container (Telnyx) |
| **Base64 payloads** | (embedded in packages) | Various | Early attack phase delivery |

### Infrastructure IOCs

**C2 Infrastructure**
- **ICP canisters** (Internet Computer Protocol) — dead-drop C2
- **Cloudflare Tunnels** — ephemeral C2 endpoints
- **GitHub repositories:** `tpcp-docs` (dead drop accounts)
- **Typosquatted domains** (TBD — used for exfiltration)

**Ransomware IOCs**
- **Vect ransomware** deployment indicators
- **Vect affiliate keys** distributed to 300,000 BreachForums users

### Behavioral Indicators

- Unusual **Python interpreter startup activity** (`.pth` execution)
- Outbound connections to **ICP blockchain nodes**
- **Mass credential access** across 50+ filesystem paths
- **Kubernetes pod creation** with `node-setup-*` naming pattern
- **WAV file downloads** in Python package installations
- Unusual **npm token usage** for package publishing
- **Memory scraping activity** via `/proc/[pid]/mem` access

---

## Brahma XDR Detection Rules

```xml
<!-- Rule ID: 903301 - TeamPCP Python .pth Auto-Execution Detection -->
<rule id="903301" level="15">
  <if_sid>72000</if_sid>
  <field name="file.path" type="pcre2">\.pth$</field>
  <field name="file.parent_path" type="pcre2">site-packages</field>
  <field name="process.name">python|python3</field>
  <description>TeamPCP: Python .pth auto-execution detected in site-packages</description>
  <mitre>
    <id>T1547.010</id>
    <id>T1195.003</id>
  </mitre>
  <group>supply_chain,teampcp,python,persistence,critical</group>
</rule>

<!-- Rule ID: 903302 - TeamPCP Mass Credential Filesystem Sweep -->
<rule id="903302" level="14" frequency="10" timeframe="60">
  <if_sid>72000</if_sid>
  <field name="file.path" type="pcre2">\.ssh/id_rsa|\.aws/credentials|\.env|\.bash_history|\.kube/config</field>
  <same_source_ip/>
  <description>TeamPCP: Mass credential filesystem sweep detected (10+ paths in 60s)</description>
  <mitre>
    <id>T1552</id>
    <id>T1213</id>
  </mitre>
  <group>supply_chain,teampcp,credential_theft,critical</group>
</rule>

<!-- Rule ID: 903303 - TeamPCP /proc/[pid]/mem Memory Scraping -->
<rule id="903303" level="15">
  <if_sid>72000</if_sid>
  <field name="file.path" type="pcre2">/proc/\d+/mem</field>
  <field name="syscall">openat|read</field>
  <description>TeamPCP: Memory scraping via /proc/[pid]/mem detected</description>
  <mitre>
    <id>T1056</id>
  </mitre>
  <group>supply_chain,teampcp,memory_scraping,credential_theft,critical</group>
</rule>

<!-- Rule ID: 903304 - TeamPCP Kubernetes Service Account Token Theft -->
<rule id="903304" level="14">
  <if_sid>72000</if_sid>
  <field name="file.path">/var/run/secrets/kubernetes.io/serviceaccount/token</field>
  <field name="process.name" type="pcre2" negate="yes">kubelet|kube-proxy</field>
  <description>TeamPCP: Kubernetes service account token access by non-system process</description>
  <mitre>
    <id>T1528</id>
    <id>T1552</id>
  </mitre>
  <group>supply_chain,teampcp,kubernetes,credential_theft,critical</group>
</rule>

<!-- Rule ID: 903305 - TeamPCP Kubernetes Privileged Pod Creation (node-setup-*) -->
<rule id="903305" level="13">
  <if_sid>92000</if_sid>
  <field name="k8s.audit.verb">create</field>
  <field name="k8s.audit.objectRef.resource">pods</field>
  <field name="k8s.audit.objectRef.name" type="pcre2">^node-setup-</field>
  <field name="k8s.audit.requestObject.spec.hostNetwork">true</field>
  <description>TeamPCP: Suspicious privileged pod creation with node-setup-* naming pattern</description>
  <mitre>
    <id>T1580</id>
    <id>T1036</id>
  </mitre>
  <group>supply_chain,teampcp,kubernetes,lateral_movement</group>
</rule>

<!-- Rule ID: 903306 - TeamPCP Cloud Metadata Service (IMDS) Access -->
<rule id="903306" level="12">
  <if_sid>80000</if_sid>
  <field name="url" type="pcre2">169\.254\.169\.254|metadata\.google\.internal|169\.254\.169\.254:80</field>
  <field name="process.name" type="pcre2" negate="yes">aws-cli|gcloud|az|cloud-init</field>
  <description>TeamPCP: Cloud metadata service access by suspicious process</description>
  <mitre>
    <id>T1552</id>
    <id>T1526</id>
  </mitre>
  <group>supply_chain,teampcp,cloud,credential_theft</group>
</rule>

<!-- Rule ID: 903307 - TeamPCP WAV Steganography Payload Detection -->
<rule id="933307" level="11">
  <if_sid>72000</if_sid>
  <field name="file.extension">wav</field>
  <field name="file.parent_path" type="pcre2">site-packages|node_modules</field>
  <description>TeamPCP: Suspicious WAV file in package directory (potential steganography payload)</description>
  <mitre>
    <id>T1027</id>
    <id>T1195.003</id>
  </mitre>
  <group>supply_chain,teampcp,steganography</group>
</rule>

<!-- Rule ID: 903308 - Vect Ransomware Deployment (TeamPCP Sourced) -->
<rule id="903308" level="15">
  <if_sid>72000</if_sid>
  <field name="process.command_line" type="pcre2">vect|\.vect</field>
  <field name="file.extension" type="pcre2">vect|locked</field>
  <description>Vect Ransomware: Deployment detected (likely TeamPCP-sourced credentials)</description>
  <mitre>
    <id>T1486</id>
  </mitre>
  <group>ransomware,vect,teampcp,critical</group>
</rule>
```

---

## Brahma NDR Detection Rules (Suricata Format)

```suricata
# TeamPCP Supply Chain Campaign Detection Rules

# SID 2903301: Detect outbound connections to Internet Computer Protocol (ICP) nodes
alert tcp $HOME_NET any -> $EXTERNAL_NET [8080,4943] (msg:"TeamPCP C2: Outbound connection to Internet Computer Protocol (ICP) canister"; flow:to_server,established; content:"|13|ic0.app"; nocase; reference:cve,2026-33634; classtype:trojan-activity; sid:2903301; rev:1; metadata:campaign teampcp, severity critical;)

# SID 2903302: Detect GitHub dead drop repository access (tpcp-docs)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"TeamPCP C2: GitHub dead drop access - tpcp-docs repository"; flow:to_server,established; content:"GET"; http_method; content:"tpcp-docs"; http_uri; nocase; content:"github.com"; content:"Host|3a|"; http_header; reference:cve,2026-33634; classtype:trojan-activity; sid:2903302; rev:1; metadata:campaign teampcp, severity high;)

# SID 2903303: Detect Cloudflare Tunnel usage (C2 infrastructure)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"TeamPCP C2: Cloudflare Tunnel connection detected"; flow:to_server,established; tls.sni; content:"trycloudflare.com"; nocase; reference:cve,2026-33634; classtype:trojan-activity; sid:2903303; rev:1; metadata:campaign teampcp, severity high;)

# SID 2903304: Detect Kubernetes API requests with node-setup-* pod naming
alert http $HOME_NET any -> $KUBERNETES_API any (msg:"TeamPCP Lateral Movement: Kubernetes pod creation - node-setup-* pattern"; flow:to_server,established; content:"POST"; http_method; content:"/api/v1/namespaces/"; http_uri; content:"/pods"; http_uri; content:"node-setup-"; http_client_body; nocase; reference:cve,2026-33634; classtype:trojan-activity; sid:2903304; rev:1; metadata:campaign teampcp, severity high;)

# SID 2903305: Detect cloud metadata service (IMDS) access
alert http $HOME_NET any -> [169.254.169.254,169.254.169.253] any (msg:"TeamPCP Credential Theft: Cloud metadata service (IMDS) access"; flow:to_server,established; content:"GET"; http_method; pcre:"/\/latest\/meta-data|\/computeMetadata\/v1/"; reference:cve,2026-33634; classtype:attempted-recon; sid:2903305; rev:1; metadata:campaign teampcp, severity medium;)

# SID 2903306: Detect PyPI package publishing with suspicious authentication
alert http $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"TeamPCP Supply Chain: Suspicious PyPI package publishing"; flow:to_server,established; content:"POST"; http_method; content:"pypi.org"; content:"Host|3a|"; http_header; content:"upload.pypi.org"; http_uri; pcre:"/Authorization\x3a\s+Basic\s+[A-Za-z0-9+\/=]+/H"; threshold:type limit, track by_src, count 1, seconds 3600; reference:cve,2026-33634; classtype:trojan-activity; sid:2903306; rev:1; metadata:campaign teampcp, severity high;)

# SID 2903307: Detect npm token usage for package publishing
alert http $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"TeamPCP Supply Chain: Suspicious npm package publishing"; flow:to_server,established; content:"PUT"; http_method; content:"registry.npmjs.org"; content:"Host|3a|"; http_header; content:"npm_"; http_header; threshold:type limit, track by_src, count 1, seconds 3600; reference:cve,2026-33634; classtype:trojan-activity; sid:2903307; rev:1; metadata:campaign teampcp, severity high;)

# SID 2903308: Detect Vect ransomware C2 beaconing
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Vect Ransomware: C2 beacon detected (TeamPCP campaign)"; flow:to_server,established; content:"POST"; http_method; content:"vect"; http_uri; nocase; content:"id="; http_client_body; pcre:"/[a-f0-9]{32,}/"; classtype:trojan-activity; sid:2903308; rev:1; metadata:campaign vect, severity critical;)
```

---

## Recommendations

### 🚨 Immediate Actions (Within 24 Hours)

1. **Identify Exposure**
   - Check if your organization uses:
     - **Trivy** (container security scanner)
     - **Checkmarx KICS** (IaC security)
     - **LiteLLM** (LLM proxy)
     - **Telnyx Python SDK** (communications API)
   - Audit package versions installed
   - Check for compromised versions

2. **Assume Compromise if Exposed**
   - **Rotate ALL credentials immediately**:
     - SSH keys
     - Cloud credentials (AWS, GCP, Azure)
     - Kubernetes service account tokens
     - `.env` file secrets
     - Database passwords
     - npm/PyPI publishing tokens
   - Consider credentials distributed to **300,000 BreachForums users**

3. **Emergency Response**
   - Isolate systems running compromised packages
   - Review logs for:
     - Unusual outbound connections (ICP, Cloudflare Tunnels, GitHub)
     - File access to 50+ credential paths
     - Memory scraping via `/proc/[pid]/mem`
     - Kubernetes pod creation with `node-setup-*` naming
   - Engage DFIR team for forensic analysis

4. **Patch and Update**
   - Update to **clean versions** of affected packages:
     - Trivy: verify clean tags via Aqua Security advisory
     - Checkmarx KICS: follow vendor guidance
     - LiteLLM: update to post-compromise version
     - Telnyx: versions **before 4.87.1** or **after 4.87.2**
   - Pin dependencies to **cryptographic hashes** (not version numbers)

### 🔍 Detection & Monitoring

5. **Deploy Detection Rules**
   - Implement provided **Brahma XDR rules** (903301-903308)
   - Deploy **Brahma NDR/Suricata rules** (2903301-2903308)
   - Monitor for:
     - Python `.pth` auto-execution
     - Mass credential filesystem access
     - Memory scraping activity
     - ICP blockchain C2 traffic
     - Cloudflare Tunnel usage
     - Kubernetes lateral movement

6. **Enhanced Monitoring**
   - Enable **full process execution logging**
   - Monitor **Python interpreter startup activity**
   - Track **cloud metadata service (IMDS) access**
   - Audit **package registry publishing activity**
   - Watch for **Vect ransomware IOCs**

### 🔐 Hardening & Long-Term Actions

7. **Supply Chain Security**
   - **Pin all dependencies** to cryptographic hashes (SHA256)
   - Implement **quarantine periods** for new package releases (24-72 hours)
   - Use **private package mirrors** with security scanning
   - Enable **Software Bill of Materials (SBOM)** tracking
   - Deploy **runtime application self-protection (RASP)**

8. **Credential Security**
   - **Never store credentials in files** — use secret managers (Vault, AWS Secrets Manager, etc.)
   - Implement **short-lived credentials** with automatic rotation
   - Use **workload identity** for cloud access (avoid static credentials)
   - Enable **credential access logging** and alerting

9. **Kubernetes Hardening**
   - Restrict **privileged pod creation**
   - Enable **Pod Security Standards** (restricted profile)
   - Monitor **service account token usage**
   - Implement **network policies** to limit lateral movement
   - Use **admission controllers** to block suspicious pod naming patterns

10. **Incident Response Preparation**
    - Update IR playbooks for **supply chain compromise**
    - Prepare **credential rotation runbooks** (prioritize speed)
    - Establish **communication channels** with vendors and partners
    - Practice **supply chain incident response drills**

### 📊 Threat Intelligence

11. **Continuous Monitoring**
    - Monitor **BreachForums** for Vect affiliate activity
    - Track **TeamPCP TTPs** via threat intel feeds
    - Watch for **new compromised packages** (ongoing campaign likely)
    - Subscribe to vendor advisories (Aqua, Checkmarx, Telnyx, etc.)
    - Monitor **ICP blockchain** for new C2 canisters

---

## Attribution and Context

### Threat Actor: TeamPCP
- **Timezone:** Likely UTC+3 (75-80% confidence)
- **Motive:** Financial gain via credential theft + ransomware partnership
- **Sophistication:** High — rapidly evolving TTPs, self-propagating worm, blockchain C2
- **Infrastructure:** Decentralized (ICP), ephemeral (Cloudflare), and resilient (GitHub dead drops)

### Ransomware Partner: Vect RaaS
- **Model:** Ransomware-as-a-Service
- **Distribution:** 300,000 BreachForums users with affiliate keys
- **Tactics:** Double extortion (encryption + data leak)
- **Targets:** Organizations exposed via TeamPCP supply chain compromise

### Campaign Significance
- **First documented abuse of ICP blockchain for C2**
- **Self-propagating supply chain worm** (exponential upstream compromise)
- **Unprecedented dark web mobilization** (300K affiliates)
- **Rapid TTP evolution** (8 days: Base64 → `.pth` → WAV steganography)

---

## References

- **CVE-2026-33634:** CVSS 9.4 (Critical)
- **Affected Vendors:** Aqua Security (Trivy), Checkmarx (KICS), LiteLLM, Telnyx
- **Ransomware Partner:** Vect RaaS
- **Dark Web Distribution:** BreachForums (300,000 users)
- **Novel C2 Infrastructure:** Internet Computer Protocol (ICP) blockchain

---

**Analysis Date:** March 31, 2026, 8:00 PM WIB  
**Analyst:** Xhavero (L3 Blue Team Specialist)  
**Category:** Supply Chain Attack | Ransomware Campaign  
**Tags:** #TeamPCP #Vect #SupplyChain #Ransomware #RaaS #ICP #Blockchain #PyPI #npm
