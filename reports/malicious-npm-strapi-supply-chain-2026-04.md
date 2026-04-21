# 36 Malicious npm Packages — Strapi CMS Supply Chain Attack with Redis/PostgreSQL Exploitation

## Metadata
- **Threat Type:** Supply Chain Attack / Malicious npm Packages
- **Severity:** HIGH
- **Target:** Node.js developers using Strapi CMS plugins
- **Campaign Date:** 2026-04-05
- **Packages Count:** 36

## Summary
36 malicious npm packages disguised as Strapi CMS plugins were discovered in the npm registry. Each package contains three files (package.json, index.js, postinstall.js) with no description or repository metadata — classic red flags. The packages exploit Redis and PostgreSQL instances accessible from developer machines, deploy reverse shells, harvest credentials, and drop persistent implants.

## Attack Chain
1. Developer installs fake Strapi plugin via npm
2. `postinstall.js` executes automatically during `npm install`
3. Payload connects to local/accessible Redis and PostgreSQL instances
4. Reverse shell deployed for persistent C2 access
5. Credentials harvested from databases and config files
6. Persistent implant dropped for long-term access

## IOCs
### Indicators
- 36 npm packages with no description/repository metadata
- All contain only: package.json, index.js, postinstall.js
- Posing as Strapi CMS plugins
- Redis/PostgreSQL connection attempts from Node.js processes
- Reverse shell connections from developer workstations

## MITRE ATT&CK TTPs
| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Supply Chain Compromise | T1195.002 |
| Execution | User Execution | T1204 |
| Credential Access | Credentials from Password Stores | T1555 |
| Persistence | Server Software Component | T1505 |
| Command & Control | Application Layer Protocol | T1071 |

## Brahma XDR Detection Rule (XML)
```xml
<rule id="900103" level="high">
  <category>process</category>
  <if_sid>100100</if_sid>
  <description>Suspicious npm postinstall script execution with network connections</description>
  <match>postinstall</match>
  <program_name>node|npm</program_name>
  <extra_data>reverse_shell|nc|/bin/bash.*-i|socket</extra_data>
  <mitre>
    <id>T1195.002</id>
    <id>T1204</id>
  </mitre>
  <group>supply-chain,npm,malicious-package,execution</group>
</rule>

<rule id="900104" level="medium">
  <category>syscheck</category>
  <if_sid>550</if_sid>
  <description>New suspicious Node.js files in node_modules with postinstall scripts</description>
  <match>postinstall.js</match>
  <path>node_modules</path>
  <group>supply-chain,npm,file-integrity</group>
</rule>
```

## Brahma NDR Detection Rule (Suricata)
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET TROJAN Malicious npm postinstall reverse shell beacon";
  flow:established,to_server;
  http.method; content:"POST";
  http.header; content:"User-Agent|3a| node";
  http.uri; content:"/api/"; depth:5;
  classtype:trojan-activity;
  sid:20263562;
  rev:1;
  metadata:created_at 2026_04_06, attack_target Client_Endpoint;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET TROJAN Possible Node.js reverse shell connection from npm package";
  flow:established,to_server;
  content:"/bin/bash";
  content:"-i";
  dsize:<200;
  classtype:trojan-activity;
  sid:20263563;
  rev:1;
  metadata:created_at 2026_04_06;
)
```

## Recommendations
1. Audit all npm packages in projects using Strapi CMS — look for suspicious plugins
2. Check for packages with no description, no repository URL, only 3 files
3. Use `npm audit` and tools like `socket.dev` to scan dependencies
4. Restrict Node.js processes from making unexpected outbound connections
5. Segment developer environments from production databases
6. Implement npm package allowlisting in CI/CD pipelines
7. Monitor Redis/PostgreSQL access logs for unauthorized connections from developer machines

## References
- https://thehackernews.com/2026/04/36-malicious-npm-packages-exploited.html
