# Indra CTI — Threat Intelligence Feed

**Community threat intelligence published by [Peris.ai](https://peris.ai)**

Curated indicators of compromise (IOCs), YARA detection rules, and technical analysis reports from our security research team.

---

## Overview

Indra CTI provides actionable threat intelligence derived from:

- **Malware reverse engineering** — static and dynamic analysis of real-world samples
- **Threat hunting** — proactive detection across endpoint and network telemetry
- **OSINT correlation** — enrichment with public threat intelligence sources

All indicators are validated before publication.

## Repository Structure

```
indra-cti/
├── feeds/
│   ├── ioc-all.csv              # All IOCs (master feed)
│   ├── ioc-malware.csv          # Malware-related IOCs
│   ├── ioc-ransomware.csv       # Ransomware-related IOCs
│   ├── ioc-apt.csv              # APT and CVE-related IOCs
│   └── daily/
│       └── YYYY-MM-DD.csv       # Daily IOC updates
├── yara/
│   ├── malware/                 # YARA rules for malware families
│   └── ransomware/              # YARA rules for ransomware families
└── reports/
    └── YYYY-MM-DD-threat-name/
        ├── report.md            # Technical analysis report
        └── screenshots/         # Analysis evidence (tool output)
```

## Feed Format

All CSV feeds use a consistent schema compatible with common SIEM/XDR import formats:

| Column | Description |
|--------|-------------|
| `ioc_type` | Indicator type: `hash-md5`, `hash-sha1`, `hash-sha256`, `domain`, `ip`, `url`, `filename`, `filepath`, `cve`, `mutex`, `registry` |
| `ioc_value` | The indicator value |
| `threat_name` | Associated threat or malware family |
| `threat_type` | Category: `malware`, `ransomware`, `apt`, `cve` |
| `severity` | `critical`, `high`, `medium`, `low` |
| `confidence` | `high`, `medium`, `low` |
| `first_seen` | Date first observed (YYYY-MM-DD) |
| `last_seen` | Date last observed (YYYY-MM-DD) |
| `mitre_attack` | MITRE ATT&CK technique IDs (pipe-separated) |
| `tags` | Semicolon-separated descriptive tags |
| `source` | Intelligence source |
| `description` | Brief description of the indicator |

## Usage

### Direct Feed Access

```bash
# Pull all IOCs
curl -sL https://raw.githubusercontent.com/perisai-labs/indra-cti/main/feeds/ioc-all.csv

# Pull today's IOC updates
curl -sL https://raw.githubusercontent.com/perisai-labs/indra-cti/main/feeds/daily/$(date +%Y-%m-%d).csv

# Pull malware IOCs only
curl -sL https://raw.githubusercontent.com/perisai-labs/indra-cti/main/feeds/ioc-malware.csv
```

### SIEM/XDR Integration

Import the CSV feeds directly into your threat intelligence module. The `ioc_type` and `ioc_value` columns map to standard indicator formats used by most platforms.

### YARA Scanning

```bash
yara -r yara/ <target_file_or_directory>
```

## Update Schedule

| Feed | Frequency |
|------|-----------|
| IOC feeds | Daily |
| YARA rules | Per analysis |
| Analysis reports | Per analysis |

## Contributing

If you identify a false positive or have additional context on any indicator, please open an issue or submit a pull request.

## License

This threat intelligence is provided under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Attribution: **Indra CTI by Peris.ai**

## References

- [Peris.ai](https://peris.ai)
- [MITRE ATT&CK](https://attack.mitre.org)

---

*Maintained by Peris.ai Security Research Team*
