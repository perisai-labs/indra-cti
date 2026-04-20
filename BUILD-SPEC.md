# Indra CTI Portal — Build Specification

## 🎯 Project Overview

Build **Indra CTI Portal** — a public-facing threat intelligence website for Peris.ai, hosted on GitHub Pages. The portal transforms raw IOC feeds, YARA rules, and sanitized reports into a beautiful, interactive web experience.

**Repository:** `/root/.openclaw/workspace/indra-cti/`
**Deploy Branch:** `gh-pages`
**Hosting:** GitHub Pages (static, no backend)
**Branding:** "Indra CTI by Peris.ai"

---

## 🎨 Design Guidelines

### Color Palette
| Role | Color | Usage |
|------|-------|-------|
| Background | `#0a0e27` | Deep navy base |
| Surface | `#111638` | Cards, panels |
| Primary Accent | `#00ff88` | Links, highlights, active states |
| Secondary Accent | `#00d4ff` | Info, subtle highlights |
| Danger | `#ff4757` | Critical/high severity |
| Warning | `#ffa502` | Medium severity |
| Text Primary | `#e8eaf6` | Main text |
| Text Secondary | `#8b8fac` | Labels, meta |
| Border | `#1e2446` | Dividers, borders |

### Typography
- **Body:** Inter (Google Fonts) — clean, readable
- **Headings:** Inter (weight 600-700)
- **Code/Data:** JetBrains Mono (Google Fonts) — mono for IOC values, hashes

### Aesthetic
- Dark ops-room / SOC dashboard vibe
- Clean, data-dense but scannable
- Mobile-first responsive
- Zero clutter — every pixel must earn its place
- Smooth hover transitions on interactive elements

---

## 📄 Page Specifications

### 1. Landing Page (`index.html`)

#### Structure
```
┌─────────────────────────────────────────┐
│  NAV: Home | Feeds | Reports | Download │
├─────────────────────────────────────────┤
│           HERO SECTION                  │
│  "Indra CTI"                            │
│  "by Peris.ai"                          │
│  subtitle: Threat Intelligence Feed     │
│  [CTA: Browse IOC Feeds] [CTA: Get Feed]│
├─────────────────────────────────────────┤
│           STATS CARDS                   │
│  [Total IOCs] [APT] [Malware] [Ransomware]│
│  (numbers pulled from CSV client-side)  │
├─────────────────────────────────────────┤
│         THREAT ACTIVITY CHART           │
│  Bar/line chart: IOCs over time (daily) │
│  using Chart.js (CDN)                   │
├─────────────────────────────────────────┤
│           FEATURES GRID                 │
│  • Real-time IOC Feed                   │
│  • MITRE ATT&CK Mapping                 │
│  • Research Reports                     │
│  • Downloadable Feeds                   │
├─────────────────────────────────────────┤
│         RECENT THREATS (table preview)  │
│  Last 5 entries from ioc-all.csv        │
├─────────────────────────────────────────┤
│           FOOTER                        │
│  "Indra CTI by Peris.ai"                │
│  "Licensed under CC BY 4.0"             │
│  GitHub link                            │
└─────────────────────────────────────────┘
```

#### Stats Cards
- Fetch `feeds/ioc-all.csv` → count rows (minus header) = total IOCs
- Filter by `ioc_type` == "apt" → APT count
- Filter by `threat_type` contains "malware" → Malware count
- Filter by `threat_type` contains "ransomware" → Ransomware count

---

### 2. IOC Feed Browser (`feeds.html`)

#### Structure
```
┌─────────────────────────────────────────┐
│  NAV (active: Feeds)                    │
├─────────────────────────────────────────┤
│  🔍 Search: [input]                     │
│  Filter: [Type ▼] [Severity ▼] [TType ▼]│
│  Results: X,XXX IOCs                    │
├─────────────────────────────────────────┤
│  TABLE (paginated, 50 rows/page)        │
│  | # | Type | IOC Value | Threat | Sev |│
│  |---|------|-----------|--------|-----|│
│  ...sortable columns...                 │
├─────────────────────────────────────────┤
│  [Prev] [1] [2] [3] ... [Next]          │
└─────────────────────────────────────────┘
```

#### Features
- Parse CSV → array of objects (client-side JS)
- **Search:** text match across `ioc_value`, `threat_name`, `description`, `tags`
- **Filters:**
  - `ioc_type`: all / hash-md5 / hash-sha256 / ip / domain / url / email / filename
  - `severity`: all / critical / high / medium / low / informational
  - `threat_type`: all / apt / malware / ransomware / phishing / exploit / cve
- **Sort:** click column header (ascending/descending)
- **Pagination:** 50 rows per page
- **Copy:** click IOC value to copy to clipboard
- **Responsive:** table scrolls horizontally on mobile, cards view

#### Severity Badges
| Severity | Color |
|----------|-------|
| Critical | `#ff4757` (red) |
| High | `#ffa502` (orange) |
| Medium | `#ffd32a` (yellow) |
| Low | `#00d4ff` (blue) |
| Informational | `#8b8fac` (gray) |

---

### 3. Reports Page (`reports.html`)

#### Structure
```
┌─────────────────────────────────────────┐
│  NAV (active: Reports)                  │
├─────────────────────────────────────────┤
│  📋 Research Reports                    │
│  Filter: [Year ▼] [Threat Type ▼]       │
├─────────────────────────────────────────┤
│  REPORT CARD [date] [threat type]       │
│  Title, brief description               │
│  [View Report →] (links to md/pngs)     │
├─────────────────────────────────────────┤
│  (repeat per report)                    │
└─────────────────────────────────────────┘
```

#### Data Source
- Reports live in: `https://raw.githubusercontent.com/perisai-labs/indra-cti/master/reports/`
- Each report folder contains: `screenshots/` with PNG evidence
- Since GitHub Pages can't list directories, hardcode a manifest or use a JS index

#### Report Cards
- Read `reports/index.json` (you create this) — or embed manifest in JS
- Each card: report date (YYYY-MM-DD), threat name, type, severity badge
- Clicking "View Report" → opens a detail view (modal or separate page) with screenshots

---

### 4. Download Page (`download.html`)

#### Structure
```
┌─────────────────────────────────────────┐
│  NAV (active: Download)                 │
├─────────────────────────────────────────┤
│  📥 Download IOC Feeds                  │
├─────────────────────────────────────────┤
│  ioc-all.csv        [3,508 IOCs] [CSV] │
│  ioc-apt.csv        [  486 IOCs] [CSV] │
│  ioc-malware.csv    [   89 IOCs] [CSV] │
│  ioc-ransomware.csv [   54 IOCs] [CSV] │
├─────────────────────────────────────────┤
│  Export Formats                         │
│  [JSON    ] [STIX 2.1    ] [MISP XML]  │
│  (client-side conversion from CSV)      │
├─────────────────────────────────────────┤
│  API / Integration                      │
│  Raw CSV: github.com/.../ioc-all.csv    │
│  Subscribe: [email webhook info]        │
├─────────────────────────────────────────┤
│  📖 MITRE ATT&CK Heatmap                │
│  (interactive matrix - top techniques)  │
└─────────────────────────────────────────┘
```

#### Export (Client-Side)
- CSV → JSON: parse CSV → `JSON.stringify()` → download blob
- CSV → STIX: map to STIX 2.1 objects (Indicator type)
- Include columns/field descriptions for each format

---

### 5. Shared Navigation Component

```html
<nav class="navbar">
  <a href="index.html" class="nav-brand">🛡️ Indra CTI</a>
  <ul class="nav-links">
    <li><a href="index.html">Home</a></li>
    <li><a href="feeds.html">IOC Feeds</a></li>
    <li><a href="reports.html">Reports</a></li>
    <li><a href="download.html">Download</a></li>
  </ul>
  <a href="https://github.com/perisai-labs/indra-cti" class="nav-github" title="GitHub">⬡</a>
</nav>
```

- Active page gets highlighted nav link (add `class="active"` on current page)
- Mobile: hamburger menu (pure CSS, no JS framework)

---

## 🔧 Technical Requirements

### Stack
- **HTML5** — semantic markup
- **CSS3** — custom properties (CSS variables), flexbox, grid, media queries
- **Vanilla JavaScript** — no frameworks, no bundlers
- **Chart.js** (CDN: `https://cdn.jsdelivr.net/npm/chart.js`) — for charts
- **Google Fonts** (CDN) — Inter + JetBrains Mono

### Data Loading Strategy

CSV files are on the `master` branch. On `gh-pages`:

```javascript
const CSV_BASE = 'https://raw.githubusercontent.com/perisai-labs/indra-cti/master/feeds/';
const IOCS_URL = CSV_BASE + 'ioc-all.csv';

// Fetch and parse
fetch(IOCS_URL)
  .then(r => r.text())
  .then(csv => {
    const headers = csv.split('\n')[0].split(',');
    const rows = csv.split('\n').slice(1).filter(r => r.trim());
    const iocs = rows.map(r => {
      const vals = r.split(',');
      return Object.fromEntries(headers.map((h, i) => [h.trim(), vals[i]?.trim()]));
    });
    // Use iocs array
  });
```

⚠️ **Important:** GitHub raw URL rate limit is generous but consider caching results in `sessionStorage` to avoid re-fetching on nav.

### Security Rules (MANDATORY — Non-Negotiable)

1. ❌ **NEVER** embed or reference `/root/.openclaw/` paths in ANY HTML/CSS/JS
2. ❌ **NEVER** embed or reference `/home/kali/` paths in ANY file
3. ❌ **NEVER** include Brahma XDR XML rules or Brahma NDR Suricata rules
4. ❌ **NEVER** expose internal API keys, tokens, or credentials
5. ✅ **ONLY** publish: sanitized IOCs, YARA rules (safe), report summaries, screenshots (sanitized)
6. ✅ Use only `raw.githubusercontent.com` URLs for data
7. ✅ All screenshots in repo must already be sanitized (handled by term2img.py)

### File Structure (on gh-pages branch)

```
gh-pages/
├── index.html           # Landing page
├── feeds.html           # IOC browser
├── reports.html         # Research reports
├── download.html        # Downloads & exports
├── css/
│   └── style.css        # Shared styles
├── js/
│   ├── common.js        # Shared utilities (nav, CSV parser)
│   ├── stats.js         # Stats computation
│   ├── feed-browser.js  # IOC table + search/filter
│   └── export.js        # CSV → JSON/STIX conversion
└── assets/
    └── logo.svg         # Optional Peris.ai/Indra logo
```

### CNAME
If domain mapping needed later: add `CNAME` file on `gh-pages` root.

---

## 🚀 Deployment

### Push to gh-pages
```bash
cd /root/.openclaw/workspace/indra-cti
git checkout gh-pages
# copy built files
git add -A
git commit -m "portal: initial release"
git push origin gh-pages
```

### GitHub Pages URL
`https://perisai-labs.github.io/indra-cti/`

---

## ✅ Acceptance Criteria

- [ ] All 4 pages functional (Home, Feeds, Reports, Download)
- [ ] IOC browser: search, filter, sort, pagination working
- [ ] Stats cards show correct numbers from CSV
- [ ] Dark theme applied consistently
- [ ] Mobile responsive (tested on 375px width)
- [ ] No console errors
- [ ] No internal paths leaked in source code
- [ ] Page loads < 3s on 3G simulation
- [ ] Pushed to `gh-pages` branch successfully
- [ ] Post summary to Discord channel with URL + screenshots

---

## 📋 Execution Order

1. **Create directory structure** on `gh-pages` branch
2. **Build `css/style.css`** — CSS variables, base styles, nav, responsive
3. **Build `js/common.js`** — CSV parser, nav highlight, clipboard copy
4. **Build `index.html`** — landing page with embedded CSS/JS references
5. **Build `js/stats.js`** — stats computation from CSV
6. **Build `feeds.html` + `js/feed-browser.js`** — full IOC browser
7. **Build `reports.html`** — report listing
8. **Build `download.html` + `js/export.js`** — downloads + format export
9. **Test all pages** — check links, filters, responsive, console errors
10. **Push `gh-pages`** — commit and deploy

---

*Build Specification v1.0 — Prepared by Xhaxor (Xor) for Aether*
