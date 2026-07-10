# STAS: Security Timeline Analysis Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C++-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://www.python.org/downloads/)
[![Cross-Platform](https://img.shields.io/badge/Linux%20%26%20Windows-Ready-brightgreen.svg)](#cross-platform-support)

**Enterprise malware analysis platform** combining high-performance C++ static analysis with AI-powered behavioral intelligence, threat correlation, and automated detection rules. Built for security operations, threat intelligence teams, and incident responders.

**What makes STAS different:** While most tools focus on *analyzing* one malware sample, STAS connects the dots across entire campaigns. It correlates infrastructure, detects code reuse, generates detection rules, and tells you who's behind the attack—all from local, open-source analysis.

---

## ✨ What You Get

### **C++ Engine: Fast Static + Dynamic Analysis**

- **Static Analysis:** PE parsing, entropy per-section, import extraction, packer detection, YARA scanning
- **Dynamic Timeline:** Simulated process/file/registry/network events with timestamps
- **MITRE ATT&CK Mapping:** Automatic technique inference from imports + behaviors
- **IOC Extraction:** Networks, domains, URLs, credentials, crypto wallets, file paths, registry keys—all with confidence scoring
- **Import Profiling:** Categorizes imports (MEMORY, NETWORK, PERSISTENCE, etc.) and predicts malware archetype (RAT, Ransomware, Loader, etc.)
- **Risk Scoring:** Contextual scoring across stealth, persistence, propagation, exfiltration dimensions
- **SQLite Storage:** Full event timeline exportable to JSON/HTML

### **AI-Powered Analytics Layer (Python)**

- **Behavior Clustering:** DBSCAN/HDBSCAN to find similar samples; Isolation Forest anomaly detection
- **Malware Family Recognition:** Pre-trained similarity engine for Emotet, Ryuk, Cobalt Strike, Mimikatz, Metasploit, AsyncRAT, RedLine, AgentTesla, Formbook + custom families
- **Campaign Correlation:** NetworkX-based threat actor campaign detection using weighted signals (shared C2, mutexes, imports, ATT&CK combos, timestamps)
- **Threat Intelligence Enrichment:** Async IOC enrichment against VirusTotal, MalwareBazaar, URLhaus, AbuseIPDB, ThreatFox with 24hr caching
- **AI Analyst Reports:** Claude-powered narrative generation—structured executive summaries, technical analysis, attribution hints, all evidence-based
- **Detection Rule Auto-Generation:** YARA rules (with imphash, entropy, strings) + Sigma rules (Sysmon-compatible) from analysis results

### **Beautiful Dark-Mode Dashboard (PyQt6)**

- **Interactive Timeline Widget:** CrowdStrike-inspired event viewer with:
  - Collapsible event grouping (by process or time window)
  - Real-time search/filter (process, type, severity, ATT&CK technique)
  - Clickable ATT&CK badges linking to MITRE
  - Lazy-load rendering for 10k+ events
  - Export selected events to JSON/Markdown
  - "Jump to Suspicious" smart navigation

- **Campaign Graph:** Interactive vis.js network showing correlated samples
  - Color-coded by campaign, family, or risk score
  - Hover edges to see correlation signals
  - Click nodes to inspect sample details
  - Export to STIX 2.1 or MISP for team collaboration

- **Unified Risk Dashboard:** Overview of family predictions, behavioral archetypes, anomaly scores, novelty signals

---

## 🚀 Quick Start

### **Prerequisites**

- **Linux:** `build-essential`, `cmake`, `nlohmann-json3-dev`, `libsqlite3-dev` (optional: `libssl-dev`, `libyara-dev`)
- **Windows:** Visual Studio 2022, vcpkg with `nlohmann-json`, `sqlite3`, `openssl`, `yara`
- **Python 3.10+**

### **Build & Run (Linux)**

```bash
# Clone and enter repo
git clone https://github.com/AbdulNafaySarmad1/STAS-Security-Timeline-Security-Suite-
cd STAS

# Install C++ dependencies
sudo apt install build-essential cmake nlohmann-json3-dev libsqlite3-dev

# Optional threat intel & visualization features
sudo apt install libssl-dev libyara-dev

# Build engine
cmake -S . -B build-linux
cmake --build build-linux -j$(nproc)

# Install Python environment
cd src/python
pip install -r ../../requirements.txt --break-system-packages

# Run dashboard
python dashboard.py
```

### **Build & Run (Windows)**

```powershell
# Install vcpkg packages
vcpkg install nlohmann-json sqlite3 openssl yara

# Build with CMake
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# Run dashboard from Python directory
cd src\python
python dashboard.py
```

### **Configure API Keys (Optional)**

Copy config templates and add your keys:

```bash
# Threat Intelligence Enrichment
cp data/threat_intel_config.example.json data/threat_intel_config.json
# Add VirusTotal and AbuseIPDB keys, or use environment variables:
export VT_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"

# AI Analyst Reports
cp data/ai_analyst_config.example.json data/ai_analyst_config.json
# Add Anthropic API key:
export ANTHROPIC_API_KEY="your_key"
```

### **Analyze a Sample**

```bash
# Analyze with C++ engine
./build-linux/stas_engine ./malware_sample.exe

# Open dashboard to explore results
python src/python/dashboard.py
```

---

## 📊 Core Modules

### **C++ (src/cpp/)**

| Module | Purpose |
|--------|---------|
| `static_analysis.cpp` | PE parsing, entropy, imports, packer detection, YARA integration |
| `dynamic_timeline.cpp` | Process/file/registry/network event simulation |
| `attack_mapper.cpp` | MITRE ATT&CK technique inference from imports + behaviors |
| `import_profiler.cpp` | Import categorization + behavioral archetype prediction |
| `ioc_extractor.cpp` | Domain, IP, URL, credential, crypto IOC extraction with regex + heuristics |
| `risk_scoring.cpp` | Contextual risk scoring across threat dimensions |
| `sqlite_db.cpp` | Event timeline persistence |

### **Python Analytics (src/python/)**

| Module | Purpose |
|--------|---------|
| `timeline_widget.py` | Interactive PyQt6 event timeline UI |
| `behavior_analyzer.py` | Malware family similarity, clustering, anomaly detection |
| `campaign_correlation.py` | NetworkX campaign detection via weighted signal correlation |
| `threat_intel_enricher.py` | Async IOC enrichment (VT, MalwareBazaar, URLhaus, AbuseIPDB, ThreatFox) with SQLite caching |
| `ai_analyst_narrator.py` | Claude-powered structured threat report generation |
| `detection_rule_generator.py` | YARA + Sigma + MISP IOC report auto-generation |
| `dashboard.py` | Main PyQt6 dashboard |

---

## 🔧 Advanced Features

### **Cross-Platform Support**

STAS builds natively on **Linux and Windows**. Optional dependencies (YARA, OpenSSL, SQLite) are detected at build time; the engine gracefully degrades if libraries are unavailable.

```bash
# Minimal Linux build (no optional deps)
cmake -S . -B build -DSTAS_ENABLE_YARA=OFF -DSTAS_ENABLE_OPENSSL=OFF -DSTAS_ENABLE_SQLITE=OFF
cmake --build build -j
```

### **Campaign Correlation**

Detect threat actor campaigns from multiple samples using weighted signals:

```python
from campaign_correlation import CampaignGraph

graph = CampaignGraph("data/campaign.db")
graph.build_graph(samples)  # Correlate shared C2, mutexes, imports, families
campaigns = graph.detect_campaigns()  # Louvain community detection

# Export for team collaboration
graph.export_html_graph("campaign_viz.html", color_by="campaign")
stix_bundle = graph.export_stix(campaigns)
misp_events = graph.export_misp(campaigns)
```

### **Threat Intelligence Enrichment**

Async IOC lookups with intelligent caching:

```python
import asyncio
from threat_intel_enricher import ThreatIntelEnricher

async def enrich():
    enricher = ThreatIntelEnricher()
    results = await enricher.enrich_iocs([
        {"value": "8.8.8.8", "type": "IPV4"},
        {"value": "malware.example.com", "type": "DOMAIN"},
    ])
    
    for result in results:
        print(f"{result.ioc_value}: {result.aggregate_verdict} ({result.aggregate_score}/100)")
        print(f"  Sources: {[s.name for s in result.sources]}")

asyncio.run(enrich())
```

### **AI-Powered Threat Reports**

Generate analyst-grade narratives with Claude:

```python
from ai_analyst_narrator import AIAnalystNarrator

narrator = AIAnalystNarrator()
report = narrator.generate_report(analysis_json)

print(report.executive_summary)
print(report.technical_analysis)
print(report.markdown)  # Full Markdown report
```

### **Auto-Generate Detection Rules**

Create YARA, Sigma, and MISP from analysis:

```python
from detection_rule_generator import DetectionRuleGenerator

gen = DetectionRuleGenerator()
yara_rule = gen.generate_yara(analysis)
sigma_rule = gen.generate_sigma(analysis)
ioc_report = gen.generate_ioc_report(analysis)
```

---

## 📁 Project Structure

```
STAS/
├── build/                    # CMake build output
├── src/
│   ├── cpp/                  # C++17 analysis engine
│   │   ├── static_analysis.cpp
│   │   ├── attack_mapper.cpp
│   │   ├── import_profiler.cpp
│   │   ├── ioc_extractor.cpp
│   │   ├── pe_structs.h      # Portable PE parsing (no Windows.h)
│   │   └── ...
│   └── python/               # Python analytics & UI
│       ├── dashboard.py      # PyQt6 main window
│       ├── timeline_widget.py
│       ├── behavior_analyzer.py
│       ├── campaign_correlation.py
│       ├── threat_intel_enricher.py
│       ├── ai_analyst_narrator.py
│       ├── detection_rule_generator.py
│       └── requirements.txt
├── data/                     # Config templates & rules
│   ├── attack_rules.json
│   ├── import_capability_rules.json
│   ├── threat_intel_config.example.json
│   └── ai_analyst_config.example.json
├── CMakeLists.txt            # Cross-platform build config
└── README.md
```

---

## 🎯 Use Cases

**Security Operations:** Monitor malware behavior in real-time with interactive timelines. Flag suspicious patterns instantly.

**Threat Intelligence:** Correlate malware samples to identify APT campaigns. Export campaign profiles to STIX/MISP for team sharing.

**Incident Response:** Generate analyst-ready threat reports in seconds. Know the malware family, capabilities, and TTPs immediately.

**Malware Research:** Cluster similar samples. Detect code reuse. Generate detection rules for Yara/Sigma/MISP.

**Compliance & Threat Hunting:** Export structured IOCs for SOC ingestion. Benchmark against known families and techniques.

---

## 📊 Malware Families Supported

Pre-trained similarity profiles for:
- **Emotet** (Loader)
- **Ryuk** (Ransomware)
- **Cobalt Strike** (Backdoor)
- **Mimikatz** (Credential Stealer)
- **Metasploit** (Backdoor)
- **AsyncRAT** (RAT)
- **RedLine** (Stealer)
- **AgentTesla** (Stealer)
- **Formbook** (Stealer)

Add custom families via `behavior_analyzer.py`.

---

## 🛠️ Configuration

### **Threat Intel APIs**

Copy and edit `data/threat_intel_config.example.json`:

```json
{
  "api_keys": {
    "virustotal": "your_vt_key",
    "abuseipdb": "your_abuseipdb_key"
  },
  "rate_limits": {
    "VirusTotal": 16.0,
    "MalwareBazaar": 1.0,
    "URLhaus": 1.0,
    "AbuseIPDB": 2.0,
    "ThreatFox": 1.0
  }
}
```

### **AI Analyst Reports**

Copy and edit `data/ai_analyst_config.example.json`:

```json
{
  "anthropic_api_key": "your_claude_key",
  "model": "claude-sonnet-4-6",
  "timeout_seconds": 90,
  "max_retries": 3,
  "max_tokens": 5000
}
```

---

## 📦 Dependencies

**C++ (Optional):**
- `nlohmann/json` – JSON I/O
- `SQLite3` – Event storage
- `OpenSSL` – Hashing (fallback to std lib)
- `YARA` – Malware rule scanning

**Python:**
- `PyQt6` – Desktop GUI
- `aiohttp` – Async HTTP for threat intel
- `networkx` – Campaign graph detection
- `scikit-learn` – Anomaly detection & clustering
- `pandas`, `numpy` – Data analysis
- `Jinja2` – Detection rule templating
- `pyvis` – Interactive graph visualization

Install all:
```bash
pip install -r src/python/requirements.txt --break-system-packages
```

---

## 🚀 Contributing

PRs welcome! Areas that need love:
- Real API hooking via MinHook (dynamic analysis)
- Memory dump + string extraction
- Full sandbox process suspension
- Additional malware family profiles
- YARA rule contributions
- UI/UX enhancements

---

## 📄 License

MIT License – free to use, modify, and distribute.

---

## 👨‍💻 Built By

**Abdul Nafay Sarmad** | 

First-year CS student at SSUET, building enterprise malware analysis tools.

---

## 🔗 Quick Links

- [MITRE ATT&CK](https://attack.mitre.org/) – Technique reference
- [Sigma Rules](https://github.com/SigmaHQ/sigma) – Detection rules
- [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) – Threat info sharing
- [MISP](https://www.misp-project.org/) – Threat intel platform
- [VirusTotal](https://www.virustotal.com/) – File scanning
- [YARA](https://virustotal.github.io/yara/) – Malware rules
