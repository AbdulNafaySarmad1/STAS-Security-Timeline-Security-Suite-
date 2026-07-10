# Security Timeline Analysis Suite (STAS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C++-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://www.python.org/downloads/)

**A hybrid static + dynamic + behavioral malware analysis platform** with automated timeline reconstruction, risk scoring, graphing, and a beautiful dark-mode dashboard.

STAS combines a high-performance C++ analysis engine with a modern PyQt6 Python GUI to deliver a powerful, local, open-source malware analysis tool.

## Features


### Core Engine (C++)
- **Static Analysis**
  - MD5, SHA1, SHA256 hashing
  - Entropy calculation (packed/encrypted detection)
  - PE header parsing (imports, exports, sections, TLS callbacks)
  - String extraction
  - Packer detection (UPX, ASPack, etc.)
  - YARA rule scanning (custom + community rules)
- **Dynamic Timeline (Simulated / Extensible)**
  - Process, file, registry, network events
  - Timestamped and sequenced
  - Persistence detection (Run keys, services, etc.)
- **SQLite Event Storage**
  - Full timeline exportable to JSON/HTML
- **Risk Scoring Engine**
  - Rule-based + ML-ready scoring (0–100)
  - Categories: Stealth, Persistence, Propagation, Exfiltration
- **MITRE ATT&CK Mapping**
  - Data-driven JSON rules for import and behavioral-event combinations
  - STIX 2.1 `attack-pattern` bundle output
  - Default rules in `data/attack_rules.json`

### Dashboard (Python + PyQt6)
- Dark-mode fluent UI
- Live event feed (real-time updates)
- Timeline visualization
- Risk score panel with color coding
- Static analysis summary
- Event filtering by type/severity
- Export reports (JSON, HTML, Markdown)
- Built-in SQLite browser

## Screenshots

![STAS Dashboard](<img width="960" height="514" alt="P1" src="https://github.com/user-attachments/assets/0678d3e5-b666-42ab-ae79-d0718d7b8661" />
)

## Quick Start

### Prerequisites
- Windows 10/11 (64-bit)
- Visual Studio 2022 (Community OK) with C++ desktop development
- Python 3.10+ 
- Git

### Build & Run

1. Clone the repo
```bash
git clone https://github.com/AbdulNafaySarmad1/STAS-Security-Timeline-Security-Suite-
cd STAS
```

Cross-platform C++ build

Linux:

```bash
sudo apt install build-essential cmake nlohmann-json3-dev libsqlite3-dev
# Optional: libssl-dev libyara-dev
cmake -S . -B build-linux
cmake --build build-linux -j
./build-linux/stas_engine ./dummy_test.exe
```

Windows:

```powershell
vcpkg install nlohmann-json sqlite3 openssl yara
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\stas_engine.exe .\dummy_test.exe
```

Optional CMake switches:

```bash
cmake -S . -B build -DSTAS_ENABLE_SQLITE=OFF -DSTAS_ENABLE_YARA=OFF -DSTAS_ENABLE_OPENSSL=OFF
```

Build the C++ engine

Bash# Open "x64 Native Tools Command Prompt for VS 2022"
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

Install Python dependencies & run dashboard

Bashcd ../src/python
pip install pyqt6 pyinstaller graphviz pandas sqlite3
python dashboard.py

Analyze a sample

Bashcd ../../build/Release
stas_engine.exe ../../../test_sample.exe

Switch back to dashboard — events appear live!

Standalone Executables (Optional)
Bash# Engine is already built as stas_engine.exe

# Dashboard standalone
cd ../src/python
pyinstaller --onefile --windowed --name STAS_Dashboard dashboard.py
# → dist/STAS_Dashboard.exe
Project Structure
textSTAS/
├── build/                  # CMake build output
├── src/
│   ├── cpp/                # Core engine (static, dynamic, SQLite, scoring)
│   └── python/             # PyQt6 dashboard + anomaly detection
├── data/                   # ML baseline, YARA rules
├── events.db               # Generated analysis database
├── dummy_test.exe          # Example test file
└── README.md
Future Roadmap (Bonus Features Ready to Add)

Real API hooking via MinHook
GraphViz process/file/network graphs
scikit-learn anomaly detection (clustering/families)
LLM-powered behavioral narration
Full sandbox with suspended process + remote thread injection
Memory dump + string extraction
REST API server mode

MITRE ATT&CK Rule Format

Rules live in `data/attack_rules.json` and are loaded by the C++ engine at runtime. `imports` and `behaviors` are ANDed together; each item supports exact matching or `*` wildcards.

```json
{
  "id": "T1055",
  "name": "Process Injection",
  "tactic": "Defense Evasion",
  "confidence": 0.9,
  "imports": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
  "behaviors": []
}
```

Contributing
Pull requests are welcome! Especially:

Real dynamic hooking modules
YARA rule contributions
UI enhancements
ML model improvements

License
MIT License — feel free to use, modify, and distribute.

STAS — Because your malware deserves a timeline.
Built with 🔥 by Abdul Nafay Sarmad — December 2025



