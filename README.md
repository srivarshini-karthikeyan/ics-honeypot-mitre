<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0a0a0a,50:1a0a2e,100:0d1117&height=220&section=header&text=ICS-Honeypot-MITRE&fontSize=60&fontColor=00ff41&animation=fadeIn&fontAlignY=38&desc=ICS%20%2F%20OT%20Deception%20Layer%20%7C%20MITRE%20ATT%26CK%20Mapped%20Threat%20Intelligence&descAlignY=60&descAlign=50&descSize=18&descColor=7ee787" width="100%"/>

<br/>

<img src="https://img.shields.io/badge/MITRE%20ATT%26CK-ICS%20Matrix-00ff41?style=for-the-badge&logo=target&logoColor=black"/>
<img src="https://img.shields.io/badge/Python-3.8%2B-7ee787?style=for-the-badge&logo=python&logoColor=black"/>
<img src="https://img.shields.io/badge/Protocols-4%20Emulated-00ff41?style=for-the-badge&logo=gnometerminal&logoColor=black"/>
<img src="https://img.shields.io/badge/Type-Deception%20Honeypot-7ee787?style=for-the-badge&logo=windowsterminal&logoColor=black"/>
<img src="https://img.shields.io/badge/Domain-ICS%20%2F%20OT%20Security-ff6b6b?style=for-the-badge&logo=hackthebox&logoColor=white"/>

<br/><br/>

<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Modbus%20%7C%20DNP3%20%7C%20S7comm-Protocol%20Stack-00ff41?style=for-the-badge&logo=wireshark&logoColor=white"/>
<img src="https://img.shields.io/badge/Red%20%26%20Blue%20Team-Dual%20Use-ff6b6b?style=for-the-badge&logo=hackthebox&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-7ee787?style=for-the-badge&logo=opensourceinitiative&logoColor=white"/>

<br/><br/>

```
╔══════════════════════════════════════════════════════════════════════════╗
║   DEPLOYING DECOY ICS INFRASTRUCTURE  ░░░░░░░░░░░░░░░░░░░░░░░  [████░]  ║
║   MAPPING ADVERSARY TTPs TO MITRE     ░░░░░░░░░░░░░░░░░░░░░░░  [████░]  ║
║   THREAT ACTOR PROFILING              ░░░░░░░░░░░░░░░░░░░░░░░  [████░]  ║
║   ATTACK TELEMETRY COLLECTION         ░░░░░░░░░░░░░░░░░░░░░░░  [LIVE ]  ║
╚══════════════════════════════════════════════════════════════════════════╝
```

</div>

---

## ⚡ OVERVIEW

> **ICS Honeypot MITRE** is a high-fidelity **Industrial Control System (ICS/SCADA) honeypot** that lures adversaries targeting critical infrastructure — and maps every observed attack technique to the **MITRE ATT&CK for ICS** framework in real time.

Operational Technology (OT) and ICS environments are prime targets for nation-state actors, ransomware groups, and cyber saboteurs. This honeypot acts as a **deception layer** — mimicking real PLCs, HMIs, and SCADA systems — while silently fingerprinting every attacker and classifying their TTPs.

<div align="center">

```
  ATTACKER                  HONEYPOT LAYER               MITRE ATT&CK
  ─────────                 ──────────────               ────────────
  [Nation State]            ┌─────────────┐              ┌──────────┐
  [APT Group   ] ─────────► │  Fake PLC   │ ─telemetry─► │ T0855    │
  [Ransomware  ]            │  Fake HMI   │              │ T0856    │
  [Opportunist ] ─────────► │  Fake SCADA │ ─telemetry─► │ T0801    │
                            └─────────────┘              └──────────┘
                                   │
                            [Alert + Report]
```

</div>

---

## 🎯 KEY FEATURES

<table>
<tr>
<td width="50%">

### 🏭 ICS Protocol Emulation
Emulates industrial protocols that real ICS devices speak — convincing enough to fool automated scanners and human operators alike.

- **Modbus TCP** — the lingua franca of PLCs
- **DNP3** — common in power & water utilities  
- **EtherNet/IP** — Allen-Bradley ecosystem  
- **S7comm** — Siemens S7 family devices  

</td>
<td width="50%">

### 🧠 MITRE ATT&CK Mapping
Every captured interaction is automatically tagged to the **MITRE ATT&CK for ICS** matrix.

- Tactic & technique classification  
- Sub-technique resolution  
- TTP chain reconstruction  
- Threat actor fingerprinting  

</td>
</tr>
<tr>
<td width="50%">

### 📡 Real-Time Telemetry
Live capture and structured logging of all attacker activity.

- Connection metadata (IP, port, timestamp)  
- Payload inspection & decoding  
- Behavioral session analysis  
- GeoIP enrichment  

</td>
<td width="50%">

### 📊 Threat Intelligence Reports
Generate structured reports ready for SOC teams and threat intel sharing.

- STIX/TAXII compatible output  
- JSON / CSV export  
- ATT&CK Navigator layer generation  
- IOC extraction  

</td>
</tr>
</table>

---

## 🗺️ MITRE ATT&CK FOR ICS COVERAGE

<div align="center">

| Tactic | Technique ID | Description | Honeypot Signal |
|--------|-------------|-------------|-----------------|
| 🔍 **Discovery** | T0846 | Remote System Discovery | Port scan detection |
| 🔍 **Discovery** | T0888 | Remote System Information Discovery | Protocol enumeration |
| 🎯 **Collection** | T0801 | Monitor Process State | Register read ops |
| 🎯 **Collection** | T0802 | Automated Collection | Bulk coil reads |
| ⚡ **Execution** | T0858 | Change Operating Mode | Mode switch cmds |
| 💥 **Inhibit Response** | T0816 | Device Restart/Shutdown | Stop coil writes |
| 💥 **Inhibit Response** | T0855 | Unauthorized Command Message | Rogue write cmds |
| 🕵️ **Lateral Movement** | T0812 | Default Credentials | Auth attempts |
| 🚨 **Impact** | T0826 | Loss of Availability | DoS patterns |
| 🚨 **Impact** | T0831 | Manipulation of Control | Set point tampering |

</div>

---

## 🏗️ ARCHITECTURE

```
                        ┌─────────────────────────────────────────┐
                        │           ICS HONEYPOT SYSTEM            │
                        │                                          │
  INTERNET              │   ┌────────────┐    ┌────────────────┐  │
  ─────────             │   │  Protocol  │    │   Log Engine   │  │
  Scanners  ──────────► │   │  Emulator  │───►│  (Structured)  │  │
  Attackers ──────────► │   │            │    └───────┬────────┘  │
  Bots      ──────────► │   │ • Modbus   │            │           │
                        │   │ • DNP3     │    ┌───────▼────────┐  │
                        │   │ • EtherNet │    │  MITRE Mapper  │  │
                        │   │   /IP      │    │                │  │
                        │   │ • S7comm   │    │ TTP Classifier │  │
                        │   └────────────┘    └───────┬────────┘  │
                        │                             │           │
                        │                    ┌────────▼────────┐  │
                        │                    │  Report Engine  │  │
                        │                    │  • JSON/CSV     │  │
                        │                    │  • Navigator    │  │
                        │                    │  • Alerts       │  │
                        │                    └─────────────────┘  │
                        └─────────────────────────────────────────┘
```

---

## 🚀 QUICK START

### Prerequisites

```bash
# Python 3.8+ required
python --version

# Clone the repository
git clone https://github.com/srivarshini-karthikeyan/ics-honeypot-mitre.git
cd ics-honeypot-mitre
```

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### Deploy the Honeypot

```bash
# Start all ICS protocol emulators
python honeypot.py --config config.yaml

# Start with specific protocols only
python honeypot.py --protocols modbus,dnp3

# Enable verbose attack logging
python honeypot.py --verbose --log-level DEBUG
```

### View Attack Dashboard

```bash
# Generate MITRE ATT&CK Navigator layer from captured logs
python mitre_mapper.py --input logs/attacks.json --output navigator_layer.json

# Export threat report
python report_generator.py --format json --output threat_report.json
```

---

## 📁 PROJECT STRUCTURE

```
ics-honeypot-mitre/
│
├── 🏭  honeypot/
│   ├── protocols/
│   │   ├── modbus_emulator.py      # Modbus TCP server (Port 502)
│   │   ├── dnp3_emulator.py        # DNP3 protocol handler
│   │   ├── enip_emulator.py        # EtherNet/IP emulator
│   │   └── s7comm_emulator.py      # Siemens S7 emulator
│   │
│   └── core/
│       ├── session_handler.py      # Connection lifecycle mgmt
│       └── payload_inspector.py    # Deep packet inspection
│
├── 🧠  mitre/
│   ├── mapper.py                   # TTP classification engine
│   ├── ics_techniques.json         # MITRE ATT&CK ICS technique DB
│   └── navigator_exporter.py       # ATT&CK Navigator layer gen
│
├── 📊  reporting/
│   ├── report_generator.py         # Multi-format report engine
│   ├── ioc_extractor.py            # IOC harvesting
│   └── templates/                  # Report templates
│
├── 📝  logs/                        # Captured attack telemetry
├── ⚙️  config.yaml                  # Honeypot configuration
├── 📋  requirements.txt
└── 🚀  honeypot.py                  # Main entry point
```

---

## 🔧 CONFIGURATION

```yaml
# config.yaml

honeypot:
  name: "ICS-HONEYPOT-01"
  
  protocols:
    modbus:
      enabled: true
      port: 502
      device_id: "Schneider Electric Modicon M340"
      
    dnp3:
      enabled: true
      port: 20000
      station_address: 10
      
    enip:
      enabled: true
      port: 44818
      device_type: "Programmable Logic Controller"
      
    s7comm:
      enabled: false   # Toggle as needed
      port: 102

logging:
  level: INFO
  structured: true
  format: json
  output: logs/attacks.json

mitre:
  auto_map: true
  confidence_threshold: 0.75
  generate_navigator: true

alerts:
  enabled: true
  channels:
    - type: email
      recipients: ["soc@yourorg.com"]
    - type: webhook
      url: "https://your-siem.example.com/ingest"
```

---

## 📊 SAMPLE OUTPUT

<details>
<summary><b>📌 Click to expand — Sample attack log (JSON)</b></summary>

```json
{
  "timestamp": "2025-03-10T14:32:01Z",
  "session_id": "sess_8f2a91bc",
  "source": {
    "ip": "185.220.xxx.xxx",
    "port": 54231,
    "geo": {
      "country": "Unknown",
      "asn": "AS206936",
      "org": "Tor Exit Node"
    }
  },
  "honeypot": {
    "protocol": "modbus",
    "port": 502,
    "device_emulated": "Schneider Electric Modicon M340"
  },
  "interaction": {
    "function_code": 3,
    "description": "Read Holding Registers",
    "register_start": 0,
    "register_count": 125,
    "raw_payload": "00010000000601030000007D"
  },
  "mitre_mapping": {
    "tactic": "Collection",
    "tactic_id": "TA0100",
    "technique": "Monitor Process State",
    "technique_id": "T0801",
    "confidence": 0.94,
    "rationale": "Bulk register read across full address space indicates reconnaissance of process variables"
  },
  "threat_score": 72,
  "tags": ["ics-recon", "bulk-read", "modbus", "automated-scanner"]
}
```

</details>

<details>
<summary><b>📌 Click to expand — MITRE ATT&CK Navigator Layer (JSON)</b></summary>

```json
{
  "name": "ICS Honeypot Observed TTPs",
  "versions": { "attack": "14", "navigator": "4.9" },
  "domain": "ics-attack",
  "techniques": [
    {
      "techniqueID": "T0846",
      "color": "#ff6b6b",
      "comment": "Observed 847 times — network scanners probing Modbus",
      "score": 847
    },
    {
      "techniqueID": "T0801",
      "color": "#ffd93d",
      "comment": "Observed 412 times — bulk register reads",
      "score": 412
    },
    {
      "techniqueID": "T0855",
      "color": "#ff4500",
      "comment": "Observed 23 times — unauthorized write commands",
      "score": 23
    }
  ]
}
```

</details>

---

## 🌐 USE CASES

<div align="center">

| Use Case | Description |
|----------|-------------|
| 🔬 **Threat Research** | Observe real-world ICS attack patterns and TTPs in the wild |
| 🛡️ **SOC Enrichment** | Feed structured IOCs and TTPs into your SIEM/SOAR |
| 📚 **Red Team Training** | Understand how defenders detect ICS intrusions |
| 🎓 **Academic Research** | Collect ground-truth datasets for ICS security ML models |
| 📋 **Compliance** | Demonstrate active threat monitoring for NERC CIP, IEC 62443 |

</div>

---

## ⚠️ LEGAL & ETHICAL USE

> **This tool is designed exclusively for authorized defensive security research.**

- ✅ Deploy only on systems **you own or have explicit written permission** to monitor  
- ✅ Comply with all local laws and regulations regarding honeypot deployment  
- ✅ Do not use captured data to retaliate against or attack observed IPs  
- ❌ **Never deploy in production OT/ICS environments** without thorough isolation  
- ❌ Do not use this project for unauthorized access to any real ICS/SCADA systems  

This project is a research and educational tool. The author bears no liability for misuse.

---

## 🤝 CONTRIBUTING

Contributions are welcome! Here's how to get involved:

```bash
# 1. Fork the repository
# 2. Create your feature branch
git checkout -b feature/add-s7comm-emulator

# 3. Commit your changes
git commit -m "feat: add full S7comm read/write emulation"

# 4. Push and open a Pull Request
git push origin feature/add-s7comm-emulator
```

**Areas where contributions are especially valued:**
- 🔌 Additional ICS protocol emulators (IEC 104, BACnet, Profinet)
- 🧠 Improved MITRE TTP classification heuristics
- 📊 Dashboard / visualization layer
- 🧪 Unit tests and integration tests
- 📖 Documentation improvements

---

## 📚 REFERENCES & RESOURCES

- 📘 [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — Official ICS attack matrix  
- 🏭 [ICS-CERT Advisories](https://www.cisa.gov/ics-cert) — Real-world ICS vulnerability intelligence  
- 📖 [IEC 62443](https://www.iec.ch/cyber-security) — Industrial cybersecurity standards  
- 🔬 [SANS ICS Security](https://www.sans.org/industrial-control-systems-security/) — Training and research  
- 📊 [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — Visualize your coverage  

---

## 👩‍💻 AUTHOR

<div align="center">

<img src="https://github.com/srivarshini-karthikeyan.png" width="100" style="border-radius: 50%"/>

**Srivarshini Karthikeyan**  
*ICS Security Researcher | Cyber Defense | MITRE ATT&CK*

[![GitHub](https://img.shields.io/badge/GitHub-srivarshini--karthikeyan-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/srivarshini-karthikeyan)

</div>

---

## 📜 LICENSE

```
MIT License — Copyright (c) 2025 Srivarshini Karthikeyan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, and distribute, subject to the
condition that the original copyright notice and this permission notice appear
in all copies.
```

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:00ff9d,100:0d1117&height=120&section=footer&animation=fadeIn" width="100%"/>

```
[ ICS-HONEYPOT-MITRE ] — Built with ⚡ for defenders, by defenders
```

**⭐ Star this repo if it helps your research. Every star helps the project grow.**

[![Star History Chart](https://img.shields.io/github/stars/srivarshini-karthikeyan/ics-honeypot-mitre?style=social)](https://github.com/srivarshini-karthikeyan/ics-honeypot-mitre)

</div>
