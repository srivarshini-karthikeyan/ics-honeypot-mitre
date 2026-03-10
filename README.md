
<div align="center">

```
                           ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ███████╗
                           ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝
                           ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝███████╗
                           ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗╚════██║
                           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║███████║
                           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
```

</div>

<div align="center">

<img src="https://img.shields.io/badge/THREAT_LEVEL-CRITICAL-cc0000?style=for-the-badge&labelColor=1a0000&color=cc0000"/>
&nbsp;
<img src="https://img.shields.io/badge/MITRE_ATT%26CK-ICS_MATRIX-8b0000?style=for-the-badge&labelColor=1a0000&color=8b0000"/>
&nbsp;
<img src="https://img.shields.io/badge/STATUS-HUNTING-ff2020?style=for-the-badge&labelColor=1a0000&color=ff2020"/>

<br/><br/>

<img src="https://img.shields.io/badge/Python-3.8+-3d0000?style=for-the-badge&logo=python&logoColor=ff2020&labelColor=1a0000"/>
&nbsp;
<img src="https://img.shields.io/badge/Modbus-TCP-3d0000?style=for-the-badge&labelColor=1a0000&color=3d0000&logoColor=ff2020"/>
&nbsp;
<img src="https://img.shields.io/badge/DNP3-Emulated-3d0000?style=for-the-badge&labelColor=1a0000&color=3d0000"/>
&nbsp;
<img src="https://img.shields.io/badge/S7comm-Active-3d0000?style=for-the-badge&labelColor=1a0000&color=3d0000"/>
&nbsp;
<img src="https://img.shields.io/badge/License-MIT-3d0000?style=for-the-badge&labelColor=1a0000&color=3d0000"/>

</div>

<br/>

<div align="center">

```
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
▓                                                                          ▓
▓   [ ADVERSARY DETECTED ]   185.220.xxx.xxx  →  MODBUS:502                ▓
▓   [ TTP CLASSIFIED    ]   T0846 · Remote System Discovery                ▓
▓   [ MITRE MAPPED      ]   Tactic: DISCOVERY  ·  Confidence: 97%          ▓
▓   [ ALERT DISPATCHED  ]   SOC notified  ·  IOC logged  ·  Session saved  ▓
▓                                                                          ▓
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
```

</div>

---

<div align="center">

## `[ 001 ]` — WHAT THIS IS

</div>

Nation-state actors. Ransomware crews. Industrial saboteurs. They all want the same thing — your **PLCs, your HMIs, your SCADA systems**. Critical infrastructure is the most dangerous battlefield in modern cyber warfare, and most defenders are flying blind.

**ICS Honeypot MITRE** changes that.

It deploys a convincing fake industrial environment — complete Modbus registers, DNP3 outstations, S7 CPU racks — and waits. When attackers probe, enumerate, or attempt to manipulate the decoy devices, every packet is captured, decoded, and automatically classified against the **MITRE ATT&CK for ICS** framework. You don't just see *that* you were attacked. You see *how*, *by whom*, and *what they were trying to do*.

> *"The best trap is one the enemy doesn't know is a trap."*

---

<div align="center">

## `[ 002 ]` — THE KILL CHAIN VIEW

</div>

```
                              ░ THREAT ACTORS ░
          ┌───────────────────────┬──────────────────────┐
          │                       │                      │
    [ APT / Nation State ]  [ Ransomware Crew ]  [ Opportunist Bot ]
          │                       │                      │
          └───────────────────────┴──────────────────────┘
                                  │
                                  │  ← they see a real ICS target
                                  ▼
          ╔═══════════════════════════════════════════════╗
          ║   D E C O Y   I N F R A S T R U C T U R E     ║
          ║                                               ║
          ║   ┌─────────────┐   ┌─────────────────────┐   ║
          ║   │  FAKE  PLC  │   │      FAKE  HMI      │   ║
          ║   │  Modbus:502 │   │  EtherNet/IP:44818  │   ║
          ║   └──────┬──────┘   └──────────┬──────────┘   ║
          ║          │                     │              ║
          ║   ┌──────▼─────────────────────▼──────────┐   ║
          ║   │        PAYLOAD  INSPECTOR             │   ║
          ║   │  decode · fingerprint · enrich · log  │   ║
          ║   └──────────────────┬────────────────────┘   ║
          ╚═══════════════════════╪═══════════════════════╝
                                  │
                          ┌───────▼────────┐
                          │  MITRE MAPPER  │
                          │                │
                          │  T0846 ██████  │
                          │  T0801 █████   │
                          │  T0855 ██      │
                          └───────┬────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   THREAT INTEL OUTPUT     │
                    │  JSON · CSV · Navigator   │
                    │  STIX · Alerts · IOCs     │
                    └───────────────────────────┘
```

---

<div align="center">

## `[ 003 ]` — PROTOCOL ARSENAL

</div>

<table>
<tr>
<td align="center" width="25%">

### ⬛ MODBUS TCP
**Port 502**

The most-attacked ICS protocol on the planet. Register reads, coil writes, function code abuse — all emulated and logged.

`Schneider · GE · Festo`

</td>
<td align="center" width="25%">

### ⬛ DNP3
**Port 20000**

Dominates power generation, water treatment, and oil & gas. Station address spoofing, unsolicited response traps.

`GE · SEL · ABB`

</td>
<td align="center" width="25%">

### ⬛ EtherNet/IP
**Port 44818**

Allen-Bradley's CIP-based protocol. Common in automotive and discrete manufacturing. Full CIP object emulation.

`Rockwell · Allen-Bradley`

</td>
<td align="center" width="25%">

### ⬛ S7comm
**Port 102**

Siemens S7 CPU family. Targeted in Stuxnet. High-value decoy for nation-state threat hunters.

`Siemens S7-300/400/1200`

</td>
</tr>
</table>

---

<div align="center">

## `[ 004 ]` — MITRE ATT&CK FOR ICS COVERAGE

</div>

```
TACTIC              │ ID     │ TECHNIQUE                         │ SIGNAL SOURCE
────────────────────┼────────┼───────────────────────────────────┼──────────────────────
RECONNAISSANCE      │ T0846  │ Remote System Discovery           │ Port scan / banner grab
RECONNAISSANCE      │ T0888  │ Remote System Info Discovery      │ Protocol enumeration
────────────────────┼────────┼───────────────────────────────────┼──────────────────────
COLLECTION          │ T0801  │ Monitor Process State             │ Bulk register reads
COLLECTION          │ T0802  │ Automated Collection              │ Sequential coil polling
────────────────────┼────────┼───────────────────────────────────┼──────────────────────
EXECUTION           │ T0858  │ Change Operating Mode             │ Mode switch commands
EXECUTION           │ T0807  │ Command-Line Interface            │ Raw socket crafting
────────────────────┼────────┼───────────────────────────────────┼──────────────────────
INHIBIT RESPONSE    │ T0816  │ Device Restart / Shutdown         │ Stop coil writes
INHIBIT RESPONSE    │ T0855  │ Unauthorized Command Message      │ Rogue write attempts
────────────────────┼────────┼───────────────────────────────────┼──────────────────────
LATERAL MOVEMENT    │ T0812  │ Default Credentials               │ Auth brute force
────────────────────┼────────┼───────────────────────────────────┼──────────────────────
IMPACT              │ T0826  │ Loss of Availability              │ Flood / DoS patterns
IMPACT              │ T0831  │ Manipulation of Control           │ Set point tampering
```

---

<div align="center">

## `[ 005 ]` — DEPLOY IN 3 COMMANDS

</div>

```bash
# Clone
git clone https://github.com/srivarshini-karthikeyan/ics-honeypot-mitre.git && cd ics-honeypot-mitre

# Install
pip install -r requirements.txt

# Hunt
python honeypot.py --config config.yaml --verbose
```

**Protocol-specific deployment:**

```bash
# Modbus + DNP3 only (power sector profile)
python honeypot.py --protocols modbus,dnp3

# Full stack with aggressive logging
python honeypot.py --all-protocols --log-level DEBUG --alert-webhook https://your-siem/ingest

# Generate MITRE Navigator layer from captured sessions
python mitre_mapper.py --input logs/attacks.json --output navigator_layer.json
```

---

<div align="center">

## `[ 006 ]` — REPO ANATOMY

</div>

```
ics-honeypot-mitre/
│
├── honeypot/
│   ├── protocols/
│   │   ├── modbus_emulator.py       ← Modbus TCP server  [Port 502]
│   │   ├── dnp3_emulator.py         ← DNP3 outstation    [Port 20000]
│   │   ├── enip_emulator.py         ← EtherNet/IP        [Port 44818]
│   │   └── s7comm_emulator.py       ← Siemens S7 CPU     [Port 102]
│   └── core/
│       ├── session_handler.py       ← Connection lifecycle
│       └── payload_inspector.py     ← Deep packet decode
│
├── mitre/
│   ├── mapper.py                    ← TTP classification engine
│   ├── ics_techniques.json          ← ATT&CK ICS technique database
│   └── navigator_exporter.py        ← Navigator .json layer generator
│
├── reporting/
│   ├── report_generator.py          ← JSON / CSV / STIX output
│   ├── ioc_extractor.py             ← IOC harvest + dedup
│   └── templates/
│
├── logs/                            ← Live attack telemetry
├── config.yaml                      ← Master configuration
├── requirements.txt
└── honeypot.py                      ← Entry point
```

---

<div align="center">

## `[ 007 ]` — LIVE ATTACK LOG (SAMPLE)

</div>

<details>
<summary><b>▶ EXPAND — Real-world style capture · Modbus bulk read</b></summary>

```json
{
  "timestamp": "2025-03-10T02:17:44Z",
  "session_id": "sess_c91f3ba2",
  "source": {
    "ip": "185.220.xxx.xxx",
    "port": 49812,
    "asn": "AS206936",
    "geo": "Tor Exit Node",
    "threat_feeds": ["blocklist.de", "emergingthreats"]
  },
  "honeypot": {
    "protocol": "modbus",
    "port": 502,
    "emulated_device": "Schneider Electric Modicon M340 PLC"
  },
  "packet": {
    "function_code": 3,
    "description": "Read Holding Registers",
    "register_start": 0,
    "register_count": 125,
    "raw": "00010000000601030000007D"
  },
  "mitre": {
    "tactic": "Collection",
    "tactic_id": "TA0100",
    "technique": "Monitor Process State",
    "technique_id": "T0801",
    "confidence": 0.96,
    "evidence": "Full address space sweep — automated ICS scanner signature"
  },
  "threat_score": 78,
  "tags": ["bulk-register-sweep", "automated-scanner", "tor-exit", "ics-recon"]
}
```

</details>

<details>
<summary><b>▶ EXPAND — Rogue write attempt · Unauthorized command (T0855)</b></summary>

```json
{
  "timestamp": "2025-03-10T03:44:11Z",
  "session_id": "sess_d44a01cc",
  "source": {
    "ip": "91.108.xxx.xxx",
    "port": 51902,
    "asn": "AS44050",
    "geo": "RU"
  },
  "honeypot": {
    "protocol": "modbus",
    "port": 502,
    "emulated_device": "Schneider Electric Modicon M340 PLC"
  },
  "packet": {
    "function_code": 6,
    "description": "Write Single Register",
    "register_address": 40001,
    "value_written": 9999,
    "raw": "0002000000060106000127F"
  },
  "mitre": {
    "tactic": "Inhibit Response Function",
    "tactic_id": "TA0107",
    "technique": "Unauthorized Command Message",
    "technique_id": "T0855",
    "confidence": 0.99,
    "evidence": "Write to process setpoint register without prior read enumeration"
  },
  "threat_score": 95,
  "tags": ["unauthorized-write", "setpoint-tamper", "high-severity", "nation-state-ioc"]
}
```

</details>

---

<div align="center">

## `[ 008 ]` — CONFIGURATION

</div>

```yaml
# config.yaml

honeypot:
  identity: "ICS-HONEYPOT-GRID-01"
  location: "DMZ-SEGMENT-4"

  protocols:
    modbus:   { enabled: true,  port: 502,   profile: "schneider-m340" }
    dnp3:     { enabled: true,  port: 20000, station_address: 10 }
    enip:     { enabled: true,  port: 44818, device_type: "PLC" }
    s7comm:   { enabled: false, port: 102  }

logging:
  format: json
  output: logs/attacks.json
  rotate: daily

mitre:
  auto_map: true
  confidence_threshold: 0.75
  navigator_export: true

alerts:
  - type: webhook
    url: "https://your-siem.example.com/ingest"
  - type: email
    recipients: ["soc@yourorg.com"]
```

---

<div align="center">

## `[ 009 ]` — WHO SHOULD USE THIS

</div>

| Profile | Why It Matters |
|---|---|
| **Threat Intelligence Analysts** | Capture in-the-wild ICS TTPs against real protocol decoys |
| **SOC / Blue Team** | Enrich detections with structured MITRE-tagged IOCs |
| **Red Team Operators** | Understand how ICS defenders detect your moves |
| **Security Researchers** | Build ground-truth datasets for OT security ML |
| **Compliance Teams** | Evidence active monitoring for NERC CIP / IEC 62443 |
| **Academic Institutions** | Reproducible ICS threat research platform |

---

<div align="center">

## `[ 010 ]` — LEGAL NOTICE

</div>

> This tool exists for **authorized defensive research only**.

Deploy exclusively on infrastructure you own or have written permission to monitor. Never use in live production OT environments without full network isolation. The author accepts no liability for misuse. Captured attacker data must not be weaponized for offensive retaliation.

---

<div align="center">

## `[ 011 ]` — CONTRIBUTING

</div>

```bash
git checkout -b feature/your-feature-name
git commit -m "feat: describe your addition"
git push origin feature/your-feature-name
# → open a Pull Request
```

**High-priority contributions:**
- IEC 60870-5-104, BACnet, Profinet protocol emulators
- Improved TTP heuristics and confidence scoring
- Web-based attack dashboard
- STIX 2.1 bundle export

---

<div align="center">

## `[ 012 ]` — REFERENCES

</div>

| Resource | Link |
|---|---|
| MITRE ATT&CK for ICS | [attack.mitre.org/matrices/ics](https://attack.mitre.org/matrices/ics/) |
| ICS-CERT Advisories | [cisa.gov/ics-cert](https://www.cisa.gov/ics-cert) |
| IEC 62443 Standard | [iec.ch/cyber-security](https://www.iec.ch/cyber-security) |
| ATT&CK Navigator | [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) |
| SANS ICS Security | [sans.org/ics](https://www.sans.org/industrial-control-systems-security/) |

---

<div align="center">

<br/>

```
╔──────────────────────────────────────────────────────────────────────╗
│                                                                      │
│          built by  SRIVARSHINI KARTHIKEYAN                           │
│          ICS Security Researcher  ·  Cyber Defense  ·  MITRE         │
│                                                                      │
│          github.com/srivarshini-karthikeyan                          │
│                                                                      │
╚──────────────────────────────────────────────────────────────────────╝
```

<img src="https://img.shields.io/github/stars/srivarshini-karthikeyan/ics-honeypot-mitre?style=for-the-badge&logo=github&labelColor=1a0000&color=8b0000&logoColor=ff2020"/>
&nbsp;
<img src="https://img.shields.io/github/forks/srivarshini-karthikeyan/ics-honeypot-mitre?style=for-the-badge&logo=github&labelColor=1a0000&color=8b0000&logoColor=ff2020"/>
&nbsp;
<img src="https://img.shields.io/github/issues/srivarshini-karthikeyan/ics-honeypot-mitre?style=for-the-badge&logo=github&labelColor=1a0000&color=8b0000&logoColor=ff2020"/>

<br/><br/>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0000,50:1a0000,100:0d0000&height=140&section=footer&text=STAY%20IN%20THE%20SHADOWS.%20LET%20THEM%20COME%20TO%20YOU.&fontSize=16&fontColor=cc0000&fontAlignY=55&animation=fadeIn" width="100%"/>

</div>
