# ICS Honeypot with MITRE ATT&CK (ICS) Mapping

This project is a **local, research-focused ICS honeypot** that emulates industrial services (starting with **Modbus/TCP**) and maps observed attacker actions to **MITRE ATT&CK for ICS** techniques.

## What you get (MVP)

- **Modbus/TCP listener** that behaves like a simple PLC (registers/coils + realistic responses)
- **Structured event logging** (JSONL) + **SQLite** storage
- **Automatic MITRE ATT&CK for ICS technique tagging** via mapping rules
- **Live dashboard** (basic) + API endpoints for querying events
- Hooks for **threat-intel enrichment** + **anomaly scoring** (optional/off by default)

## Quick start (Windows PowerShell)

From the repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m ics_honeypot.app
```

### Services

- **API + dashboard**: `http://127.0.0.1:8000`
- **Modbus/TCP honeypot**: `0.0.0.0:5020` (non-privileged port by default)

> Note: Port 502 usually requires admin privileges on Windows. Use `5020` unless you intentionally run elevated.

## Try it (quick attacker simulation)

If you have a Modbus client, try reading/writing:

- Read Holding Registers: address 0..49
- Write Single Register: address 0..49
- Write Multiple Registers: address 0..49

Each interaction is logged and mapped (e.g., writes map to **Manipulation of Control**).

## Configuration

See `config/default.yaml`.

## Project layout

- `ics_honeypot/`
  - `app.py` – FastAPI app + dashboard + startup of honeypot services
  - `honeypots/modbus.py` – Modbus/TCP PLC emulator + logging
  - `mitre/mapping.py` – MITRE technique mapping rules engine
  - `storage/` – SQLite + JSONL event sinks
  - `intel/` – threat intel enrichment hooks (optional)
  - `ml/` – anomaly detection stub (optional)

## Safety / Legal

Run this **only in a controlled environment** you own (lab VLAN, VM, or isolated network). Do not deploy to the public internet without clear authorization, egress controls, and monitoring.

