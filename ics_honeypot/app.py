from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from ics_honeypot.config import load_settings
from ics_honeypot.honeypots.modbus import ModbusTcpHoneypot, PlcState
from ics_honeypot.intel.offline import OfflineIntel
from ics_honeypot.mitre.mapping import MitreMapper
from ics_honeypot.pipeline import EventPipeline
from ics_honeypot.sim.demo import run_demo_loop
from ics_honeypot.storage.bus import EventBus
from ics_honeypot.storage.jsonl import JsonlSink
from ics_honeypot.storage.sqlite import SqliteStore


TEMPLATES_DIR = Path(__file__).resolve().parent / "web" / "templates"
INDEX_HTML = (TEMPLATES_DIR / "index.html").resolve()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    mitre = MitreMapper.from_yaml(settings.path("mitre_mapping.rules_path"))
    bus = EventBus()
    sqlite = SqliteStore(settings.path("storage.sqlite_path"))
    jsonl = JsonlSink(settings.path("storage.jsonl_path"))

    offline_intel = None
    ti_cfg: dict[str, Any] = settings.get("threat_intel", {}) or {}
    if bool(ti_cfg.get("enabled", True)) and str(ti_cfg.get("mode", "offline")).lower() == "offline":
        offline_intel = OfflineIntel.from_file(settings.path("threat_intel.denylist_path"))

    pipeline = EventPipeline(mitre=mitre, sqlite=sqlite, jsonl=jsonl, bus=bus, offline_intel=offline_intel)

    app.state.settings = settings
    app.state.bus = bus
    app.state.sqlite = sqlite
    app.state.pipeline = pipeline

    # Also echo events to the CLI so you see everything in the terminal.
    async def _cli_echo(ev):
        tags = ", ".join({t.technique_id for t in ev.mitre if t.technique_id}) or "-"
        src = f"{ev.src_ip}:{ev.src_port}" if ev.src_port else ev.src_ip
        ts = ev.ts.isoformat().replace("+00:00", "Z")
        print(f"[{ts}] {ev.service} {ev.action} src={src} sev={ev.severity} mitre={tags}")

    await bus.subscribe(_cli_echo)

    # Start honeypots
    modbus_cfg: dict[str, Any] = settings.get("honeypots.modbus", {}) or {}
    honeypots: list[Any] = []
    if modbus_cfg.get("enabled", True):
        state = PlcState(
            coils=[0] * int(modbus_cfg.get("coils", 50)),
            discretes=[0] * int(modbus_cfg.get("discretes", 50)),
            holding=[0] * int(modbus_cfg.get("holding_registers", 50)),
            input_regs=[0] * int(modbus_cfg.get("input_registers", 50)),
            water_tank_level_register=int(modbus_cfg.get("plant", {}).get("water_tank_level_register", 0)),
            valve_open_coil=int(modbus_cfg.get("plant", {}).get("valve_open_coil", 0)),
        )
        hp = ModbusTcpHoneypot(
            host=str(modbus_cfg.get("host", "0.0.0.0")),
            port=int(modbus_cfg.get("port", 5020)),
            unit_id=int(modbus_cfg.get("unit_id", 1)),
            state=state,
            pipeline=pipeline,
        )
        await hp.start()
        honeypots.append(hp)

    app.state.honeypots = honeypots

    # Optional simulation: continuously generate demo attacks so the dashboard
    # looks alive even without real attackers on the network.
    sim_cfg: dict[str, Any] = settings.get("simulation", {}) or {}
    sim_task = None
    if bool(sim_cfg.get("enabled", False)):
        min_iv = float(sim_cfg.get("min_interval_s", 1.5))
        max_iv = float(sim_cfg.get("max_interval_s", 4.0))
        sim_task = asyncio.create_task(run_demo_loop(pipeline, min_interval=min_iv, max_interval=max_iv))
        app.state.sim_task = sim_task
    try:
        yield
    finally:
        try:
            await bus.unsubscribe(_cli_echo)
        except Exception:
            pass
        sim_task = getattr(app.state, "sim_task", None)
        if sim_task:
            sim_task.cancel()
            with suppress(Exception):
                await sim_task
        # stop honeypots
        for hp in honeypots:
            try:
                await hp.stop()
            except Exception:
                pass


app = FastAPI(title="ICS Honeypot", version="0.1.0", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML.read_text(encoding="utf-8"))


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.get("/api/events")
async def api_events(limit: int = 200):
    limit = max(1, min(2000, int(limit)))
    return {"events": app.state.sqlite.query_recent(limit=limit)}


@app.get("/api/events/by-ip/{src_ip}")
async def api_events_by_ip(src_ip: str, limit: int = 200):
    limit = max(1, min(2000, int(limit)))
    return {"events": app.state.sqlite.query_by_src_ip(src_ip=src_ip, limit=limit)}


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await ws.accept()
    q: asyncio.Queue[dict] = asyncio.Queue(maxsize=500)

    async def _sub(ev):
        try:
            q.put_nowait(ev.model_dump(mode="json"))
        except asyncio.QueueFull:
            # drop oldest by draining one
            try:
                _ = q.get_nowait()
            except Exception:
                pass
            try:
                q.put_nowait(ev.model_dump(mode="json"))
            except Exception:
                pass

    await app.state.bus.subscribe(_sub)
    try:
        while True:
            item = await q.get()
            await ws.send_json(item)
    except WebSocketDisconnect:
        pass
    finally:
        await app.state.bus.unsubscribe(_sub)


def main() -> None:
    settings = load_settings()
    host = str(settings.get("app.host", "127.0.0.1"))
    port = int(settings.get("app.port", 8000))
    log_level = str(settings.get("app.log_level", "info"))
    uvicorn.run("ics_honeypot.app:app", host=host, port=port, log_level=log_level, reload=False)


if __name__ == "__main__":
    main()

