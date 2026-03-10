from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from ics_honeypot.models import Event


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  service TEXT NOT NULL,
  action TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER,
  dest_ip TEXT,
  dest_port INTEGER,
  session_id TEXT,
  protocol TEXT,
  severity TEXT NOT NULL,
  mitre_json TEXT NOT NULL,
  enrichments_json TEXT NOT NULL,
  anomaly_score REAL,
  data_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
"""


class SqliteStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._connect() as con:
            con.executescript(SCHEMA)

    def insert(self, event: Event) -> int:
        row = event.model_dump(mode="json")
        with self._connect() as con:
            cur = con.execute(
                """
                INSERT INTO events(
                  ts, service, action, src_ip, src_port, dest_ip, dest_port,
                  session_id, protocol, severity, mitre_json, enrichments_json,
                  anomaly_score, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["ts"],
                    row["service"],
                    row["action"],
                    row["src_ip"],
                    row.get("src_port"),
                    row.get("dest_ip"),
                    row.get("dest_port"),
                    row.get("session_id"),
                    row.get("protocol"),
                    row["severity"],
                    json.dumps(row.get("mitre", []), ensure_ascii=False),
                    json.dumps(row.get("enrichments", {}), ensure_ascii=False),
                    row.get("anomaly_score"),
                    json.dumps(row.get("data", {}), ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid)

    def query_recent(self, limit: int = 200) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def query_by_src_ip(self, src_ip: str, limit: int = 200) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM events WHERE src_ip=? ORDER BY id DESC LIMIT ?",
                (src_ip, int(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

