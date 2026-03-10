from __future__ import annotations

from pathlib import Path

import orjson

from ics_honeypot.models import Event


class JsonlSink:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: Event) -> None:
        b = orjson.dumps(event.model_dump(mode="json"))
        with open(self.path, "ab") as f:
            f.write(b + b"\n")

