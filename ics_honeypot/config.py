from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Settings:
    raw: dict[str, Any]
    base_dir: Path

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def path(self, dotted: str, default: str | None = None) -> Path:
        val = self.get(dotted, default)
        if val is None:
            raise KeyError(f"Missing config key: {dotted}")
        p = Path(val)
        if not p.is_absolute():
            p = (self.base_dir / p).resolve()
        return p


def load_settings(config_path: str | Path | None = None) -> Settings:
    base_dir = Path(__file__).resolve().parents[1]
    config_path = Path(config_path) if config_path else (base_dir / "config" / "default.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return Settings(raw=raw, base_dir=base_dir)

