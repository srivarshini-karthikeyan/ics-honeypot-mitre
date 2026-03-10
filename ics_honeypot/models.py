from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MitreTag(BaseModel):
    tactic: str
    technique_id: str
    technique: str
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str | None = None


class Event(BaseModel):
    ts: datetime = Field(default_factory=utc_now)
    service: str
    action: str
    src_ip: str
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    session_id: str | None = None
    protocol: str | None = None
    severity: Literal["low", "medium", "high"] = "low"
    data: dict[str, Any] = Field(default_factory=dict)
    mitre: list[MitreTag] = Field(default_factory=list)
    enrichments: dict[str, Any] = Field(default_factory=dict)
    anomaly_score: float | None = None

