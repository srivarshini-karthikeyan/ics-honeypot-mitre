from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ics_honeypot.models import Event, MitreTag


@dataclass(frozen=True)
class Rule:
    id: str
    when: dict[str, Any]
    mitre: dict[str, Any]
    confidence: float

    def matches(self, event: Event) -> bool:
        for k, v in self.when.items():
            if getattr(event, k, None) != v:
                return False
        return True

    def tag(self) -> MitreTag:
        return MitreTag(
            tactic=str(self.mitre.get("tactic", "")),
            technique_id=str(self.mitre.get("technique_id", "")),
            technique=str(self.mitre.get("technique", "")),
            confidence=float(self.confidence),
            rule_id=self.id,
        )


class MitreMapper:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def from_yaml(cls, path: Path) -> "MitreMapper":
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        rules: list[Rule] = []
        for r in raw.get("rules", []):
            rules.append(
                Rule(
                    id=r["id"],
                    when=r.get("when", {}),
                    mitre=r.get("mitre", {}),
                    confidence=float(r.get("confidence", 0.5)),
                )
            )
        return cls(rules)

    def apply(self, event: Event) -> Event:
        tags: list[MitreTag] = list(event.mitre)
        for rule in self.rules:
            if rule.matches(event):
                tags.append(rule.tag())
        return event.model_copy(update={"mitre": tags})

