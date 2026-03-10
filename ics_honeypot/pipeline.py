from __future__ import annotations

from ics_honeypot.mitre.mapping import MitreMapper
from ics_honeypot.models import Event
from ics_honeypot.intel.offline import OfflineIntel
from ics_honeypot.storage.bus import EventBus
from ics_honeypot.storage.jsonl import JsonlSink
from ics_honeypot.storage.sqlite import SqliteStore


class EventPipeline:
    def __init__(
        self,
        *,
        mitre: MitreMapper,
        sqlite: SqliteStore,
        jsonl: JsonlSink,
        bus: EventBus,
        offline_intel: OfflineIntel | None = None,
    ):
        self._mitre = mitre
        self._sqlite = sqlite
        self._jsonl = jsonl
        self._bus = bus
        self._offline_intel = offline_intel

    async def handle(self, event: Event) -> None:
        if self._offline_intel and self._offline_intel.match_ip(event.src_ip):
            enrich = dict(event.enrichments)
            enrich["intel.offline"] = {"denylisted": True}
            event = event.model_copy(update={"enrichments": enrich, "severity": "medium"})
        event = self._mitre.apply(event)
        self._sqlite.insert(event)
        self._jsonl.write(event)
        await self._bus.publish(event)

