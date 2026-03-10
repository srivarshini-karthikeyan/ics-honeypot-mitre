from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from ics_honeypot.models import Event


Subscriber = Callable[[Event], Awaitable[None]]


class EventBus:
    """
    Simple async pub-sub so the API/dashboard can stream events without
    coupling to protocol emulators.
    """

    def __init__(self):
        self._subs: set[Subscriber] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self, fn: Subscriber) -> None:
        async with self._lock:
            self._subs.add(fn)

    async def unsubscribe(self, fn: Subscriber) -> None:
        async with self._lock:
            self._subs.discard(fn)

    async def publish(self, event: Event) -> None:
        async with self._lock:
            subs = list(self._subs)
        # Fan-out without failing the publisher if one subscriber errors.
        for fn in subs:
            asyncio.create_task(fn(event))

