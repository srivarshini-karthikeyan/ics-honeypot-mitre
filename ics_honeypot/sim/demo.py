from __future__ import annotations

import asyncio
import random
from ipaddress import IPv4Address
from typing import Iterable

from ics_honeypot.models import Event
from ics_honeypot.pipeline import EventPipeline


def _rand_ip() -> str:
    # Simple pseudo-random "Internet" IP, avoiding obvious private ranges.
    first = random.choice([5, 31, 37, 45, 62, 77, 88, 91, 94, 101, 146, 178, 185])
    rest = [random.randint(0, 255) for _ in range(3)]
    return str(IPv4Address(f"{first}.{rest[0]}.{rest[1]}.{rest[2]}"))


async def generate_sequence(pipeline: EventPipeline, *, src_ip: str | None = None) -> None:
    """
    Emit a small kill-chain-like sequence of events for one attacker.

    This is NOT real traffic, but is designed to look realistic enough for demos:
      - connect / basic scan
      - Modbus reads (discovery)
      - Modbus writes (manipulation of control)
    """
    ip = src_ip or _rand_ip()
    base_port = random.randint(20000, 60000)

    # 1) Connect
    await pipeline.handle(
        Event(
            service="modbus",
            action="connect",
            protocol="modbus/tcp",
            src_ip=ip,
            src_port=base_port,
            dest_ip="127.0.0.1",
            dest_port=5020,
            severity="low",
            data={"sim": True},
        )
    )
    await asyncio.sleep(random.uniform(0.2, 0.8))

    # 2) Discovery reads
    for addr, qty in [(0, 10), (10, 10), (0, 16)]:
        await pipeline.handle(
            Event(
                service="modbus",
                action="modbus.read_holding_registers" if addr < 20 else "modbus.read_coils",
                protocol="modbus/tcp",
                src_ip=ip,
                src_port=base_port,
                dest_ip="127.0.0.1",
                dest_port=5020,
                severity="low",
                data={"addr": addr, "qty": qty, "sim": True},
            )
        )
        await asyncio.sleep(random.uniform(0.3, 1.0))

    # 3) Manipulation of control – write to tank level or valve coil
    # These will map to T0831 via the rules.
    await pipeline.handle(
        Event(
            service="modbus",
            action="modbus.write_single_register",
            protocol="modbus/tcp",
            src_ip=ip,
            src_port=base_port,
            dest_ip="127.0.0.1",
            dest_port=5020,
            severity="high",
            data={"addr": 0, "value": random.randint(800, 1000), "sim": True},
        )
    )
    await asyncio.sleep(random.uniform(0.3, 0.8))
    await pipeline.handle(
        Event(
            service="modbus",
            action="modbus.write_single_coil",
            protocol="modbus/tcp",
            src_ip=ip,
            src_port=base_port,
            dest_ip="127.0.0.1",
            dest_port=5020,
            severity="high",
            data={"addr": 0, "value": 1, "sim": True},
        )
    )


async def run_demo_loop(pipeline: EventPipeline, *, min_interval: float, max_interval: float) -> None:
    """
    Background task: continuously sprinkle simulated attacks so the dashboard
    and CLI have live-looking data even when no one is attacking the honeypot.
    """
    while True:
        try:
            await generate_sequence(pipeline)
        except Exception:
            # Never kill the loop; just wait a bit and continue.
            await asyncio.sleep(1.0)
        await asyncio.sleep(random.uniform(min_interval, max_interval))

