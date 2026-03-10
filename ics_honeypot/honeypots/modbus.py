from __future__ import annotations

import asyncio
import struct
import uuid
from dataclasses import dataclass
from typing import Optional

from ics_honeypot.models import Event
from ics_honeypot.pipeline import EventPipeline


# Modbus exception codes (subset)
ILLEGAL_FUNCTION = 0x01
ILLEGAL_DATA_ADDRESS = 0x02
ILLEGAL_DATA_VALUE = 0x03


def _clamp_u16(v: int) -> int:
    return max(0, min(0xFFFF, int(v)))


@dataclass
class PlcState:
    coils: list[int]
    discretes: list[int]
    holding: list[int]
    input_regs: list[int]
    water_tank_level_register: int = 0
    valve_open_coil: int = 0

    def __post_init__(self) -> None:
        self.coils = [1 if x else 0 for x in self.coils]
        self.discretes = [1 if x else 0 for x in self.discretes]
        self.holding = [_clamp_u16(x) for x in self.holding]
        self.input_regs = [_clamp_u16(x) for x in self.input_regs]


class ModbusTcpHoneypot:
    """
    Minimal Modbus/TCP emulator (asyncio) that logs each request with client IP.

    Supported function codes:
      0x01 Read Coils
      0x03 Read Holding Registers
      0x05 Write Single Coil
      0x06 Write Single Register
      0x0F Write Multiple Coils
      0x10 Write Multiple Registers
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        unit_id: int,
        state: PlcState,
        pipeline: EventPipeline,
    ):
        self.host = host
        self.port = int(port)
        self.unit_id = int(unit_id) & 0xFF
        self.state = state
        self.pipeline = pipeline
        self._server: Optional[asyncio.AbstractServer] = None
        self._plant_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self._plant_task = asyncio.create_task(self._plant_sim_loop())

    async def stop(self) -> None:
        if self._plant_task:
            self._plant_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _plant_sim_loop(self) -> None:
        """
        Tiny "digital twin": a water tank level increases when valve coil is open,
        decreases when closed. Level is stored in holding register (0..1000).
        """
        level_addr = self.state.water_tank_level_register
        valve_addr = self.state.valve_open_coil
        while True:
            await asyncio.sleep(1.0)
            try:
                level = int(self.state.holding[level_addr])
                valve_open = int(self.state.coils[valve_addr]) == 1
                if valve_open:
                    level = min(1000, level + 5)
                else:
                    level = max(0, level - 2)
                self.state.holding[level_addr] = _clamp_u16(level)
                # mirror to input register 0 for "sensor"
                if self.state.input_regs:
                    self.state.input_regs[0] = _clamp_u16(level)
            except Exception:
                # Keep the plant sim resilient; honeypot continues regardless.
                continue

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sock = writer.get_extra_info("sockname")
        src_ip, src_port = (peer[0], int(peer[1])) if peer else ("unknown", None)
        dest_ip, dest_port = (sock[0], int(sock[1])) if sock else (None, None)
        session_id = str(uuid.uuid4())

        await self.pipeline.handle(
            Event(
                service="modbus",
                action="connect",
                protocol="modbus/tcp",
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                session_id=session_id,
                severity="low",
                data={},
            )
        )

        try:
            while not reader.at_eof():
                # MBAP header: transaction(2) protocol(2) length(2) unit(1)
                hdr = await reader.readexactly(7)
                tid, pid, length, uid = struct.unpack(">HHHB", hdr)
                if pid != 0 or length < 2:
                    # invalid; drop
                    break
                pdu = await reader.readexactly(length - 1)
                fc = pdu[0]

                resp_pdu, log_action, log_data, severity = self._process_pdu(fc, pdu[1:])

                await self.pipeline.handle(
                    Event(
                        service="modbus",
                        action=log_action,
                        protocol="modbus/tcp",
                        src_ip=src_ip,
                        src_port=src_port,
                        dest_ip=dest_ip,
                        dest_port=dest_port,
                        session_id=session_id,
                        severity=severity,
                        data={"tid": tid, "unit_id": uid, **log_data},
                    )
                )

                out = struct.pack(">HHHB", tid, 0, len(resp_pdu) + 1, uid) + resp_pdu
                writer.write(out)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            await self.pipeline.handle(
                Event(
                    service="modbus",
                    action="error",
                    protocol="modbus/tcp",
                    src_ip=src_ip,
                    src_port=src_port,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    session_id=session_id,
                    severity="medium",
                    data={"error": repr(e)},
                )
            )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await self.pipeline.handle(
                Event(
                    service="modbus",
                    action="disconnect",
                    protocol="modbus/tcp",
                    src_ip=src_ip,
                    src_port=src_port,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    session_id=session_id,
                    severity="low",
                    data={},
                )
            )

    def _exc(self, fc: int, code: int) -> bytes:
        return bytes([fc | 0x80, code])

    def _process_pdu(self, fc: int, data: bytes) -> tuple[bytes, str, dict, str]:
        # Returns: resp_pdu, action, log_data, severity
        try:
            if fc == 0x03:  # Read Holding Registers
                addr, qty = struct.unpack(">HH", data[:4])
                if qty < 1 or qty > 125:
                    return self._exc(fc, ILLEGAL_DATA_VALUE), "modbus.read_holding_registers", {"addr": addr, "qty": qty}, "medium"
                if addr + qty > len(self.state.holding):
                    return self._exc(fc, ILLEGAL_DATA_ADDRESS), "modbus.read_holding_registers", {"addr": addr, "qty": qty}, "medium"
                regs = self.state.holding[addr : addr + qty]
                payload = struct.pack("B", qty * 2) + b"".join(struct.pack(">H", r) for r in regs)
                return bytes([fc]) + payload, "modbus.read_holding_registers", {"addr": addr, "qty": qty}, "low"

            if fc == 0x01:  # Read Coils
                addr, qty = struct.unpack(">HH", data[:4])
                if qty < 1 or qty > 2000:
                    return self._exc(fc, ILLEGAL_DATA_VALUE), "modbus.read_coils", {"addr": addr, "qty": qty}, "medium"
                if addr + qty > len(self.state.coils):
                    return self._exc(fc, ILLEGAL_DATA_ADDRESS), "modbus.read_coils", {"addr": addr, "qty": qty}, "medium"
                bits = self.state.coils[addr : addr + qty]
                # pack bits LSB-first
                out_bytes = bytearray()
                b = 0
                bit_i = 0
                for v in bits:
                    if v:
                        b |= (1 << bit_i)
                    bit_i += 1
                    if bit_i == 8:
                        out_bytes.append(b)
                        b = 0
                        bit_i = 0
                if bit_i:
                    out_bytes.append(b)
                payload = struct.pack("B", len(out_bytes)) + bytes(out_bytes)
                return bytes([fc]) + payload, "modbus.read_coils", {"addr": addr, "qty": qty}, "low"

            if fc == 0x06:  # Write Single Register
                addr, value = struct.unpack(">HH", data[:4])
                if addr >= len(self.state.holding):
                    return self._exc(fc, ILLEGAL_DATA_ADDRESS), "modbus.write_single_register", {"addr": addr, "value": value}, "high"
                self.state.holding[addr] = _clamp_u16(value)
                return bytes([fc]) + struct.pack(">HH", addr, value), "modbus.write_single_register", {"addr": addr, "value": value}, "high"

            if fc == 0x10:  # Write Multiple Registers
                addr, qty, byte_count = struct.unpack(">HHB", data[:5])
                if qty < 1 or qty > 123 or byte_count != qty * 2:
                    return self._exc(fc, ILLEGAL_DATA_VALUE), "modbus.write_multiple_registers", {"addr": addr, "qty": qty}, "high"
                if addr + qty > len(self.state.holding):
                    return self._exc(fc, ILLEGAL_DATA_ADDRESS), "modbus.write_multiple_registers", {"addr": addr, "qty": qty}, "high"
                values = list(struct.unpack(">" + "H" * qty, data[5 : 5 + byte_count]))
                for i, v in enumerate(values):
                    self.state.holding[addr + i] = _clamp_u16(v)
                return bytes([fc]) + struct.pack(">HH", addr, qty), "modbus.write_multiple_registers", {"addr": addr, "qty": qty, "values": values[:10]}, "high"

            if fc == 0x05:  # Write Single Coil
                addr, raw = struct.unpack(">HH", data[:4])
                if addr >= len(self.state.coils):
                    return self._exc(fc, ILLEGAL_DATA_ADDRESS), "modbus.write_single_coil", {"addr": addr, "value": raw}, "high"
                if raw == 0xFF00:
                    self.state.coils[addr] = 1
                elif raw == 0x0000:
                    self.state.coils[addr] = 0
                else:
                    return self._exc(fc, ILLEGAL_DATA_VALUE), "modbus.write_single_coil", {"addr": addr, "value": raw}, "high"
                return bytes([fc]) + struct.pack(">HH", addr, raw), "modbus.write_single_coil", {"addr": addr, "value": self.state.coils[addr]}, "high"

            if fc == 0x0F:  # Write Multiple Coils
                addr, qty, byte_count = struct.unpack(">HHB", data[:5])
                if qty < 1 or qty > 1968:
                    return self._exc(fc, ILLEGAL_DATA_VALUE), "modbus.write_multiple_coils", {"addr": addr, "qty": qty}, "high"
                if addr + qty > len(self.state.coils):
                    return self._exc(fc, ILLEGAL_DATA_ADDRESS), "modbus.write_multiple_coils", {"addr": addr, "qty": qty}, "high"
                payload = data[5 : 5 + byte_count]
                bits: list[int] = []
                for b in payload:
                    for i in range(8):
                        bits.append(1 if (b >> i) & 1 else 0)
                bits = bits[:qty]
                for i, v in enumerate(bits):
                    self.state.coils[addr + i] = 1 if v else 0
                return bytes([fc]) + struct.pack(">HH", addr, qty), "modbus.write_multiple_coils", {"addr": addr, "qty": qty, "values": bits[:16]}, "high"

            return self._exc(fc, ILLEGAL_FUNCTION), "modbus.unknown_function", {"fc": fc}, "medium"
        except Exception as e:
            return self._exc(fc, ILLEGAL_DATA_VALUE), "modbus.parse_error", {"fc": fc, "error": repr(e)}, "medium"

