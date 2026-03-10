from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class OfflineIntel:
    ip_nets: tuple[ipaddress._BaseNetwork, ...]
    domains: tuple[str, ...]

    @classmethod
    def from_file(cls, path: Path) -> "OfflineIntel":
        if not path.exists():
            return cls(ip_nets=(), domains=())
        ip_nets = []
        domains = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # domain
            if any(c.isalpha() for c in line) and "/" not in line and ":" not in line and line.count(".") >= 1:
                domains.append(line.lower())
                continue
            # ip / cidr
            try:
                if "/" in line:
                    ip_nets.append(ipaddress.ip_network(line, strict=False))
                else:
                    ip_nets.append(ipaddress.ip_network(line + "/32", strict=False))
            except Exception:
                continue
        return cls(ip_nets=tuple(ip_nets), domains=tuple(domains))

    def match_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        return any(addr in n for n in self.ip_nets)

