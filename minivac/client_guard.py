"""Toy client-side file/plugin integrity checks for an owned test program.

Not a security guarantee: an attacker controlling the client can disable the
monitor or falsify all of its output. No OS kernel, process hooking, or VAC code.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from dataclasses import dataclass


def sha256_file(file_path: str | Path) -> str:
    return hashlib.sha256(Path(file_path).read_bytes()).hexdigest()


@dataclass
class ClientGuard:
    expected_asset_digest: str
    allowed_plugins: frozenset[str] = frozenset({"hud", "accessibility"})
    active: bool = True

    def inspect(self, asset: str | Path, loaded_plugins: list[str]) -> list[str]:
        if not self.active:
            return []  # illustrates the critical untrusted-monitor blind spot
        alerts: list[str] = []
        try:
            current = sha256_file(asset)
        except OSError:
            current = None
        if current != self.expected_asset_digest:
            alerts.append("asset_integrity_violation")
        for plugin in loaded_plugins:
            if plugin not in self.allowed_plugins:
                alerts.append(f"unapproved_plugin:{plugin}")
        return alerts
