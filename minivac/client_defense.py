"""Client-side defense v2 for the MiniVAC testbed (owner: Arian, client defense).

Scope: this guards ONLY the toy client in this repository: one test asset file
and toy "plugins" that are plain (name, bytes) records. No plugin is ever
imported or executed, and nothing touches real games, VAC, other processes or
the OS. Results describe the toy model, not real anti-cheat performance.

The starter guard (client_guard.py) is left untouched so both can be run on the
same attacks. What v2 changes, and the attack scenario that motivated it:

  starter guard weakness                        v2 mechanism
  expected hash is a bare attribute   (CA04)    reference data sits in an authenticated manifest
  allowlist is an editable set        (CA12)    the allowlist is part of that same manifest
  plugins are trusted by name         (CA09)    a plugin needs an approved name AND content digest
  plugins are checked only at scans   (CA10)    loads through the loader are checked at load time
  one opaque alert string                       typed events: modified vs missing, with a response
  alerts never leave the client                 measurements are reported for the server to judge

What v2 does not change: the attacker still owns this machine. They can disable
the guard, replace its trust anchor, or make it report whatever the server wants
to hear. See docs/CLIENT_DEFENSE_LOG.md for which of those are still caught.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from .manifest import (ASSET_MISSING, ASSET_MODIFIED, MANIFEST_AUTH_FAILED,
                       PLUGIN_BLOCKED, PLUGIN_CONTENT_MISMATCH, PLUGIN_NOT_APPROVED,
                       Manifest, SignedManifest, sha256_bytes)

# What the client should DO about each event. None of these is "ban": every one
# has an innocent explanation among the legitimate controls (CL03, CL04, CL06),
# so an integrity event alone is evidence of a mismatch, not of cheating.
SUGGESTED_RESPONSE = {
    ASSET_MISSING: "repair",            # re-download the file (also a broken install, CL06)
    ASSET_MODIFIED: "repair",           # re-verify files (also a stale baseline, CL03)
    PLUGIN_NOT_APPROVED: "block",       # do not let it run (also a harmless overlay, CL04)
    PLUGIN_CONTENT_MISMATCH: "block",
    PLUGIN_BLOCKED: "block",
    MANIFEST_AUTH_FAILED: "review",     # the reference itself is in doubt
}


@dataclass(frozen=True)
class SecurityEvent:
    code: str
    subject: str      # which asset or plugin
    detail: str = ""

    @property
    def response(self) -> str:
        return SUGGESTED_RESPONSE.get(self.code, "review")

    def __str__(self) -> str:
        return f"{self.code}:{self.subject}"


@dataclass
class LoadedPlugin:
    """A toy plugin: a name plus the bytes that stand for its code. Never executed."""
    name: str
    content: bytes

    @property
    def digest(self) -> str:
        return sha256_bytes(self.content)


@dataclass
class ScanResult:
    events: list[SecurityEvent]
    assets: dict[str, str | None]      # measured digest per asset, None if unreadable
    plugins: list[tuple[str, str]]     # (name, measured content digest) per loaded plugin
    manifest_version: int


def measure_file(path: str | Path) -> str | None:
    """SHA-256 of a file, read in chunks. None if the file cannot be read."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


@dataclass
class HardenedClientGuard:
    signed_manifest: SignedManifest
    # Stands in for a pinned public verification key: it can check a tag, not make one.
    trust_anchor: Callable[[SignedManifest], bool]
    active: bool = True

    def manifest_is_authentic(self) -> bool:
        return bool(self.trust_anchor(self.signed_manifest))

    def scan(self, assets: dict[str, Path],
             loaded_plugins: list[LoadedPlugin]) -> ScanResult | None:
        """Measure the client and compare it with the manifest.

        Returns None when the guard is disabled: no alert and nothing to report.
        Measuring is kept separate from judging, because the server repeats the
        judging against its own manifest (integrity_verifier.py).
        """
        if not self.active:
            return None
        manifest = self.signed_manifest.manifest
        measured_assets = {name: measure_file(path) for name, path in assets.items()}
        measured_plugins = [(plugin.name, plugin.digest) for plugin in loaded_plugins]

        if not self.manifest_is_authentic():
            # Fail closed: a manifest that does not verify cannot clear anything,
            # so none of its digests are consulted.
            events = [SecurityEvent(MANIFEST_AUTH_FAILED, "manifest",
                                    "tag does not verify under the trust anchor")]
        else:
            events = self._judge_assets(manifest, measured_assets)
            events += [event for plugin in loaded_plugins
                       if (event := self._judge_plugin(manifest, plugin)) is not None]
        return ScanResult(events, measured_assets, measured_plugins, manifest.version)

    def authorize_plugin(self, plugin: LoadedPlugin) -> SecurityEvent | None:
        """Load-time gate, inspired by Trusted Mode: decide BEFORE a plugin runs.

        Returns None to allow the load, or a PLUGIN_BLOCKED event to refuse it.
        This is prevention rather than detection, and it only mediates loads that
        go through the loader. Code injected around the loader is seen at the next
        scan at the earliest (CA10), and not at all if it hides (DA06).
        """
        if not self.active:
            return None  # a disabled guard mediates nothing
        if not self.manifest_is_authentic():
            return SecurityEvent(PLUGIN_BLOCKED, repr(plugin.name), MANIFEST_AUTH_FAILED)
        verdict = self._judge_plugin(self.signed_manifest.manifest, plugin)
        if verdict is None:
            return None
        return SecurityEvent(PLUGIN_BLOCKED, verdict.subject, verdict.code)

    @staticmethod
    def _judge_assets(manifest: Manifest,
                      measured: dict[str, str | None]) -> list[SecurityEvent]:
        events = []
        for name, expected in manifest.assets.items():
            actual = measured.get(name)
            if actual is None:
                events.append(SecurityEvent(ASSET_MISSING, name))
            elif actual != expected:
                events.append(SecurityEvent(ASSET_MODIFIED, name))
        return events

    @staticmethod
    def _judge_plugin(manifest: Manifest, plugin: LoadedPlugin) -> SecurityEvent | None:
        # Plugin names are attacker-chosen strings, so they are repr()'d in events:
        # 'hud ' and 'hud' must not look the same in a log.
        if plugin.name not in manifest.plugins:
            return SecurityEvent(PLUGIN_NOT_APPROVED, repr(plugin.name))
        if plugin.digest != manifest.plugins[plugin.name]:
            return SecurityEvent(PLUGIN_CONTENT_MISMATCH, repr(plugin.name),
                                 "approved name, different content")
        return None


def build_report(player_id: str, nonce: str, result: ScanResult,
                 extra_events: Iterable[SecurityEvent] = ()) -> dict:
    """The JSON-ready message the client sends across the trust boundary.

    Every field is a CLAIM made by an untrusted machine. The nonce stops an old
    report being replayed. Nothing stops a new report being invented, because no
    key or hardware the attacker cannot reach is involved in producing it. That
    is the difference between this and remote attestation.
    """
    return {
        "player_id": player_id,
        "nonce": nonce,
        "manifest_version": result.manifest_version,
        "assets": dict(result.assets),
        "plugins": [{"name": name, "sha256": digest} for name, digest in result.plugins],
        "events": [str(event) for event in (*result.events, *extra_events)],
    }
