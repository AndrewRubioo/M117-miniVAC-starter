"""Authenticated baseline manifest for the MiniVAC toy client (owner: Arian, client defense).

A manifest is the reference the integrity checks compare against: the SHA-256 of
every protected asset and of every approved plugin. It is issued by a trusted
publisher, read by the untrusted client guard (client_defense.py) and held
independently by the server (integrity_verifier.py), so it sits in its own
module rather than on either side of the trust boundary.

Why it is authenticated: in the starter guard the expected hash and the plugin
allowlist are plain attributes, so an attacker edits them and every check passes
(CA04, CA12 in docs/CLIENT_ATTACK_LOG.md). Here they are covered by a MAC tag,
so an edited manifest no longer verifies.

Why HMAC and what that hides: the Python standard library has no public-key
signatures, so the tag is HMAC-SHA256. A real client would hold only a public
verification key; an HMAC verifier holds the same secret that creates tags.
The toy hands the guard `ManifestAuthority.verify` and treats it as that
verify-only key. Either way the attacker owns the machine and can swap the key
the guard trusts or skip the check; client_defense_eval.py tests exactly that
(DA04). Authentication moves the attack from "edit a value" to "replace the
trust anchor". It does not make the client trustworthy.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

# Event codes shared by the client guard and the server verifier.
MANIFEST_AUTH_FAILED = "manifest_auth_failed"
ASSET_MODIFIED = "asset_modified"
ASSET_MISSING = "asset_missing"
PLUGIN_NOT_APPROVED = "plugin_not_approved"
PLUGIN_CONTENT_MISMATCH = "plugin_content_mismatch"
PLUGIN_BLOCKED = "plugin_blocked"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Manifest:
    """What an unmodified client install looks like."""
    version: int
    assets: dict[str, str]    # protected asset name -> SHA-256 hex digest
    plugins: dict[str, str]   # approved plugin name -> SHA-256 hex digest of its content

    def canonical_bytes(self) -> bytes:
        """Deterministic encoding, so equal manifests always give equal MAC input."""
        return json.dumps(
            {"version": self.version, "assets": self.assets, "plugins": self.plugins},
            sort_keys=True, separators=(",", ":")).encode("utf8")

    def copy(self) -> "Manifest":
        """Independent copy. The client and the server must never share one object,
        or an attacker editing the client's manifest would silently edit the server's."""
        return Manifest(self.version, dict(self.assets), dict(self.plugins))


@dataclass
class SignedManifest:
    manifest: Manifest
    tag: str  # hex HMAC-SHA256 over manifest.canonical_bytes()


class ManifestAuthority:
    """The trusted publisher: the only party able to issue a manifest that verifies."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else secrets.token_bytes(32)

    def _mac(self, manifest: Manifest) -> bytes:
        return hmac.new(self._key, manifest.canonical_bytes(), hashlib.sha256).digest()

    def issue(self, manifest: Manifest) -> SignedManifest:
        return SignedManifest(manifest, self._mac(manifest).hex())

    def verify(self, signed: SignedManifest) -> bool:
        """True only if the tag matches the manifest's current contents.

        Anything malformed counts as a failed verification, never as an error the
        caller might ignore: an attacker controls every byte of this input.
        """
        try:
            supplied = bytes.fromhex(signed.tag)
            expected = self._mac(signed.manifest)
        except (TypeError, ValueError, AttributeError):
            return False
        return hmac.compare_digest(expected, supplied)
