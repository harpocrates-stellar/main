"""Ownership-scoped authentication for ``POST /api/proofs/register``.

Two kinds of credential can authorize a registration:

* the legacy **unscoped** key (``REGISTER_API_KEY``), unchanged and still
  accepted so existing callers keep working; and
* **owner-scoped** keys (``REGISTER_SCOPED_KEYS``), each bound to exactly one
  Stellar ``sourceAddress``. A scoped credential may only register proofs whose
  ``sourceAddress`` is its owner.

Scoped keys are configured as SHA-256 *digests*, never plaintext, so a leaked
environment dump or config file does not yield a usable credential. The wire
format is ``<G-address>:<sha256-hex>`` entries separated by commas.

Nothing here logs or returns token material, digests, or addresses; failures are
described by a stable reason code only.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Final

from strkey import validate_source_address

#: Longest bearer token considered. Anything longer cannot be a real credential
#: and is rejected without being hashed, bounding work per unauthenticated call.
MAX_TOKEN_CHARS: Final[int] = 256

#: Upper bound on configured scoped credentials, to keep the per-request scan
#: (which deliberately never exits early) bounded.
MAX_SCOPED_KEYS: Final[int] = 256

_DIGEST_HEX_LEN: Final[int] = 64
_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")

# Stable reason codes; also the values written to privacy-safe auth logs.
REASON_MISSING: Final[str] = "missing"
REASON_INVALID: Final[str] = "invalid"
REASON_EXPIRED: Final[str] = "expired"
REASON_SCOPE: Final[str] = "scope_mismatch"
REASON_OWNER_CONFLICT: Final[str] = "owner_conflict"


@dataclass(frozen=True)
class ScopedKey:
    """One owner-bound credential, stored as a digest."""

    owner: str
    digest: bytes


@dataclass(frozen=True)
class RegistrationPrincipal:
    """Who is registering. ``owner`` is ``None`` for the legacy unscoped key."""

    owner: str | None

    @property
    def is_scoped(self) -> bool:
        return self.owner is not None


def token_digest(token: str) -> bytes:
    """SHA-256 of a bearer token, the form scoped keys are configured in."""
    return hashlib.sha256(token.encode("utf-8")).digest()


def parse_scoped_keys(raw: str | None) -> tuple[ScopedKey, ...]:
    """Parse ``REGISTER_SCOPED_KEYS``. Fails closed on any malformed entry.

    Errors name the entry *position* only, never its contents, so a bad config
    value cannot leak into startup logs.
    """
    if raw is None or not raw.strip():
        return ()

    entries = [item.strip() for item in raw.split(",") if item.strip()]
    if len(entries) > MAX_SCOPED_KEYS:
        raise RuntimeError(f"REGISTER_SCOPED_KEYS allows at most {MAX_SCOPED_KEYS} entries")

    parsed: list[ScopedKey] = []
    seen_digests: set[bytes] = set()
    for position, entry in enumerate(entries, start=1):
        owner_text, separator, digest_text = entry.partition(":")
        if not separator:
            raise RuntimeError(f"REGISTER_SCOPED_KEYS entry {position} must be <address>:<sha256-hex>")
        try:
            owner = validate_source_address(owner_text)
        except ValueError as exc:
            raise RuntimeError(
                f"REGISTER_SCOPED_KEYS entry {position} has an invalid Stellar G-address"
            ) from exc
        digest_text = digest_text.strip().lower()
        if len(digest_text) != _DIGEST_HEX_LEN or any(c not in _HEX_DIGITS for c in digest_text):
            raise RuntimeError(f"REGISTER_SCOPED_KEYS entry {position} digest must be 64 hex characters")
        digest = bytes.fromhex(digest_text)
        if digest in seen_digests:
            # One credential must map to one owner, or ownership is ambiguous.
            raise RuntimeError(f"REGISTER_SCOPED_KEYS entry {position} reuses another entry's digest")
        seen_digests.add(digest)
        parsed.append(ScopedKey(owner=owner, digest=digest))
    return tuple(parsed)


def authenticate(
    token: str,
    *,
    legacy_key: str | None,
    scoped_keys: tuple[ScopedKey, ...],
) -> RegistrationPrincipal | None:
    """Resolve a bearer token to a principal, or ``None`` when it matches nothing.

    Every configured credential is compared on every call, with no early exit,
    so timing does not reveal which entry (if any) matched.
    """
    if len(token) > MAX_TOKEN_CHARS:
        return None

    presented = token.encode("utf-8")
    presented_digest = hashlib.sha256(presented).digest()

    matched_owner: str | None = None
    scoped_match = False
    for entry in scoped_keys:
        if hmac.compare_digest(presented_digest, entry.digest):
            matched_owner = entry.owner
            scoped_match = True

    legacy_match = False
    if legacy_key is not None:
        legacy_match = hmac.compare_digest(presented, legacy_key.encode("utf-8"))

    if scoped_match:
        return RegistrationPrincipal(owner=matched_owner)
    if legacy_match:
        return RegistrationPrincipal(owner=None)
    return None


def scope_allows(principal: RegistrationPrincipal, claimed_owner: str | None) -> bool:
    """May ``principal`` register a proof claiming ``claimed_owner``?

    Unscoped principals are unrestricted (compatibility). Scoped principals
    must name their own address; an omitted address is not allowed, because
    that would let a scoped key register ownerless proofs.
    """
    if principal.owner is None:
        return True
    if claimed_owner is None:
        return False
    return hmac.compare_digest(principal.owner.encode("ascii"), claimed_owner.encode("ascii"))
