from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


CONSENT_SCHEMA_VERSION = "1.0.0"
DEFAULT_CONSENT_POLICY_REVISION = "consent-policy-v1"
CONSENT_GRACE_PERIOD_SECONDS = 1800

_POLICY_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_STELLAR_KEY_RE = re.compile(r"^[GSM][A-Z2-7]{55,68}$")


def validate_consent_policy_revision(revision: str) -> str:
    if not isinstance(revision, str) or not _POLICY_REVISION_RE.match(revision):
        raise ValueError("invalid consent policy revision")
    if _HEX32_RE.match(revision) or _STELLAR_KEY_RE.match(revision):
        raise ValueError("invalid consent policy revision")
    return revision


class ConsentCollectionDisposition:
    COLLECTED_UNDER_CONSENT = "collected_under_consent"
    CONSENT_WITHDRAWN = "consent_withdrawn"
    NEVER_COLLECTED = "never_collected"


class ConsentStatus:
    UNKNOWN = "unknown"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    INVALID = "invalid"
    GRACE = "grace"


_VALID_STATUSES = {
    ConsentStatus.UNKNOWN,
    ConsentStatus.GRANTED,
    ConsentStatus.DENIED,
    ConsentStatus.EXPIRED,
    ConsentStatus.WITHDRAWN,
    ConsentStatus.INVALID,
    ConsentStatus.GRACE,
}


class ConsentSource:
    USER_EXPLICIT = "user_explicit"
    USER_IMPLICIT = "user_implicit"
    LEGAL = "legal_basis"
    SYSTEM_DEFAULT = "system_default"
    TOKEN = "consent_token"
    API_REQUEST = "api_request"
    UNKNOWN_SOURCE = "unknown"


_VALID_SOURCES = {
    ConsentSource.USER_EXPLICIT,
    ConsentSource.USER_IMPLICIT,
    ConsentSource.LEGAL,
    ConsentSource.SYSTEM_DEFAULT,
    ConsentSource.TOKEN,
    ConsentSource.API_REQUEST,
    ConsentSource.UNKNOWN_SOURCE,
}


@dataclass
class ConsentDecision:
    status: str
    source: str
    scope: List[str]
    expires_at_epoch_seconds: float
    granted_at_epoch_seconds: float
    version: str = CONSENT_SCHEMA_VERSION
    consent_token: Optional[str] = None
    withdrawal_epoch_seconds: Optional[float] = None
    reason: Optional[str] = None
    stable_account_tag: Optional[str] = None
    policy_revision: str = DEFAULT_CONSENT_POLICY_REVISION

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"invalid consent status: {self.status}")
        if self.source not in _VALID_SOURCES:
            raise ValueError(f"invalid consent source: {self.source}")
        validate_consent_policy_revision(self.policy_revision)


@dataclass
class ConsentState:
    account_tag: Optional[str] = None
    status: str = ConsentStatus.UNKNOWN
    source: str = ConsentSource.UNKNOWN_SOURCE
    granted_at_epoch_seconds: float = 0.0
    expires_at_epoch_seconds: float = 0.0
    withdrawal_epoch_seconds: Optional[float] = None
    granted_scopes: List[str] = field(default_factory=list)
    denied_scopes: List[str] = field(default_factory=list)
    consent_token: Optional[str] = None
    last_modified_epoch_seconds: float = 0.0
    version: str = CONSENT_SCHEMA_VERSION
    policy_revision: str = DEFAULT_CONSENT_POLICY_REVISION
    had_consented_collection: bool = False
    collection_policy_history: List[Tuple[float, str]] = field(default_factory=list)

    def is_active(self, now_epoch_seconds: float | None = None) -> bool:
        if self.status in {ConsentStatus.GRANTED, ConsentStatus.GRACE}:
            return True
        return False

    def requires_scope(self, scope: str) -> bool:
        if self.status == ConsentStatus.GRANTED:
            if scope in self.granted_scopes or "*" in self.granted_scopes:
                return True
        return False

    def to_decision(self) -> ConsentDecision:
        return ConsentDecision(
            status=self.status,
            source=self.source,
            scope=list(self.granted_scopes),
            expires_at_epoch_seconds=self.expires_at_epoch_seconds,
            granted_at_epoch_seconds=self.granted_at_epoch_seconds,
            version=self.version,
            consent_token=self.consent_token,
            withdrawal_epoch_seconds=self.withdrawal_epoch_seconds,
            stable_account_tag=self.account_tag,
            policy_revision=self.policy_revision,
        )


DEFAULT_CONSENT_STATE = ConsentState(
    status=ConsentStatus.UNKNOWN,
    source=ConsentSource.SYSTEM_DEFAULT,
    granted_at_epoch_seconds=0,
    expires_at_epoch_seconds=0,
    consent_token=None,
)


class ConsentManager:
    _consent_states: Dict[str, ConsentState]
    _grace_period: float
    _default_policy_revision: str
    _lock: threading.Lock

    def __init__(
        self,
        grace_period_seconds: float = CONSENT_GRACE_PERIOD_SECONDS,
        *,
        default_policy_revision: str = DEFAULT_CONSENT_POLICY_REVISION,
    ) -> None:
        validate_consent_policy_revision(default_policy_revision)
        self._grace_period = float(grace_period_seconds)
        self._default_policy_revision = default_policy_revision
        self._lock = threading.Lock()
        self._consent_states = {}

    def check_consent(
        self,
        account_tag: Optional[str],
        scope: Optional[str],
        now_epoch_seconds: float | None = None,
    ) -> Tuple[bool, ConsentState]:
        now = now_epoch_seconds if now_epoch_seconds is not None else time.time()
        if account_tag is None:
            temp = ConsentState(
                account_tag=None,
                status=ConsentStatus.GRACE,
                source=ConsentSource.SYSTEM_DEFAULT,
                granted_at_epoch_seconds=now,
                expires_at_epoch_seconds=now + self._grace_period,
                last_modified_epoch_seconds=now,
                policy_revision=self._default_policy_revision,
            )
            return (True, temp)
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                new_state = ConsentState(
                    account_tag=account_tag,
                    status=ConsentStatus.GRACE,
                    source=ConsentSource.SYSTEM_DEFAULT,
                    granted_at_epoch_seconds=now,
                    expires_at_epoch_seconds=now + self._grace_period,
                    last_modified_epoch_seconds=now,
                    policy_revision=self._default_policy_revision,
                )
                self._consent_states[account_tag] = new_state
                return (False, new_state)
            effective_status = state.status
            if state.status == ConsentStatus.GRANTED and state.expires_at_epoch_seconds > 0:
                if now > state.expires_at_epoch_seconds:
                    effective_status = ConsentStatus.EXPIRED
            if effective_status in {
                ConsentStatus.EXPIRED,
                ConsentStatus.WITHDRAWN,
                ConsentStatus.INVALID,
                ConsentStatus.DENIED,
                ConsentStatus.UNKNOWN,
            }:
                return (False, state)
            if effective_status == ConsentStatus.GRACE and not state.granted_scopes:
                return (False, state)
            if scope is not None:
                if scope not in state.granted_scopes and "*" not in state.granted_scopes:
                    return (False, state)
            return (True, state)

    def set_consent(self, account_tag: str, decision: ConsentDecision) -> ConsentState:
        now = time.time()
        with self._lock:
            existing = self._consent_states.get(account_tag)
            history = list(existing.collection_policy_history) if existing is not None else []
            had_collection = existing.had_consented_collection if existing is not None else False
            if decision.status == ConsentStatus.GRANTED:
                effective_from = decision.granted_at_epoch_seconds
                if not history or history[-1] != (effective_from, decision.policy_revision):
                    history.append((effective_from, decision.policy_revision))
                    history.sort(key=lambda pair: pair[0])

            new_state = ConsentState(
                account_tag=account_tag,
                status=decision.status,
                source=decision.source,
                granted_at_epoch_seconds=decision.granted_at_epoch_seconds,
                expires_at_epoch_seconds=decision.expires_at_epoch_seconds,
                withdrawal_epoch_seconds=decision.withdrawal_epoch_seconds,
                granted_scopes=list(decision.scope),
                consent_token=decision.consent_token,
                last_modified_epoch_seconds=now,
                version=decision.version,
                policy_revision=decision.policy_revision,
                had_consented_collection=had_collection,
                collection_policy_history=history,
            )
            if existing is not None:
                same = (
                    existing.status == new_state.status
                    and existing.source == new_state.source
                    and existing.granted_scopes == new_state.granted_scopes
                    and existing.expires_at_epoch_seconds == new_state.expires_at_epoch_seconds
                    and existing.consent_token == new_state.consent_token
                    and existing.withdrawal_epoch_seconds == new_state.withdrawal_epoch_seconds
                    and existing.policy_revision == new_state.policy_revision
                )
                if same:
                    existing.last_modified_epoch_seconds = now
                    return existing
            self._consent_states[account_tag] = new_state
            return new_state

    def record_collection(
        self,
        account_tag: str,
        scope: Optional[str],
        *,
        collected_at_epoch_seconds: float | None = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify active consent at collection time and return the effective policy revision."""
        ts = collected_at_epoch_seconds if collected_at_epoch_seconds is not None else time.time()
        allowed, _ = self.check_consent(account_tag=account_tag, scope=scope, now_epoch_seconds=ts)
        if not allowed:
            return False, None
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                return False, None
            rev = self._resolve_policy_locked(state, ts)
            if rev is None:
                return False, None
            state.had_consented_collection = True
            return True, rev

    def _resolve_policy_locked(
        self,
        state: ConsentState,
        timestamp_epoch_seconds: float,
    ) -> Optional[str]:
        if state.withdrawal_epoch_seconds is not None and timestamp_epoch_seconds >= state.withdrawal_epoch_seconds:
            return None
        chosen: Optional[str] = None
        for effective_from, rev in state.collection_policy_history:
            if effective_from <= timestamp_epoch_seconds:
                chosen = rev
            else:
                break
        if chosen is not None:
            return chosen
        if state.status == ConsentStatus.GRANTED and state.granted_at_epoch_seconds <= timestamp_epoch_seconds:
            return state.policy_revision
        return None

    def policy_effective_at(
        self,
        account_tag: str,
        timestamp_epoch_seconds: float,
    ) -> Optional[str]:
        """Return the consent policy revision that was effective at collection time."""
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                return None
            return self._resolve_policy_locked(state, timestamp_epoch_seconds)

    def inspect_subject_disposition(
        self,
        account_tag: Optional[str],
        *,
        matched_store_records: int = 0,
    ) -> Tuple[str, bool, Optional[str]]:
        """Return `(disposition, had_prior_collection, prior_policy_revision)` for export reporting."""
        if not account_tag:
            if matched_store_records > 0:
                return (
                    ConsentCollectionDisposition.COLLECTED_UNDER_CONSENT,
                    True,
                    self._default_policy_revision,
                )
            return ConsentCollectionDisposition.NEVER_COLLECTED, False, None

        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                return ConsentCollectionDisposition.NEVER_COLLECTED, False, None

            prior_rev = (
                state.collection_policy_history[-1][1]
                if state.collection_policy_history
                else (state.policy_revision if state.had_consented_collection else None)
            )
            had_prior = bool(
                state.had_consented_collection
                or matched_store_records > 0
                or len(state.collection_policy_history) > 0
            )

            if state.status == ConsentStatus.WITHDRAWN:
                return ConsentCollectionDisposition.CONSENT_WITHDRAWN, had_prior, prior_rev

            if matched_store_records > 0 and state.status == ConsentStatus.GRANTED:
                return (
                    ConsentCollectionDisposition.COLLECTED_UNDER_CONSENT,
                    True,
                    state.policy_revision,
                )

            return ConsentCollectionDisposition.NEVER_COLLECTED, False, None

    def withdraw_consent(
        self,
        account_tag: str,
        reason: Optional[str] = None,
        *,
        now_epoch_seconds: float | None = None,
    ) -> ConsentState:
        now = now_epoch_seconds if now_epoch_seconds is not None else time.time()
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                state = ConsentState(
                    account_tag=account_tag,
                    status=ConsentStatus.WITHDRAWN,
                    source=ConsentSource.USER_EXPLICIT,
                    last_modified_epoch_seconds=now,
                    policy_revision=self._default_policy_revision,
                )
                self._consent_states[account_tag] = state
            state.status = ConsentStatus.WITHDRAWN
            state.withdrawal_epoch_seconds = now
            state.last_modified_epoch_seconds = now
            return state

    def invalidate_consent(self, account_tag: str, reason: Optional[str] = None) -> ConsentState:
        now = time.time()
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                state = ConsentState(
                    account_tag=account_tag,
                    status=ConsentStatus.INVALID,
                    source=ConsentSource.SYSTEM_DEFAULT,
                    last_modified_epoch_seconds=now,
                    policy_revision=self._default_policy_revision,
                )
                self._consent_states[account_tag] = state
            state.status = ConsentStatus.INVALID
            state.last_modified_epoch_seconds = now
            return state

    def prune_expired(self, now_epoch_seconds: float | None = None, max_to_prune: int = 1000) -> int:
        now = now_epoch_seconds if now_epoch_seconds is not None else time.time()
        removed = 0
        with self._lock:
            to_remove: List[str] = []
            for tag, state in self._consent_states.items():
                if len(to_remove) >= max_to_prune:
                    break
                if state.status in {ConsentStatus.EXPIRED, ConsentStatus.WITHDRAWN, ConsentStatus.INVALID}:
                    age = now - state.last_modified_epoch_seconds
                    if age > self._grace_period:
                        to_remove.append(tag)
            for tag in to_remove:
                del self._consent_states[tag]
                removed += 1
        return removed

    def generate_consent_token(self, account_tag: str, status: str, scopes: List[str]) -> str:
        sorted_scopes = sorted(scopes)
        scopes_str = ",".join(sorted_scopes)
        random_bytes = os.urandom(8)
        raw = (account_tag + status + scopes_str).encode("utf-8") + random_bytes
        hashed = hashlib.sha256(raw).hexdigest()[:24]
        return "cst-v1:" + hashed
