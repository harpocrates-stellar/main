"""Tests for telemetry consent lifecycle in backend/analytics/consent.py.

Covers:
- ConsentDecision validation (valid/invalid status and source)
- ConsentState lifecycle (is_active, requires_scope, to_decision)
- ConsentManager consent checks with injected now_epoch_seconds (grace period, scope checks, expiry)
- ConsentManager grant / set_consent (new, updated, idempotent)
- ConsentManager withdrawal (existing and new accounts)
- ConsentManager invalidation (existing and new accounts)
- ConsentManager prune_expired respecting grace period and max_to_prune
- ConsentManager generate_consent_token stability and account tag redaction
- Policy revision recorded at collection time, and withdrawn consent distinguished
  from data never collected
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest

from analytics.consent import (
    CONSENT_GRACE_PERIOD_SECONDS,
    CONSENT_SCHEMA_VERSION,
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
    ConsentState,
    DEFAULT_CONSENT_STATE,
)


# ===========================================================================
# ConsentDecision tests
# ===========================================================================


class TestConsentDecision:
    """Verifies ConsentDecision instantiation and validation."""

    def test_valid_decision(self) -> None:
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry", "error_reporting"],
            expires_at_epoch_seconds=1_800_000_000.0,
            granted_at_epoch_seconds=1_700_000_000.0,
            version=CONSENT_SCHEMA_VERSION,
            consent_token="cst-v1:abcdef1234567890abcdef12",
            withdrawal_epoch_seconds=None,
            reason="user_opt_in",
            stable_account_tag="acct_12345",
        )
        assert decision.status == ConsentStatus.GRANTED
        assert decision.source == ConsentSource.USER_EXPLICIT
        assert decision.scope == ["telemetry", "error_reporting"]
        assert decision.expires_at_epoch_seconds == 1_800_000_000.0
        assert decision.granted_at_epoch_seconds == 1_700_000_000.0
        assert decision.version == CONSENT_SCHEMA_VERSION
        assert decision.consent_token == "cst-v1:abcdef1234567890abcdef12"
        assert decision.withdrawal_epoch_seconds is None
        assert decision.reason == "user_opt_in"
        assert decision.stable_account_tag == "acct_12345"

    def test_invalid_status_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="invalid consent status: invalid_status"):
            ConsentDecision(
                status="invalid_status",
                source=ConsentSource.USER_EXPLICIT,
                scope=[],
                expires_at_epoch_seconds=0.0,
                granted_at_epoch_seconds=0.0,
            )

    def test_invalid_source_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="invalid consent source: invalid_source"):
            ConsentDecision(
                status=ConsentStatus.GRANTED,
                source="invalid_source",
                scope=[],
                expires_at_epoch_seconds=0.0,
                granted_at_epoch_seconds=0.0,
            )


# ===========================================================================
# ConsentState tests
# ===========================================================================


class TestConsentState:
    """Verifies ConsentState behavior: is_active, requires_scope, to_decision."""

    @pytest.mark.parametrize(
        ("status", "expected_active"),
        [
            (ConsentStatus.GRANTED, True),
            (ConsentStatus.GRACE, True),
            (ConsentStatus.EXPIRED, False),
            (ConsentStatus.WITHDRAWN, False),
            (ConsentStatus.INVALID, False),
            (ConsentStatus.DENIED, False),
            (ConsentStatus.UNKNOWN, False),
        ],
    )
    def test_is_active_by_status(self, status: str, expected_active: bool) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=status,
            source=ConsentSource.USER_EXPLICIT,
        )
        assert state.is_active() is expected_active
        # Injected now_epoch_seconds must also never report expired as active
        assert state.is_active(now_epoch_seconds=1_000_000.0) is expected_active

    def test_default_consent_state_not_active(self) -> None:
        assert DEFAULT_CONSENT_STATE.is_active() is False
        assert DEFAULT_CONSENT_STATE.status == ConsentStatus.UNKNOWN
        assert DEFAULT_CONSENT_STATE.source == ConsentSource.SYSTEM_DEFAULT

    def test_requires_scope_when_granted(self) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=ConsentStatus.GRANTED,
            granted_scopes=["telemetry", "diagnostics"],
        )
        assert state.requires_scope("telemetry") is True
        assert state.requires_scope("diagnostics") is True
        assert state.requires_scope("profiling") is False

    def test_requires_scope_wildcard(self) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=ConsentStatus.GRANTED,
            granted_scopes=["*"],
        )
        assert state.requires_scope("telemetry") is True
        assert state.requires_scope("anything") is True

    @pytest.mark.parametrize(
        "status",
        [
            ConsentStatus.GRACE,
            ConsentStatus.DENIED,
            ConsentStatus.EXPIRED,
            ConsentStatus.WITHDRAWN,
            ConsentStatus.INVALID,
            ConsentStatus.UNKNOWN,
        ],
    )
    def test_requires_scope_false_when_not_granted(self, status: str) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=status,
            granted_scopes=["telemetry", "*"],
        )
        assert state.requires_scope("telemetry") is False

    def test_to_decision(self) -> None:
        state = ConsentState(
            account_tag="acct_123",
            status=ConsentStatus.GRANTED,
            source=ConsentSource.API_REQUEST,
            granted_at_epoch_seconds=1_000.0,
            expires_at_epoch_seconds=2_000.0,
            withdrawal_epoch_seconds=None,
            granted_scopes=["telemetry", "metrics"],
            consent_token="cst-v1:1234567890abcdef12345678",
            version=CONSENT_SCHEMA_VERSION,
        )
        decision = state.to_decision()
        assert decision.status == ConsentStatus.GRANTED
        assert decision.source == ConsentSource.API_REQUEST
        assert decision.scope == ["telemetry", "metrics"]
        assert decision.expires_at_epoch_seconds == 2_000.0
        assert decision.granted_at_epoch_seconds == 1_000.0
        assert decision.version == CONSENT_SCHEMA_VERSION
        assert decision.consent_token == "cst-v1:1234567890abcdef12345678"
        assert decision.withdrawal_epoch_seconds is None
        assert decision.stable_account_tag == "acct_123"


# ===========================================================================
# ConsentManager check_consent tests
# ===========================================================================


class TestConsentManagerCheckConsent:
    """Verifies check_consent with injected now_epoch_seconds without wall-clock time."""

    def test_check_consent_none_account_tag(self) -> None:
        cm = ConsentManager(grace_period_seconds=1200)
        now = 10_000.0
        allowed, state = cm.check_consent(account_tag=None, scope="telemetry", now_epoch_seconds=now)
        assert allowed is True
        assert state.account_tag is None
        assert state.status == ConsentStatus.GRACE
        assert state.source == ConsentSource.SYSTEM_DEFAULT
        assert state.granted_at_epoch_seconds == now
        assert state.expires_at_epoch_seconds == now + 1200.0
        assert state.last_modified_epoch_seconds == now

    def test_check_consent_unseen_account_tag_enters_grace_but_denied(self) -> None:
        cm = ConsentManager(grace_period_seconds=1800)
        now = 20_000.0
        allowed, state = cm.check_consent(account_tag="acct_new", scope="telemetry", now_epoch_seconds=now)
        assert allowed is False
        assert state.account_tag == "acct_new"
        assert state.status == ConsentStatus.GRACE
        assert state.source == ConsentSource.SYSTEM_DEFAULT
        assert state.granted_at_epoch_seconds == now
        assert state.expires_at_epoch_seconds == now + 1800.0
        assert state.last_modified_epoch_seconds == now

    def test_check_consent_granted_with_matching_scope(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry", "diagnostics"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_1", decision)

        allowed, state = cm.check_consent("acct_1", scope="telemetry", now_epoch_seconds=20_000.0)
        assert allowed is True
        assert state.status == ConsentStatus.GRANTED

    def test_check_consent_granted_with_unmatched_scope(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_1", decision)

        allowed, state = cm.check_consent("acct_1", scope="profiling", now_epoch_seconds=20_000.0)
        assert allowed is False
        assert state.status == ConsentStatus.GRANTED

    def test_check_consent_granted_with_wildcard_scope(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["*"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_wild", decision)

        allowed, _ = cm.check_consent("acct_wild", scope="any_arbitrary_scope", now_epoch_seconds=20_000.0)
        assert allowed is True

    def test_check_consent_granted_without_scope_check(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_noscope", decision)

        allowed, _ = cm.check_consent("acct_noscope", scope=None, now_epoch_seconds=20_000.0)
        assert allowed is True

    def test_check_consent_expiry_using_injected_now_epoch_seconds(self) -> None:
        cm = ConsentManager()
        expiry = 30_000.0
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=expiry,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_exp", decision)

        # Before expiry: active & allowed
        allowed, _ = cm.check_consent("acct_exp", scope="telemetry", now_epoch_seconds=expiry - 1.0)
        assert allowed is True

        # At expiry boundary: allowed
        allowed, _ = cm.check_consent("acct_exp", scope="telemetry", now_epoch_seconds=expiry)
        assert allowed is True

        # After expiry: not allowed (expired consent never reports active)
        allowed, state = cm.check_consent("acct_exp", scope="telemetry", now_epoch_seconds=expiry + 0.1)
        assert allowed is False
