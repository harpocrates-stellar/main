import json
import logging
from datetime import datetime, timedelta, timezone
from unittest import mock
import urllib.error

from fetch_external import FetchResult, FetchTimeoutError, ResponseTooLargeError
from webhook import (
    sign_payload,
    dispatch_webhook,
    is_previous_secret_valid,
    LOGGER,
)


def test_sign_payload():
    payload = b'{"hello": "world"}'
    secret = "mysecret"
    timestamp = 1620000000
    sig = sign_payload(payload, secret, timestamp)
    assert len(sig) == 64  # SHA-256 hex digest length

    sig2 = sign_payload(payload, secret, timestamp)
    assert sig == sig2


def test_is_previous_secret_valid():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Empty / None previous secret
    assert not is_previous_secret_valid(None, None, current_time=now)
    assert not is_previous_secret_valid("", None, current_time=now)

    # Valid indefinitely if no expiry
    assert is_previous_secret_valid("old_sec", None, current_time=now)

    # Future expiry (overlap window)
    future_dt = now + timedelta(hours=1)
    assert is_previous_secret_valid("old_sec", future_dt, current_time=now)
    assert is_previous_secret_valid("old_sec", future_dt.isoformat(), current_time=now)
    assert is_previous_secret_valid("old_sec", future_dt.timestamp(), current_time=now)

    # Past expiry (expired)
    past_dt = now - timedelta(seconds=1)
    assert not is_previous_secret_valid("old_sec", past_dt, current_time=now)
    assert not is_previous_secret_valid("old_sec", past_dt.isoformat(), current_time=now)
    assert not is_previous_secret_valid("old_sec", past_dt.timestamp(), current_time=now)

    # Exactly now
    assert not is_previous_secret_valid("old_sec", now, current_time=now)

    # Malformed expiration
    assert not is_previous_secret_valid("old_sec", "invalid-date", current_time=now)


@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_success(mock_update, mock_safe):
    mock_safe.return_value = FetchResult(status=200, body=b"ok")

    delivery = {
        "delivery_id": 1,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 0,
        "payload": {"event_type": "embed"},
    }
    dispatch_webhook(delivery)

    mock_update.assert_called_once_with(1, True, 200, 0)


@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_failure(mock_update, mock_safe):
    mock_safe.side_effect = urllib.error.HTTPError(
        "http://example.com", 500, "Internal Error", {}, None
    )

    delivery = {
        "delivery_id": 2,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 1,
        "payload": {"event_type": "extract"},
    }
    dispatch_webhook(delivery)

    mock_update.assert_called_once_with(2, False, 500, 1)


@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_single_secret(mock_update, mock_safe):
    mock_safe.return_value = FetchResult(status=200, body=b"ok")

    delivery = {
        "delivery_id": 10,
        "url": "http://example.com/webhook",
        "secret_key": "active_secret_key",
        "previous_secret_key": None,
        "previous_secret_expires_at": None,
        "retry_count": 0,
        "payload": {"event_type": "proof_registered", "proof_id": "p-123"},
    }
    dispatch_webhook(delivery)

    mock_safe.assert_called_once()
    req = mock_safe.call_args[0][0]
    sig_header = req.get_header("X-harpocrates-signature")
    assert sig_header is not None

    parts = sig_header.split(",")
    assert len(parts) == 2
    assert parts[0].startswith("t=")
    assert parts[1].startswith("v1=")

    # Verify signature matches active secret
    timestamp = int(parts[0].split("=")[1])
    payload_bytes = json.dumps(delivery["payload"], separators=(",", ":")).encode("utf-8")
    expected_sig = sign_payload(payload_bytes, "active_secret_key", timestamp)
    assert parts[1] == f"v1={expected_sig}"


@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_overlapping_secrets(mock_update, mock_safe):
    mock_safe.return_value = FetchResult(status=200, body=b"ok")

    # Expiry 2 hours in the future
    future_expiry = datetime.now(timezone.utc) + timedelta(hours=2)

    delivery = {
        "delivery_id": 11,
        "url": "http://example.com/webhook",
        "secret_key": "new_secret_key",
        "previous_secret_key": "old_secret_key",
        "previous_secret_expires_at": future_expiry,
        "retry_count": 0,
        "payload": {"event_type": "proof_registered", "proof_id": "p-456"},
    }
    dispatch_webhook(delivery)

    mock_safe.assert_called_once()
    req = mock_safe.call_args[0][0]
    sig_header = req.get_header("X-harpocrates-signature")
    assert sig_header is not None

    parts = sig_header.split(",")
    # t=..., v1=<new>, v1=<old>
    assert len(parts) == 3
    assert parts[0].startswith("t=")
    assert parts[1].startswith("v1=")
    assert parts[2].startswith("v1=")

    timestamp = int(parts[0].split("=")[1])
    payload_bytes = json.dumps(delivery["payload"], separators=(",", ":")).encode("utf-8")
    expected_new_sig = sign_payload(payload_bytes, "new_secret_key", timestamp)
    expected_old_sig = sign_payload(payload_bytes, "old_secret_key", timestamp)

    assert parts[1] == f"v1={expected_new_sig}"
    assert parts[2] == f"v1={expected_old_sig}"
    assert expected_new_sig != expected_old_sig


@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_overlapping_secrets_iso_string(mock_update, mock_safe):
    mock_safe.return_value = FetchResult(status=200, body=b"ok")

    future_expiry_iso = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()

    delivery = {
        "delivery_id": 12,
        "url": "http://example.com/webhook",
        "secret_key": "current_sec",
        "previous_secret_key": "prev_sec",
        "previous_secret_expires_at": future_expiry_iso,
        "retry_count": 0,
        "payload": {"event_type": "proof_verified"},
    }
    dispatch_webhook(delivery)

    req = mock_safe.call_args[0][0]
    sig_header = req.get_header("X-harpocrates-signature")
    parts = sig_header.split(",")
    assert len(parts) == 3
    assert parts[1].startswith("v1=")
    assert parts[2].startswith("v1=")


@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_expired_previous_secret(mock_update, mock_safe):
    mock_safe.return_value = FetchResult(status=200, body=b"ok")

    # Expiry 10 minutes in the past
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)

    delivery = {
        "delivery_id": 13,
        "url": "http://example.com/webhook",
        "secret_key": "new_secret_key",
        "previous_secret_key": "expired_old_secret_key",
        "previous_secret_expires_at": past_expiry,
        "retry_count": 0,
        "payload": {"event_type": "proof_registered", "proof_id": "p-789"},
    }
    dispatch_webhook(delivery)

    mock_safe.assert_called_once()
    req = mock_safe.call_args[0][0]
    sig_header = req.get_header("X-harpocrates-signature")
    assert sig_header is not None

    parts = sig_header.split(",")
    # Only t= and v1=<new> should be present; expired secret must NOT be emitted
    assert len(parts) == 2
    assert parts[0].startswith("t=")
    assert parts[1].startswith("v1=")

    timestamp = int(parts[0].split("=")[1])
    payload_bytes = json.dumps(delivery["payload"], separators=(",", ":")).encode("utf-8")
    expected_new_sig = sign_payload(payload_bytes, "new_secret_key", timestamp)
    expired_old_sig = sign_payload(payload_bytes, "expired_old_secret_key", timestamp)

    assert parts[1] == f"v1={expected_new_sig}"
    assert f"v1={expired_old_sig}" not in sig_header


@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.update_delivery_status")
def test_secrets_never_logged(mock_update, mock_safe, caplog):
    secret_curr = "SUPER_SECRET_KEY_987654"
    secret_prev = "SUPER_SECRET_PREV_123456"

    delivery = {
        "delivery_id": 42,
        "url": "http://example.com/webhook",
        "secret_key": secret_curr,
        "previous_secret_key": secret_prev,
        "previous_secret_expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "retry_count": 0,
        "payload": {"event_type": "embed"},
    }

    scenarios = [
        # 1. 200 OK
        lambda: FetchResult(status=200, body=b"ok"),
        # 2. 500 error
        lambda: FetchResult(status=500, body=b"internal error"),
        # 3. HTTPError
        lambda: urllib.error.HTTPError("http://example.com", 502, "Bad Gateway", {}, None),
        # 4. FetchTimeoutError
        lambda: FetchTimeoutError("connect timed out"),
        # 5. ResponseTooLargeError
        lambda: ResponseTooLargeError("response too large"),
        # 6. Unexpected error
        lambda: RuntimeError("unexpected socket failure"),
    ]

    with caplog.at_level(logging.DEBUG, logger="harpocrates.webhook"):
        for scenario in scenarios:
            caplog.clear()
            val = scenario()
            if isinstance(val, Exception):
                mock_safe.side_effect = val
            else:
                mock_safe.side_effect = None
                mock_safe.return_value = val

            dispatch_webhook(delivery)

            for record in caplog.records:
                assert secret_curr not in record.message
                assert secret_prev not in record.message


def test_receiver_verification_behavior():
    """Verify receiver behavior: accept if ANY v1 signature matches."""
    payload_bytes = b'{"event":"test"}'
    timestamp = 1700000000
    old_secret = "secret_generation_1"
    new_secret = "secret_generation_2"
    attacker_secret = "secret_attacker"

    sig_new = sign_payload(payload_bytes, new_secret, timestamp)
    sig_old = sign_payload(payload_bytes, old_secret, timestamp)

    header = f"t={timestamp},v1={sig_new},v1={sig_old}"

    # Receiver parsing logic
    parts = header.split(",")
    t_val = None
    v1_sigs = []
    for part in parts:
        if part.startswith("t="):
            t_val = int(part[2:])
        elif part.startswith("v1="):
            v1_sigs.append(part[3:])

    assert t_val == timestamp
    assert len(v1_sigs) == 2

    def receiver_verify(receiver_secret: str) -> bool:
        expected = sign_payload(payload_bytes, receiver_secret, t_val)
        import hmac
        return any(hmac.compare_digest(expected, sig) for sig in v1_sigs)

    # Receiver deployed with old secret accepts
    assert receiver_verify(old_secret) is True
    # Receiver deployed with new secret accepts
    assert receiver_verify(new_secret) is True
    # Receiver with invalid secret rejects
    assert receiver_verify(attacker_secret) is False

