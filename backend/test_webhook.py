import hashlib
import hmac
import json
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

from fetch_external import FetchResult
from webhook import (
    MAX_RETRIES,
    RETRY_BACKOFF_SECONDS,
    dispatch_webhook,
    queue_webhook_deliveries,
    sign_payload,
    validate_event_types,
    verify_signature,
)

DOC_PATH = Path(__file__).resolve().parent / "docs" / "webhooks.md"

SAMPLE_PAYLOAD = {
    "event_type": "embed",
    "video_hash": "a" * 64,
}
SAMPLE_BODY = (
    '{"event_type":"embed","video_hash":"'
    + "a" * 64
    + '"}'
)
SAMPLE_SECRET = "whsec_test_secret"
SAMPLE_TIMESTAMP = 1700000000
SAMPLE_SIGNATURE = "279de12b5d5c5157d75c884b6cad8caef222af865638c922969ed4e920c5beaf"


def test_sign_payload_documented_sample():
    body = json.dumps(SAMPLE_PAYLOAD, separators=(",", ":")).encode("utf-8")

    assert body == SAMPLE_BODY.encode("utf-8")
    assert sign_payload(body, SAMPLE_SECRET, SAMPLE_TIMESTAMP) == SAMPLE_SIGNATURE


def test_documentation_contains_verified_sample():
    document = DOC_PATH.read_text(encoding="utf-8")

    assert SAMPLE_BODY in document
    assert SAMPLE_SECRET in document
    assert str(SAMPLE_TIMESTAMP) in document
    assert f"v1={SAMPLE_SIGNATURE}" in document


def test_documented_header_verifies_with_snippet_logic():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    parts = {}
    for item in header.split(","):
        key, separator, value = item.strip().partition("=")
        assert separator
        parts[key] = value

    signed = f"{int(parts['t'])}.".encode("utf-8") + SAMPLE_BODY.encode("utf-8")
    expected = hmac.new(
        SAMPLE_SECRET.encode("utf-8"), signed, hashlib.sha256
    ).hexdigest()

    assert hmac.compare_digest(expected, parts["v1"])


def test_retry_constants_match_documentation():
    assert MAX_RETRIES == 5
    assert RETRY_BACKOFF_SECONDS == [10, 60, 300, 3600, 86400]


@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
def test_dispatch_webhook_success(mock_safe_urlopen, mock_update):
    mock_safe_urlopen.return_value = FetchResult(status=200, body=b"ok")

    delivery = {
        "delivery_id": 1,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 0,
        "payload": {"event_type": "embed"},
    }
    dispatch_webhook(delivery)

    mock_update.assert_called_once_with(1, True, 200, 0)


@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
def test_dispatch_webhook_failure(mock_safe_urlopen, mock_update):
    mock_safe_urlopen.side_effect = urllib.error.HTTPError(
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


@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.time.time", return_value=SAMPLE_TIMESTAMP)
def test_dispatch_webhook_sends_documented_signature(
    _mock_time, mock_safe_urlopen, _mock_update
):
    mock_safe_urlopen.return_value = FetchResult(status=204, body=b"")

    delivery = {
        "delivery_id": 3,
        "url": "http://example.com/webhook",
        "secret_key": SAMPLE_SECRET,
        "retry_count": 0,
        "payload": SAMPLE_PAYLOAD,
    }
    dispatch_webhook(delivery)

    request = mock_safe_urlopen.call_args.args[0]
    assert request.data == SAMPLE_BODY.encode("utf-8")
    assert request.get_header("X-harpocrates-signature") == (
        f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    )


def _queue_connection(event_row):
    cursor = mock.MagicMock()
    cursor.fetchone.return_value = event_row

    cursor_context = mock.MagicMock()
    cursor_context.__enter__.return_value = cursor

    connection = mock.MagicMock()
    connection.cursor.return_value = cursor_context

    connection_context = mock.MagicMock()
    connection_context.__enter__.return_value = connection

    return connection, cursor, connection_context


def _inserted_subscription_ids(cursor):
    return [
        call.args[1]
        for call in cursor.execute.call_args_list
        if "insert into webhook_deliveries" in call.args[0].lower()
    ]


def test_queue_deliveries_filtered():
    subs = [
        {"id": 1, "event_types": ["register"]},
        {"id": 2, "event_types": ["embed"]},
    ]
    connection, cursor, context = _queue_connection({"event_type": "register"})

    with mock.patch("webhook.database_url", return_value="postgresql://test"), \
            mock.patch("webhook.get_active_subscriptions", return_value=subs), \
            mock.patch("webhook.get_connection", return_value=context):
        queue_webhook_deliveries(7)

    assert _inserted_subscription_ids(cursor) == [(1, 7)]
    connection.commit.assert_called_once()


def test_queue_deliveries_unfiltered():
    subs = [
        {"id": 1, "event_types": None},
        {"id": 2, "event_types": ["embed"]},
    ]
    connection, cursor, context = _queue_connection({"event_type": "register"})

    with mock.patch("webhook.database_url", return_value="postgresql://test"), \
            mock.patch("webhook.get_active_subscriptions", return_value=subs), \
            mock.patch("webhook.get_connection", return_value=context):
        queue_webhook_deliveries(8)

    assert _inserted_subscription_ids(cursor) == [(1, 8)]
    connection.commit.assert_called_once()


def test_queue_deliveries_missing_event_is_ignored():
    subs = [{"id": 1, "event_types": None}]
    _connection, cursor, context = _queue_connection(None)

    with mock.patch("webhook.database_url", return_value="postgresql://test"), \
            mock.patch("webhook.get_active_subscriptions", return_value=subs), \
            mock.patch("webhook.get_connection", return_value=context):
        queue_webhook_deliveries(999)

    assert _inserted_subscription_ids(cursor) == []


def test_validate_event_types_allows_known():
    assert validate_event_types(["registration", "revocation"]) == [
        "registration",
        "revocation",
    ]
    assert validate_event_types(None) is None


def test_validate_event_types_rejects_unknown():
    with pytest.raises(ValueError):
        validate_event_types(["embed"])


def _dispatch_and_capture(mock_safe_urlopen, delivery):
    mock_safe_urlopen.return_value = FetchResult(status=204, body=b"")
    dispatch_webhook(delivery)
    return mock_safe_urlopen.call_args.args[0]


@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
def test_dispatch_webhook_sends_delivery_attempt_and_event_headers(
    mock_safe_urlopen, _mock_update
):
    request = _dispatch_and_capture(mock_safe_urlopen, {
        "delivery_id": 42,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 0,
        "payload": {"event_type": "register", "proof_id": "b" * 64},
    })

    assert request.get_header("X-harpocrates-delivery") == "42"
    assert request.get_header("X-harpocrates-attempt") == "1"
    assert request.get_header("X-harpocrates-event") == "register"


@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
def test_dispatch_webhook_attempt_header_counts_retries(
    mock_safe_urlopen, _mock_update
):
    request = _dispatch_and_capture(mock_safe_urlopen, {
        "delivery_id": 7,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 3,
        "payload": {"event_type": "embed"},
    })

    assert request.get_header("X-harpocrates-delivery") == "7"
    assert request.get_header("X-harpocrates-attempt") == "4"


@pytest.mark.parametrize("payload", [
    {"video_hash": "a" * 64},
    {"event_type": None},
    {"event_type": ""},
    {"event_type": "bad\r\nInjected: yes"},
])
@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
def test_dispatch_webhook_omits_event_header_without_safe_event_type(
    mock_safe_urlopen, _mock_update, payload
):
    request = _dispatch_and_capture(mock_safe_urlopen, {
        "delivery_id": 9,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 0,
        "payload": payload,
    })

    assert request.get_header("X-harpocrates-event") is None
    assert request.get_header("X-harpocrates-delivery") == "9"
    assert request.get_header("X-harpocrates-attempt") == "1"


@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
@mock.patch("webhook.time.time", return_value=SAMPLE_TIMESTAMP)
def test_new_headers_leave_signature_and_body_unchanged(
    _mock_time, mock_safe_urlopen, _mock_update
):
    request = _dispatch_and_capture(mock_safe_urlopen, {
        "delivery_id": 3,
        "url": "http://example.com/webhook",
        "secret_key": SAMPLE_SECRET,
        "retry_count": 2,
        "payload": SAMPLE_PAYLOAD,
    })

    assert request.data == SAMPLE_BODY.encode("utf-8")
    assert request.get_header("X-harpocrates-signature") == (
        f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    )
    header_values = [
        request.get_header("X-harpocrates-delivery"),
        request.get_header("X-harpocrates-attempt"),
    ]
    assert header_values == ["3", "3"]
    for value in header_values:
        assert "a" * 64 not in value


# --- verify_signature tests ---

VECTOR_2_BODY = (
    '{"event_type":"registration","contract_id":"CA3D5KRYM6CB7OWQ6TWYRR3Z4EK7O3YJXYTO2B2UNTWO5CDW252NO3ST",'
    '"proof_id":"' + "b" * 64 + '","tier":"seal"}'
)
VECTOR_2_SECRET = "whsec_test_secret_beta"
VECTOR_2_TIMESTAMP = 1710000000
VECTOR_2_SIGNATURE = "155aaba5797185e03a6cac932efae52cdcc6334119e4a4b54698d694f17bc5ae"

VECTOR_3_BODY = (
    '{"event_type":"verification","tx_hash":"' + "c" * 64 + '","tx_status":"confirmed"}'
)
VECTOR_3_SECRET = "whsec_test_secret_gamma"
VECTOR_3_TIMESTAMP = 1720000000
VECTOR_3_SIGNATURE = "7709c1f88e7d53789ca538e9bdc8cb5dd04cb4d0fe7a7c7d8c25065eb2422ea9"


def test_documentation_contains_all_test_vectors():
    doc = DOC_PATH.read_text(encoding="utf-8")
    for body, secret, timestamp, sig in [
        (SAMPLE_BODY, SAMPLE_SECRET, SAMPLE_TIMESTAMP, SAMPLE_SIGNATURE),
        (VECTOR_2_BODY, VECTOR_2_SECRET, VECTOR_2_TIMESTAMP, VECTOR_2_SIGNATURE),
        (VECTOR_3_BODY, VECTOR_3_SECRET, VECTOR_3_TIMESTAMP, VECTOR_3_SIGNATURE),
    ]:
        assert body in doc
        assert secret in doc
        assert str(timestamp) in doc
        assert sig in doc


@pytest.mark.parametrize(
    ("body_str", "secret", "timestamp", "sig"),
    [
        (SAMPLE_BODY, SAMPLE_SECRET, SAMPLE_TIMESTAMP, SAMPLE_SIGNATURE),
        (VECTOR_2_BODY, VECTOR_2_SECRET, VECTOR_2_TIMESTAMP, VECTOR_2_SIGNATURE),
        (VECTOR_3_BODY, VECTOR_3_SECRET, VECTOR_3_TIMESTAMP, VECTOR_3_SIGNATURE),
    ],
)
def test_published_vectors_verify_successfully(body_str, secret, timestamp, sig):
    header = f"t={timestamp},v1={sig}"
    body = body_str.encode("utf-8")
    assert verify_signature(header, body, secret, tolerance_seconds=300, now=timestamp)
    # Also verify tolerance allows exact bounds
    assert verify_signature(header, body, secret, tolerance_seconds=300, now=timestamp + 300)
    assert verify_signature(header, body, secret, tolerance_seconds=300, now=timestamp - 300)


def test_verify_signature_tampered_payload_fails():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    tampered_body = SAMPLE_BODY.replace('"embed"', '"revocation"').encode("utf-8")
    assert not verify_signature(header, tampered_body, SAMPLE_SECRET, now=SAMPLE_TIMESTAMP)


def test_verify_signature_wrong_secret_fails():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    assert not verify_signature(
        header, SAMPLE_BODY.encode("utf-8"), "wrong_secret", now=SAMPLE_TIMESTAMP
    )


def test_verify_signature_stale_timestamp_fails():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    # 301 seconds later -> exceeds 300s tolerance
    assert not verify_signature(
        header,
        SAMPLE_BODY.encode("utf-8"),
        SAMPLE_SECRET,
        tolerance_seconds=300,
        now=SAMPLE_TIMESTAMP + 301,
    )


def test_verify_signature_future_timestamp_beyond_tolerance_fails():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    # now is 301 seconds before the signature's timestamp
    assert not verify_signature(
        header,
        SAMPLE_BODY.encode("utf-8"),
        SAMPLE_SECRET,
        tolerance_seconds=300,
        now=SAMPLE_TIMESTAMP - 301,
    )


def test_verify_signature_within_tolerance_succeeds():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    body = SAMPLE_BODY.encode("utf-8")
    assert verify_signature(header, body, SAMPLE_SECRET, tolerance_seconds=300, now=SAMPLE_TIMESTAMP + 299)
    assert verify_signature(header, body, SAMPLE_SECRET, tolerance_seconds=300, now=SAMPLE_TIMESTAMP - 299)


def test_verify_signature_default_now_uses_time(monkeypatch):
    monkeypatch.setattr("webhook.time.time", lambda: float(SAMPLE_TIMESTAMP + 50))
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    assert verify_signature(header, SAMPLE_BODY.encode("utf-8"), SAMPLE_SECRET)

    monkeypatch.setattr("webhook.time.time", lambda: float(SAMPLE_TIMESTAMP + 350))
    assert not verify_signature(header, SAMPLE_BODY.encode("utf-8"), SAMPLE_SECRET)


def test_verify_signature_custom_tolerance():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    body = SAMPLE_BODY.encode("utf-8")
    assert verify_signature(header, body, SAMPLE_SECRET, tolerance_seconds=10, now=SAMPLE_TIMESTAMP + 10)
    assert not verify_signature(header, body, SAMPLE_SECRET, tolerance_seconds=10, now=SAMPLE_TIMESTAMP + 11)


@pytest.mark.parametrize(
    "malformed_header",
    [
        "",
        "invalid",
        "t=1700000000",
        "v1=279de12b5d5c5157d75c884b6cad8caef222af865638c922969ed4e920c5beaf",
        "t=not_a_number,v1=279de12b5d5c5157d75c884b6cad8caef222af865638c922969ed4e920c5beaf",
        "t=1700000000,v1=",
        "=1700000000,v1=abc",
        "t=1700000000,no_equals",
        "t=1700000000,v1=279de12b,extra=foo",  # doesn't match expected sig even if parsed
    ],
)
def test_verify_signature_malformed_headers(malformed_header):
    assert not verify_signature(
        malformed_header, SAMPLE_BODY.encode("utf-8"), SAMPLE_SECRET, now=SAMPLE_TIMESTAMP
    )


def test_verify_signature_invalid_argument_types():
    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    body = SAMPLE_BODY.encode("utf-8")

    assert not verify_signature(None, body, SAMPLE_SECRET, now=SAMPLE_TIMESTAMP)
    assert not verify_signature(header, "not bytes", SAMPLE_SECRET, now=SAMPLE_TIMESTAMP)
    assert not verify_signature(header, body, None, now=SAMPLE_TIMESTAMP)
    assert not verify_signature(header, bytearray(body), SAMPLE_SECRET, now=SAMPLE_TIMESTAMP) is False
    # bytearray should work
    assert verify_signature(header, bytearray(body), SAMPLE_SECRET, now=SAMPLE_TIMESTAMP) is True


def test_verify_signature_uses_compare_digest(monkeypatch):
    called = []
    real_compare_digest = hmac.compare_digest

    def tracking_compare_digest(a, b):
        called.append((a, b))
        return real_compare_digest(a, b)

    monkeypatch.setattr("webhook.hmac.compare_digest", tracking_compare_digest)

    header = f"t={SAMPLE_TIMESTAMP},v1={SAMPLE_SIGNATURE}"
    res = verify_signature(header, SAMPLE_BODY.encode("utf-8"), SAMPLE_SECRET, now=SAMPLE_TIMESTAMP)
    assert res is True
    assert len(called) == 1
    assert called[0] == (SAMPLE_SIGNATURE, SAMPLE_SIGNATURE)
