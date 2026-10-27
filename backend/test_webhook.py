import hashlib
import hmac
import json
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

from fetch_external import FetchResult, FetchTimeoutError, ResponseTooLargeError
from metrics import collector as metrics_collector
from webhook import (
    MAX_RETRIES,
    RETRY_BACKOFF_SECONDS,
    dispatch_webhook,
    queue_webhook_deliveries,
    sign_payload,
    validate_event_types,
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


@mock.patch("webhook.update_delivery_status")
@mock.patch("webhook.safe_urlopen")
def test_dispatch_webhook_records_outcome_metrics(mock_safe_urlopen, _mock_update):
    metrics_collector.reset()
    delivery = {
        "delivery_id": 10,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 0,
        "payload": {"event_type": "embed"},
    }

    # 1. Success
    mock_safe_urlopen.return_value = FetchResult(status=200, body=b"ok")
    dispatch_webhook(delivery)

    # 2. Non-2xx HTTP status (handled via result status)
    mock_safe_urlopen.return_value = FetchResult(status=500, body=b"error")
    dispatch_webhook(delivery)

    # 3. HTTPError exception
    mock_safe_urlopen.side_effect = urllib.error.HTTPError(
        "http://example.com", 404, "Not Found", {}, None
    )
    dispatch_webhook(delivery)

    # 4. Timeout
    mock_safe_urlopen.side_effect = FetchTimeoutError("timed out")
    dispatch_webhook(delivery)

    # 5. ResponseTooLargeError
    mock_safe_urlopen.side_effect = ResponseTooLargeError("too large")
    dispatch_webhook(delivery)

    # 6. Unexpected error
    mock_safe_urlopen.side_effect = RuntimeError("network cable pulled")
    dispatch_webhook(delivery)

    prom_output = metrics_collector.generate_prometheus_metrics()
    assert 'harpocrates_webhook_deliveries_total{outcome="success"} 1' in prom_output
    assert 'harpocrates_webhook_deliveries_total{outcome="http_error"} 2' in prom_output
    assert 'harpocrates_webhook_deliveries_total{outcome="timeout"} 1' in prom_output
    assert 'harpocrates_webhook_deliveries_total{outcome="too_large"} 1' in prom_output
    assert 'harpocrates_webhook_deliveries_total{outcome="error"} 1' in prom_output
    # Ensure no URL or subscription id appears in labels
    lines = [l for l in prom_output.splitlines() if l.startswith("harpocrates_webhook_deliveries_total{")]
    for line in lines:
        assert "http://example.com" not in line
        assert "delivery_id" not in line
        assert "subscription" not in line
