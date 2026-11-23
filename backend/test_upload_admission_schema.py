import pytest
from flask import Flask, jsonify

from admission import (
    ADMISSION_DECISION_SCHEMA,
    AdmissionDecision,
    AdmissionReason,
    AdmissionController,
    admission_decision,
    require_capacity,
)


class _RejectingController(AdmissionController):
    def __init__(self, reason: str, timeout_seconds: float = 0.25):
        super().__init__(
            max_concurrent=1,
            max_queue=0,
            max_per_identity=1,
            timeout_seconds=timeout_seconds,
        )
        self.reason = reason

    def acquire_ticket(self, identity, ticket=None):
        return False, self.reason, ticket


@pytest.mark.parametrize(
    ("reason", "expected_reason", "expected_code", "expected_status"),
    [
        (
            "identity_limit",
            AdmissionReason.IDENTITY_QUOTA,
            "ADMISSION_IDENTITY_QUOTA",
            429,
        ),
        (
            "queue_full",
            AdmissionReason.QUEUE_SATURATION,
            "ADMISSION_QUEUE_SATURATION",
            503,
        ),
        (
            "timeout",
            AdmissionReason.PROCESSING_CAPACITY,
            "ADMISSION_PROCESSING_CAPACITY",
            503,
        ),
    ],
)
def test_admission_rejections_use_distinct_stable_codes(
    reason, expected_reason, expected_code, expected_status
):
    app = Flask(__name__)
    controller = _RejectingController(reason)

    @app.get("/upload")
    @require_capacity(controller)
    def upload():
        return jsonify({"ok": True})

    response = app.test_client().get("/upload")
    body = response.get_json()

    assert response.status_code == expected_status
    assert body["ok"] is False
    assert body["reason"] == reason
    assert body["error"]["code"] == expected_code
    assert body["error"]["admission"]["reason"] == expected_reason.value
    assert body["error"]["admission"]["code"] == expected_code
    assert body["error"]["admission"]["retryable"] is True


def test_retry_guidance_is_bounded_and_matches_header():
    app = Flask(__name__)
    controller = _RejectingController("queue_full", timeout_seconds=3600)

    @app.get("/upload")
    @require_capacity(controller)
    def upload():
        return jsonify({"ok": True})

    response = app.test_client().get("/upload")
    body = response.get_json()
    retry = body["error"]["admission"]["retryAfterSeconds"]

    assert response.headers["Retry-After"] == str(retry)
    assert 1 <= retry <= ADMISSION_DECISION_SCHEMA["properties"]["maxRetryAfterSeconds"]
    assert "request_id" in body["error"]


def test_admission_messages_never_disclose_identity_or_queue_depth():
    app = Flask(__name__)
    controller = _RejectingController("identity_limit")

    @app.get("/upload")
    @require_capacity(controller)
    def upload():
        return jsonify({"ok": True})

    body = app.test_client().get(
        "/upload", environ_base={"REMOTE_ADDR": "203.0.113.99"}
    ).get_json()

    serialized = str(body)
    assert "203.0.113.99" not in serialized
    assert "current_queue" not in serialized
    assert "identity_counts" not in serialized


def test_decision_schema_is_stable():
    assert ADMISSION_DECISION_SCHEMA["title"] == "UploadAdmissionDecision"
    assert ADMISSION_DECISION_SCHEMA["type"] == "object"
    assert set(ADMISSION_DECISION_SCHEMA["required"]) == {
        "code",
        "reason",
        "message",
        "retryAfterSeconds",
        "retryable",
    }
    assert ADMISSION_DECISION_SCHEMA["properties"]["maxRetryAfterSeconds"] == 60


@pytest.mark.parametrize(
    ("timeout", "expected"),
    [(0.0, 1), (0.1, 1), (1.5, 2), (3600.0, 60)],
)
def test_retry_after_is_clamped(timeout, expected):
    decision: AdmissionDecision = admission_decision("timeout", timeout)
    assert decision.retry_after_seconds == expected
