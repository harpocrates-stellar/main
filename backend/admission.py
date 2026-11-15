from dataclasses import dataclass
from functools import wraps
import math
import threading
from typing import Any, Dict, Tuple

from flask import jsonify, request

ADMISSION_DECISION_SCHEMA = "hpx-upload-admission/1"

ADMISSION_CATEGORY_ADMITTED = "admitted"
ADMISSION_CATEGORY_IDENTITY_QUOTA = "identity_quota"
ADMISSION_CATEGORY_QUEUE_SATURATION = "queue_saturation"
ADMISSION_CATEGORY_PROCESSING_CAPACITY = "processing_capacity"

MIN_RETRY_AFTER_SECONDS = 1
MAX_RETRY_AFTER_SECONDS = 300


def clamp_retry_after_seconds(raw_seconds: float | int) -> int:
    """Clamp retry delay guidance into ``[MIN_RETRY_AFTER_SECONDS, MAX_RETRY_AFTER_SECONDS]``."""
    try:
        numeric = float(raw_seconds)
    except (TypeError, ValueError):
        return MIN_RETRY_AFTER_SECONDS
    if not math.isfinite(numeric):
        return MAX_RETRY_AFTER_SECONDS
    rounded = int(math.ceil(numeric))
    if rounded < MIN_RETRY_AFTER_SECONDS:
        return MIN_RETRY_AFTER_SECONDS
    if rounded > MAX_RETRY_AFTER_SECONDS:
        return MAX_RETRY_AFTER_SECONDS
    return rounded


@dataclass(frozen=True)
class AdmissionDecision:
    """Privacy-safe upload admission decision under ``hpx-upload-admission/1``."""

    admitted: bool
    category: str
    reason: str
    http_status: int
    retry_after_seconds: int
    backoff_strategy: str
    guidance: str
    schema: str = ADMISSION_DECISION_SCHEMA

    def to_api_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "admitted": self.admitted,
            "category": self.category,
            "reason": self.reason,
            "retryAfterSeconds": self.retry_after_seconds,
            "retryGuidance": {
                "delaySeconds": self.retry_after_seconds,
                "maxDelaySeconds": MAX_RETRY_AFTER_SECONDS,
                "strategy": self.backoff_strategy,
                "message": self.guidance,
            },
        }


def build_admission_decision(reason: str, *, timeout_seconds: float) -> AdmissionDecision:
    """Map an internal admission reason onto the stable public decision schema."""
    if reason == "ok":
        return AdmissionDecision(
            admitted=True,
            category=ADMISSION_CATEGORY_ADMITTED,
            reason="ok",
            http_status=200,
            retry_after_seconds=0,
            backoff_strategy="none",
            guidance="Upload capacity is available.",
        )
    if reason == "identity_limit":
        delay = clamp_retry_after_seconds(max(1.0, float(timeout_seconds)))
        return AdmissionDecision(
            admitted=False,
            category=ADMISSION_CATEGORY_IDENTITY_QUOTA,
            reason="identity_limit",
            http_status=429,
            retry_after_seconds=delay,
            backoff_strategy="caller_completion",
            guidance="Per-caller concurrent upload quota reached; wait for an in-flight upload from this caller to finish before retrying.",
        )
    if reason == "queue_full":
        delay = clamp_retry_after_seconds(max(2.0, float(timeout_seconds) * 3.0))
        return AdmissionDecision(
            admitted=False,
            category=ADMISSION_CATEGORY_QUEUE_SATURATION,
            reason="queue_full",
            http_status=503,
            retry_after_seconds=delay,
            backoff_strategy="exponential",
            guidance="Upload admission queue is saturated; retry using bounded exponential backoff.",
        )
    delay = clamp_retry_after_seconds(max(1.0, float(timeout_seconds) * 2.0))
    return AdmissionDecision(
        admitted=False,
        category=ADMISSION_CATEGORY_PROCESSING_CAPACITY,
        reason="timeout",
        http_status=503,
        retry_after_seconds=delay,
        backoff_strategy="linear",
        guidance="Upload processing capacity is busy; retry after the bounded delay.",
    )


class AdmissionController:
    """
    Manages capacity and queue limits, providing backpressure via admission control.
    """

    def __init__(
        self,
        max_concurrent: int,
        max_queue: int,
        max_per_identity: int,
        timeout_seconds: float,
    ):
        self.max_concurrent = max_concurrent
        self.max_queue = max_queue
        self.max_per_identity = max_per_identity
        self.timeout_seconds = timeout_seconds

        self._lock = threading.Lock()
        self._active_count = 0
        self._current_queue = 0
        self._identity_counts: Dict[str, int] = {}
        self._semaphore = threading.Semaphore(max_concurrent)

    def acquire(self, identity: str) -> Tuple[bool, str]:
        """
        Attempt to acquire a concurrency slot.
        Returns (True, "ok") if successful, or (False, reason) if rejected.
        """
        with self._lock:
            # 1. Per-identity fairness
            if self._identity_counts.get(identity, 0) >= self.max_per_identity:
                return False, "identity_limit"

            # Take an immediately available execution slot without consuming
            # queue capacity. This keeps max_queue=0 useful as "no waiting".
            if self._semaphore.acquire(blocking=False):
                self._active_count += 1
                self._identity_counts[identity] = (
                    self._identity_counts.get(identity, 0) + 1
                )
                return True, "ok"

            # 2. Queue limits apply only when all execution slots are busy.
            if self._current_queue >= self.max_queue:
                return False, "queue_full"

            # Join the queue
            self._current_queue += 1
            self._identity_counts[identity] = self._identity_counts.get(identity, 0) + 1

        # 3. Wait for global concurrency
        acquired = self._semaphore.acquire(timeout=self.timeout_seconds)

        with self._lock:
            # Leave the queue
            self._current_queue -= 1

            if not acquired:
                # Timed out waiting
                self._identity_counts[identity] -= 1
                if self._identity_counts[identity] == 0:
                    del self._identity_counts[identity]
                return False, "timeout"

            self._active_count += 1

        return True, "ok"

    def decide(self, identity: str) -> AdmissionDecision:
        """Acquire capacity and return a structured ``AdmissionDecision``."""
        _acquired, reason = self.acquire(identity)
        return build_admission_decision(reason, timeout_seconds=self.timeout_seconds)

    def preview_decision(self, identity: str) -> AdmissionDecision:
        """Return a non-mutating admission decision snapshot without disclosing peers."""
        with self._lock:
            if self._identity_counts.get(identity, 0) >= self.max_per_identity:
                reason = "identity_limit"
            elif self._active_count < self.max_concurrent:
                reason = "ok"
            elif self._current_queue >= self.max_queue:
                reason = "queue_full"
            else:
                reason = "timeout"
        return build_admission_decision(reason, timeout_seconds=self.timeout_seconds)

    def release(self, identity: str) -> None:
        """
        Release a previously acquired concurrency slot.
        """
        with self._lock:
            self._active_count = max(0, self._active_count - 1)
            self._identity_counts[identity] -= 1
            if self._identity_counts[identity] == 0:
                del self._identity_counts[identity]

        self._semaphore.release()


def _get_client_identity() -> str:
    """Extract a stable identity string for the client."""
    # Note: In a real production deployment behind a load balancer, 
    # this should securely parse X-Forwarded-For or use a more robust token.
    # We take the first IP in X-Forwarded-For to avoid spoofing if possible,
    # but for this scope we just safely read it.
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def require_capacity(controller: AdmissionController):
    """
    Flask decorator to enforce admission control on a route.
    Returns 429 or 503 with a Retry-After header and stable admission schema on rejection.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            identity = _get_client_identity()
            decision = controller.decide(identity)

            if not decision.admitted:
                # Import here to avoid circular imports if needed
                from metrics import collector as metrics_collector

                # Record the rejection metric
                endpoint = request.url_rule.rule if request.url_rule else request.path
                metrics_collector.record_rejection(decision.reason, endpoint)

                admission_payload = decision.to_api_dict()
                response = jsonify({
                    "ok": False,
                    "error": "service overloaded",
                    "reason": decision.reason,
                    "schema": decision.schema,
                    "admission": admission_payload,
                })
                response.status_code = decision.http_status
                response.headers["Retry-After"] = str(decision.retry_after_seconds)
                response.headers["X-Upload-Admission-Schema"] = decision.schema
                response.headers["X-Upload-Admission-Category"] = decision.category
                return response

            try:
                response = f(*args, **kwargs)
                return response
            finally:
                controller.release(identity)
        return wrapped
    return decorator
