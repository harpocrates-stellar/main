import threading
import time
from functools import wraps
from typing import Callable, Dict, Optional, Tuple

from flask import jsonify, request


class AdmissionLease:
    """Idempotent handle to an acquired concurrency slot on ``AdmissionController``."""

    def __init__(self, controller: "AdmissionController", identity: str) -> None:
        self._controller = controller
        self.identity = identity
        self._lock = threading.Lock()
        self._released = False

    @property
    def released(self) -> bool:
        with self._lock:
            return self._released

    def release(self) -> bool:
        with self._lock:
            if self._released:
                return False
            self._released = True
        self._controller.release(self.identity)
        return True

    def __enter__(self) -> "AdmissionLease":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


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
        self._condition = threading.Condition(self._lock)
        self._active_count = 0
        self._current_queue = 0
        self._identity_counts: Dict[str, int] = {}

    def notify_cancelled(self) -> None:
        """Wake queued waiters so cancelled entries exit immediately."""
        with self._condition:
            self._condition.notify_all()

    def acquire(
        self,
        identity: str,
        *,
        cancel_event: Optional[threading.Event] = None,
        on_queued: Optional[Callable[[], None]] = None,
    ) -> Tuple[bool, str]:
        """
        Attempt to acquire a concurrency slot.
        Returns (True, "ok") if successful, or (False, reason) if rejected/cancelled.
        """
        queued_callback = None
        with self._condition:
            if cancel_event is not None and cancel_event.is_set():
                return False, "cancelled"

            # 1. Per-identity fairness
            if self._identity_counts.get(identity, 0) >= self.max_per_identity:
                return False, "identity_limit"

            # Take an immediately available execution slot without consuming
            # queue capacity. This keeps max_queue=0 useful as "no waiting".
            if self._active_count < self.max_concurrent:
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
            queued_callback = on_queued

        if queued_callback is not None:
            queued_callback()

        deadline = time.monotonic() + max(0.0, float(self.timeout_seconds))
        with self._condition:
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    self._current_queue -= 1
                    self._decrement_identity_unlocked(identity)
                    self._condition.notify_all()
                    return False, "cancelled"

                if self._active_count < self.max_concurrent:
                    self._current_queue -= 1
                    self._active_count += 1
                    return True, "ok"

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._current_queue -= 1
                    self._decrement_identity_unlocked(identity)
                    return False, "timeout"

                self._condition.wait(timeout=min(remaining, 0.05))

    def acquire_lease(
        self,
        identity: str,
        *,
        cancel_event: Optional[threading.Event] = None,
        on_queued: Optional[Callable[[], None]] = None,
    ) -> Tuple[Optional[AdmissionLease], str]:
        acquired, reason = self.acquire(
            identity,
            cancel_event=cancel_event,
            on_queued=on_queued,
        )
        if not acquired:
            return None, reason
        lease = AdmissionLease(self, identity)
        if cancel_event is not None and cancel_event.is_set():
            lease.release()
            return None, "cancelled"
        return lease, "ok"

    def _decrement_identity_unlocked(self, identity: str) -> None:
        remaining = self._identity_counts.get(identity, 0) - 1
        if remaining <= 0:
            self._identity_counts.pop(identity, None)
        else:
            self._identity_counts[identity] = remaining

    def release(self, identity: str) -> None:
        """
        Release a previously acquired concurrency slot.
        """
        with self._condition:
            self._active_count = max(0, self._active_count - 1)
            self._decrement_identity_unlocked(identity)
            self._condition.notify_all()


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
    Returns 429 or 503 with a Retry-After header on rejection.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            identity = _get_client_identity()
            acquired, reason = controller.acquire(identity)
            
            if not acquired:
                # Import here to avoid circular imports if needed
                from metrics import collector as metrics_collector
                
                # Record the rejection metric
                endpoint = request.url_rule.rule if request.url_rule else request.path
                metrics_collector.record_rejection(reason, endpoint)
                
                status_code = 429 if reason == "identity_limit" else 503
                response = jsonify({
                    "error": "service overloaded", 
                    "reason": reason
                })
                response.status_code = status_code
                response.headers["Retry-After"] = str(int(controller.timeout_seconds * 2) or 5)
                return response
                
            try:
                return f(*args, **kwargs)
            finally:
                controller.release(identity)
        return wrapped
    return decorator
