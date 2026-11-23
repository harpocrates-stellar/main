import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Dict, List, Optional, Tuple

from flask import g, request, jsonify


RETRY_AFTER_MIN_SECONDS = 1
RETRY_AFTER_MAX_SECONDS = 60

ADMISSION_IDENTITY_QUOTA = "ADMISSION_IDENTITY_QUOTA"
ADMISSION_QUEUE_SATURATION = "ADMISSION_QUEUE_SATURATION"
ADMISSION_PROCESSING_CAPACITY = "ADMISSION_PROCESSING_CAPACITY"

ADMISSION_DECISION_SCHEMA = {
    "title": "UploadAdmissionDecision",
    "type": "object",
    "required": [
        "code",
        "reason",
        "message",
        "retryAfterSeconds",
        "retryable",
    ],
    "properties": {
        "code": {
            "type": "string",
            "enum": [
                ADMISSION_IDENTITY_QUOTA,
                ADMISSION_QUEUE_SATURATION,
                ADMISSION_PROCESSING_CAPACITY,
            ],
        },
        "reason": {
            "type": "string",
            "enum": ["identity_quota", "queue_saturation", "processing_capacity"],
        },
        "message": {"type": "string"},
        "retryAfterSeconds": {
            "type": "integer",
            "minimum": RETRY_AFTER_MIN_SECONDS,
            "maximum": RETRY_AFTER_MAX_SECONDS,
        },
        "retryable": {"type": "boolean", "const": True},
        "maxRetryAfterSeconds": RETRY_AFTER_MAX_SECONDS,
    },
}


class AdmissionReason(str, Enum):
    IDENTITY_QUOTA = "identity_quota"
    QUEUE_SATURATION = "queue_saturation"
    PROCESSING_CAPACITY = "processing_capacity"


@dataclass(frozen=True)
class AdmissionDecision:
    legacy_reason: str
    reason: AdmissionReason
    code: str
    message: str
    status: int
    retry_after_seconds: int

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "reason": self.reason.value,
            "message": self.message,
            "retryAfterSeconds": self.retry_after_seconds,
            "retryable": True,
        }


_ADMISSION_DECISIONS = {
    "identity_limit": (
        AdmissionReason.IDENTITY_QUOTA,
        ADMISSION_IDENTITY_QUOTA,
        "upload concurrency quota reached for this client",
        429,
    ),
    "queue_full": (
        AdmissionReason.QUEUE_SATURATION,
        ADMISSION_QUEUE_SATURATION,
        "upload admission queue is full",
        503,
    ),
    "timeout": (
        AdmissionReason.PROCESSING_CAPACITY,
        ADMISSION_PROCESSING_CAPACITY,
        "upload processing capacity is temporarily unavailable",
        503,
    ),
    "cancelled": (
        AdmissionReason.PROCESSING_CAPACITY,
        ADMISSION_PROCESSING_CAPACITY,
        "upload processing capacity is temporarily unavailable",
        503,
    ),
}


def admission_decision(reason: str, timeout_seconds: float) -> AdmissionDecision:
    decision_reason, code, message, status = _ADMISSION_DECISIONS.get(
        reason,
        _ADMISSION_DECISIONS["timeout"],
    )
    retry_after = math.ceil(max(0.0, float(timeout_seconds)))
    retry_after = max(RETRY_AFTER_MIN_SECONDS, min(RETRY_AFTER_MAX_SECONDS, retry_after))
    return AdmissionDecision(
        legacy_reason=reason,
        reason=decision_reason,
        code=code,
        message=message,
        status=status,
        retry_after_seconds=retry_after,
    )


def admission_error_response(decision: AdmissionDecision):
    payload = decision.as_dict()
    request_id = getattr(g, "request_id", "unknown")
    return jsonify({
        "ok": False,
        "error": {
            "code": decision.code,
            "message": decision.message,
            "request_id": request_id,
            "admission": payload,
        },
        "reason": decision.legacy_reason,
        "admissionReason": decision.reason.value,
        "retryAfterSeconds": decision.retry_after_seconds,
    })


class AdmissionState(str, Enum):
    QUEUED = "queued"
    ACTIVE = "active"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    RELEASED = "released"


@dataclass
class AdmissionTicket:
    id: str
    identity: str
    state: AdmissionState = AdmissionState.QUEUED
    cancel_event: threading.Event = field(default_factory=threading.Event)
    queued: bool = False


class AdmissionController:
    """
    Manages capacity and queue limits, providing backpressure via admission control.
    Also tracks per-identity temporary upload storage budget reservations.
    """

    def __init__(
        self,
        max_concurrent: int,
        max_queue: int,
        max_per_identity: int,
        timeout_seconds: float,
        max_temp_storage_per_identity: int | None = None,
    ):
        self.max_concurrent = max_concurrent
        self.max_queue = max_queue
        self.max_per_identity = max_per_identity
        self.timeout_seconds = timeout_seconds
        self.max_temp_storage_per_identity = max_temp_storage_per_identity

        self._lock = threading.Lock()
        self._current_queue = 0
        self._identity_counts: Dict[str, int] = {}
        self._tickets: Dict[str, AdmissionTicket] = {}
        self._identity_tickets: Dict[str, List[str]] = {}
        self._semaphore = threading.Semaphore(max_concurrent)

    def create_ticket(self, identity: str) -> Optional[AdmissionTicket]:
        with self._lock:
            if self._identity_counts.get(identity, 0) >= self.max_per_identity:
                return None
            ticket = AdmissionTicket(id=str(uuid.uuid4()), identity=identity)
            self._tickets[ticket.id] = ticket
            self._identity_tickets.setdefault(identity, []).append(ticket.id)
            return ticket

    def acquire(self, identity: str) -> Tuple[bool, str]:
        ok, reason, _ticket = self.acquire_ticket(identity)
        return ok, reason

    def acquire_ticket(
        self,
        identity: str,
        ticket: Optional[AdmissionTicket] = None,
    ) -> Tuple[bool, str, Optional[AdmissionTicket]]:
        ticket = ticket or self.create_ticket(identity)
        if ticket is None:
            return False, "identity_limit", None
        if ticket.identity != identity or ticket.state is not AdmissionState.QUEUED:
            return False, "cancelled", ticket

        with self._lock:
            if self._identity_counts.get(identity, 0) >= self.max_per_identity:
                self._finish_ticket(ticket, AdmissionState.RELEASED)
                return False, "identity_limit", ticket

            if self._semaphore.acquire(blocking=False):
                self._identity_counts[identity] = (
                    self._identity_counts.get(identity, 0) + 1
                )
                ticket.state = AdmissionState.ACTIVE
                return True, "ok", ticket

            if self._current_queue >= self.max_queue:
                self._finish_ticket(ticket, AdmissionState.RELEASED)
                return False, "queue_full", ticket

            self._current_queue += 1
            ticket.queued = True
            self._identity_counts[identity] = self._identity_counts.get(identity, 0) + 1

        deadline = time.monotonic() + self.timeout_seconds
        while True:
            if ticket.cancel_event.is_set():
                with self._lock:
                    self._leave_queue(ticket)
                    self._finish_ticket(ticket, AdmissionState.CANCELLED)
                return False, "cancelled", ticket

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with self._lock:
                    self._leave_queue(ticket)
                    self._finish_ticket(ticket, AdmissionState.RELEASED)
                return False, "timeout", ticket

            if self._semaphore.acquire(blocking=False):
                with self._lock:
                    if ticket.cancel_event.is_set():
                        self._semaphore.release()
                        self._leave_queue(ticket)
                        self._finish_ticket(ticket, AdmissionState.CANCELLED)
                        return False, "cancelled", ticket
                    self._current_queue -= 1
                    ticket.queued = False
                    ticket.state = AdmissionState.ACTIVE
                return True, "ok", ticket

            ticket.cancel_event.wait(min(0.02, remaining))

    def get_ticket(self, ticket_id: str) -> Optional[AdmissionTicket]:
        with self._lock:
            return self._tickets.get(ticket_id)

    def cancel(self, ticket_id: str) -> bool:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None or ticket.state not in (
                AdmissionState.QUEUED,
                AdmissionState.ACTIVE,
            ):
                return False
            ticket.cancel_event.set()
            if ticket.state is AdmissionState.ACTIVE:
                ticket.state = AdmissionState.CANCELLING
            else:
                ticket.state = AdmissionState.CANCELLED
            return True

    def release(self, identity: str) -> None:
        with self._lock:
            ticket_ids = list(reversed(self._identity_tickets.get(identity, [])))
            ticket_id = next(
                (
                    candidate
                    for candidate in ticket_ids
                    if self._tickets[candidate].state
                    in (AdmissionState.ACTIVE, AdmissionState.CANCELLING)
                ),
                None,
            )
        if ticket_id is not None:
            self.release_ticket(ticket_id)

    def release_ticket(self, ticket_id: str) -> bool:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                return False
            if ticket.state is AdmissionState.QUEUED:
                self._leave_queue(ticket)
                self._finish_ticket(ticket, AdmissionState.CANCELLED)
                return True
            if ticket.state is AdmissionState.CANCELLED:
                if ticket.queued:
                    self._leave_queue(ticket)
                    self._finish_ticket(ticket, AdmissionState.CANCELLED)
                    return True
                return False
            if ticket.state not in (
                AdmissionState.ACTIVE,
                AdmissionState.CANCELLING,
            ):
                return False
            final_state = (
                AdmissionState.CANCELLED
                if ticket.state is AdmissionState.CANCELLING
                else AdmissionState.RELEASED
            )
            self._identity_counts[ticket.identity] -= 1
            if self._identity_counts[ticket.identity] == 0:
                del self._identity_counts[ticket.identity]
            self._finish_ticket(ticket, final_state)
        self._semaphore.release()
        return True

    def _leave_queue(self, ticket: AdmissionTicket) -> None:
        if not ticket.queued:
            return
        ticket.queued = False
        self._current_queue -= 1
        self._identity_counts[ticket.identity] -= 1
        if self._identity_counts[ticket.identity] == 0:
            del self._identity_counts[ticket.identity]

    def _finish_ticket(self, ticket: AdmissionTicket, state: AdmissionState) -> None:
        ticket.state = state
        self._tickets.pop(ticket.id, None)
        identity_tickets = self._identity_tickets.get(ticket.identity, [])
        if ticket.id in identity_tickets:
            identity_tickets.remove(ticket.id)
        if not identity_tickets:
            self._identity_tickets.pop(ticket.identity, None)


def _get_client_identity() -> str:
    """Extract a stable identity string for the client."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def require_capacity(controller: AdmissionController):
    """
    Flask decorator to enforce admission control on a route.
    Returns 429 or 503 with a Retry-After header on rejection.
    If the decorated route processes an upload session (session_id in kwargs or
    view_args), marks the session as active while processing so retention
    sweeps avoid deleting chunks referenced by active workers.
    """

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            identity = _get_client_identity()
            acquired, reason, ticket = controller.acquire_ticket(identity)
            g.admission_ticket = ticket

            if not acquired:
                from metrics import collector as metrics_collector

                endpoint = request.url_rule.rule if request.url_rule else request.path
                metrics_collector.record_rejection(reason, endpoint)

                decision = admission_decision(reason, controller.timeout_seconds)
                response = admission_error_response(decision)
                response.status_code = decision.status
                response.headers["Retry-After"] = str(decision.retry_after_seconds)
                return response

            try:
                return f(*args, **kwargs)
            finally:
                if ticket is not None:
                    controller.release_ticket(ticket.id)
                else:
                    controller.release(identity)
        return wrapped
    return decorator


@contextmanager
def admit_verified_work(
    controller: AdmissionController,
    identity: str,
    *,
    endpoint: str | None = None,
) -> Iterator[None]:
    """Acquire an admission slot for *identity* after pre-flight verification.

    Use this instead of ``@require_capacity`` when a request must first pass
    authentication and content-hash verification before consuming processing
    capacity.  Raises ``AdmissionRejectedError`` on backpressure.
    """
    acquired, reason = controller.acquire(identity)
    if not acquired:
        try:
            from metrics import collector as metrics_collector

            metrics_collector.record_rejection(reason, endpoint or "verified_work")
        except Exception:
            pass
        status_code = 429 if reason == "identity_limit" else 503
        retry_after = int(controller.timeout_seconds * 2) or 5
        raise AdmissionRejectedError(
            reason=reason,
            status_code=status_code,
            retry_after=retry_after,
        )
    try:
        yield
    finally:
        controller.release(identity)
