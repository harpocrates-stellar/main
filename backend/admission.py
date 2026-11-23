import contextlib
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Dict, List, Optional, Tuple

from flask import g, request, jsonify


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


class AdmissionRejectedError(Exception):
    """Raised when admission control rejects work due to backpressure."""

    def __init__(self, reason: str, status_code: int, retry_after: int):
        super().__init__(f"admission rejected: {reason}")
        self.reason = reason
        self.status_code = status_code
        self.retry_after = retry_after


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
        self._active_sessions: Dict[str, int] = {}
        self._semaphore = threading.Semaphore(max_concurrent)

    def acquire(self, identity: str, session_id: str | None = None) -> Tuple[bool, str]:
        """
        Attempt to acquire a concurrency slot.
        Optionally associates the execution with an upload session ID.
        Returns (True, "ok") if successful, or (False, reason) if rejected.
        """
        success, reason = self._acquire_slot(identity)
        if success and session_id:
            self.acquire_session(session_id)
        return success, reason

    def _acquire_slot(self, identity: str) -> Tuple[bool, str]:
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

    def release(self, identity: str, session_id: str | None = None) -> None:
        """
        Release a previously acquired concurrency slot.
        Optionally releases an associated upload session reference.
        """
        if session_id:
            self.release_session(session_id)
        with self._lock:
            return self._reserved_storage.get(identity, 0)

    def acquire_session(self, session_id: str) -> None:
        """Register an active worker reference to an upload session.

        While an upload session is referenced by one or more active workers,
        its chunks are protected from retention cleanup or expiration purges.
        """
        if not session_id:
            return
        with self._lock:
            self._active_sessions[session_id] = (
                self._active_sessions.get(session_id, 0) + 1
            )

    def release_session(self, session_id: str) -> None:
        """Release an active worker reference to an upload session."""
        if not session_id:
            return
        with self._lock:
            count = self._active_sessions.get(session_id, 0) - 1
            if count <= 0:
                self._active_sessions.pop(session_id, None)
            else:
                self._active_sessions[session_id] = count

    def is_session_active(self, session_id: str) -> bool:
        """Return whether an upload session is currently referenced by active workers."""
        if not session_id:
            return False
        with self._lock:
            return self._active_sessions.get(session_id, 0) > 0

    def get_active_sessions(self) -> set[str]:
        """Return a snapshot set of upload session IDs referenced by active workers."""
        with self._lock:
            return set(self._active_sessions.keys())

    @contextlib.contextmanager
    def active_session(self, session_id: str):
        """Context manager to hold an active worker session reference."""
        self.acquire_session(session_id)
        try:
            yield
        finally:
            self.release_session(session_id)


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
            session_id = kwargs.get("session_id")
            if not session_id and hasattr(request, "view_args") and request.view_args:
                session_id = request.view_args.get("session_id")

            acquired, reason = controller.acquire(identity, session_id=session_id)
            
            if not acquired:
                from metrics import collector as metrics_collector

                endpoint = request.url_rule.rule if request.url_rule else request.path
                metrics_collector.record_rejection(reason, endpoint)

                status_code = 429 if reason == "identity_limit" else 503
                response = jsonify({
                    "error": "service overloaded",
                    "reason": reason,
                })
                response.status_code = status_code
                response.headers["Retry-After"] = str(int(controller.timeout_seconds * 2) or 5)
                return response

            try:
                return f(*args, **kwargs)
            finally:
                controller.release(identity, session_id=session_id)
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
