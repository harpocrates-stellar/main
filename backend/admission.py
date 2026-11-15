import re
import threading
from functools import wraps
from pathlib import Path
from typing import Dict, Optional, Tuple

from flask import g, jsonify, request

import register_auth

_TENANT_HEADER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


class TenantUploadBudgetExceededError(Exception):
    """Raised when a tenant exceeds its temporary upload storage budget."""

    def __init__(
        self,
        message: str = "temporary upload storage budget exceeded",
        *,
        budget_bytes: int = 0,
        requested_bytes: int = 0,
    ) -> None:
        super().__init__(message)
        self.budget_bytes = max(0, int(budget_bytes))
        self.requested_bytes = max(0, int(requested_bytes))


class TenantUploadBudgetReservation:
    """Idempotent handle tracking temporary upload disk bytes reserved for one tenant."""

    def __init__(
        self,
        manager: "TenantUploadBudgetManager",
        tenant_id: str,
        reserved_bytes: int,
    ) -> None:
        self._manager = manager
        self.tenant_id = tenant_id
        self._reserved_bytes = max(0, int(reserved_bytes))
        self._released = False

    @property
    def reserved_bytes(self) -> int:
        return 0 if self._released else self._reserved_bytes

    @property
    def released(self) -> bool:
        return self._released

    def grow(self, additional_bytes: int) -> int:
        delta = int(additional_bytes)
        if delta < 0:
            raise ValueError("additional_bytes must be non-negative")
        if self._released:
            raise RuntimeError("cannot grow a released upload budget reservation")
        if delta == 0:
            return self._reserved_bytes
        self._manager._reserve_delta(self.tenant_id, delta)
        self._reserved_bytes += delta
        return self._reserved_bytes

    def ensure_reserved(self, total_bytes: int) -> int:
        needed = max(0, int(total_bytes))
        if self._released:
            raise RuntimeError("cannot update a released upload budget reservation")
        if needed <= self._reserved_bytes:
            return self._reserved_bytes
        return self.grow(needed - self._reserved_bytes)

    def release(self) -> int:
        if self._released:
            return 0
        self._released = True
        freed = self._reserved_bytes
        self._reserved_bytes = 0
        if freed > 0:
            self._manager._release_delta(self.tenant_id, freed)
        return freed

    def __enter__(self) -> "TenantUploadBudgetReservation":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


class TenantUploadBudgetManager:
    """Thread-safe per-tenant temporary upload disk budget tracker."""

    def __init__(self, budget_bytes: int) -> None:
        self.budget_bytes = max(0, int(budget_bytes))
        self._lock = threading.Lock()
        self._tenant_bytes: Dict[str, int] = {}
        self._session_chunks: Dict[str, Tuple[str, Dict[int, int], Optional[str]]] = {}

    def _reserve_delta(self, tenant_id: str, delta: int) -> None:
        if delta <= 0:
            return
        with self._lock:
            current = self._tenant_bytes.get(tenant_id, 0)
            if self.budget_bytes > 0 and current + delta > self.budget_bytes:
                raise TenantUploadBudgetExceededError(
                    budget_bytes=self.budget_bytes,
                    requested_bytes=delta,
                )
            self._tenant_bytes[tenant_id] = current + delta

    def _release_delta(self, tenant_id: str, delta: int) -> None:
        if delta <= 0:
            return
        with self._lock:
            current = self._tenant_bytes.get(tenant_id, 0)
            remaining = max(0, current - delta)
            if remaining == 0:
                self._tenant_bytes.pop(tenant_id, None)
            else:
                self._tenant_bytes[tenant_id] = remaining

    def reconcile_missing_sessions(self) -> None:
        with self._lock:
            stale_ids = [
                sid
                for sid, (_tenant, _chunks, dir_str) in self._session_chunks.items()
                if dir_str and not Path(dir_str).exists()
            ]
        for sid in stale_ids:
            self.release_session(sid)

    def reserve(
        self,
        tenant_id: str,
        initial_bytes: int = 0,
    ) -> TenantUploadBudgetReservation:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        requested = int(initial_bytes)
        if requested < 0:
            raise ValueError("initial_bytes must be non-negative")
        self.reconcile_missing_sessions()
        if requested > 0:
            self._reserve_delta(tenant_id, requested)
        return TenantUploadBudgetReservation(self, tenant_id, requested)

    def record_session_chunk(
        self,
        session_id: str,
        tenant_id: str,
        chunk_index: int,
        chunk_bytes: int,
        *,
        session_dir: Optional[str] = None,
        request_reservation: Optional[TenantUploadBudgetReservation] = None,
    ) -> None:
        """Persist exact chunk disk usage against the tenant's session budget."""
        actual = max(0, int(chunk_bytes))
        with self._lock:
            existing = self._session_chunks.get(session_id)
            effective_tenant = existing[0] if existing is not None else tenant_id
            chunks_map = dict(existing[1]) if existing is not None else {}
            prev_chunk_bytes = chunks_map.get(chunk_index, 0)
            net_delta = actual - prev_chunk_bytes

            req_credit = 0
            if (
                request_reservation is not None
                and not request_reservation.released
                and request_reservation.tenant_id == effective_tenant
            ):
                req_credit = request_reservation.reserved_bytes

            current = self._tenant_bytes.get(effective_tenant, 0)
            projected = max(0, current - req_credit + net_delta)
            if self.budget_bytes > 0 and net_delta > 0 and projected > self.budget_bytes:
                raise TenantUploadBudgetExceededError(
                    budget_bytes=self.budget_bytes,
                    requested_bytes=net_delta,
                )

            if req_credit > 0 and request_reservation is not None:
                request_reservation._released = True
                request_reservation._reserved_bytes = 0

            if projected == 0:
                self._tenant_bytes.pop(effective_tenant, None)
            else:
                self._tenant_bytes[effective_tenant] = projected

            chunks_map[chunk_index] = actual
            resolved_dir = session_dir or (existing[2] if existing is not None else None)
            self._session_chunks[session_id] = (effective_tenant, chunks_map, resolved_dir)

    def release_session(self, session_id: str) -> int:
        """Release all staged chunk bytes held for *session_id*."""
        with self._lock:
            entry = self._session_chunks.pop(session_id, None)
            if entry is None:
                return 0
            tenant_id, chunks_map, _dir = entry
            freed = sum(chunks_map.values())
            if freed > 0:
                current = self._tenant_bytes.get(tenant_id, 0)
                remaining = max(0, current - freed)
                if remaining == 0:
                    self._tenant_bytes.pop(tenant_id, None)
                else:
                    self._tenant_bytes[tenant_id] = remaining
            return freed

    def reserved_bytes(self, tenant_id: str) -> int:
        with self._lock:
            return self._tenant_bytes.get(tenant_id, 0)

    def active_tenant_count(self) -> int:
        with self._lock:
            return len(self._tenant_bytes)


def resolve_upload_tenant_id(config=None) -> str:
    """Resolve a tenant storage bucket key without cross-tenant spoofing."""
    principal = getattr(g, "register_principal", None)
    if principal is not None and getattr(principal, "owner", None):
        return f"principal:{principal.owner}"

    scoped_keys = getattr(config, "register_scoped_keys", ()) if config is not None else ()
    legacy_key = getattr(config, "register_api_key", None) if config is not None else None
    auth_header = request.headers.get("Authorization", "")
    if scoped_keys and auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):].strip()
        resolved = register_auth.authenticate(
            token,
            legacy_key=legacy_key,
            scoped_keys=scoped_keys,
        )
        if resolved is not None and resolved.owner:
            return f"principal:{resolved.owner}"

    raw_tenant = (request.headers.get("X-Tenant-ID") or "").strip()
    if raw_tenant and _TENANT_HEADER_RE.fullmatch(raw_tenant):
        return f"tenant:{raw_tenant}"

    return f"client:{_get_client_identity()}"


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

        return True, "ok"

    def release(self, identity: str) -> None:
        """
        Release a previously acquired concurrency slot.
        """
        with self._lock:
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
