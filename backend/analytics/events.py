"""Analytics event models and types for privacy-safe telemetry."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class EventType(Enum):
    """Types of analytics events that can be processed."""
    
    # Request and response events
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    
    # Performance events
    PERFORMANCE = "performance"
    RESOURCE_USAGE = "resource_usage"
    
    # System events
    SYSTEM = "system"
    HEALTH_CHECK = "health_check"
    
    # Operational events
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    CONFIGURATION = "configuration"
    
    # Privacy and security events
    PRIVACY_VIOLATION = "privacy_violation"
    ACCESS_ATTEMPT = "access_attempt"
    RATE_LIMIT = "rate_limit"


@dataclass
class AnalyticsEvent:
    """Base analytics event with privacy-safe data structure."""
    
    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    data: Dict[str, Any] = field(default_factory=dict)
    
    # Event classification
    sensitivity_level: str = "standard"  # minimal, standard, sensitive
    requires_redaction: bool = True
    
    # Event metadata  
    source_component: Optional[str] = None
    operation_category: Optional[str] = None
    
    def is_metric(self) -> bool:
        """Check if this event represents a metric."""
        return self.event_type in {
            EventType.REQUEST,
            EventType.RESPONSE, 
            EventType.PERFORMANCE,
            EventType.RESOURCE_USAGE,
            EventType.HEALTH_CHECK
        }
    
    def is_log(self) -> bool:
        """Check if this event represents a log entry."""
        return self.event_type in {
            EventType.ERROR,
            EventType.SYSTEM,
            EventType.STARTUP,
            EventType.SHUTDOWN,
            EventType.CONFIGURATION,
            EventType.PRIVACY_VIOLATION,
            EventType.ACCESS_ATTEMPT,
            EventType.RATE_LIMIT
        }
    
    def is_sensitive(self) -> bool:
        """Check if this event may contain sensitive data."""
        return self.sensitivity_level in ("sensitive", "high") or self.requires_redaction
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "sensitivity_level": self.sensitivity_level,
            "requires_redaction": self.requires_redaction,
            "source_component": self.source_component,
            "operation_category": self.operation_category,
            "data": self.data.copy()
        }


@dataclass
class RequestEvent(AnalyticsEvent):
    """Analytics event for HTTP request processing."""
    
    event_type: EventType = EventType.REQUEST
    
    # Sanitized request information (never includes payloads or sensitive headers)
    method: Optional[str] = None
    endpoint_pattern: Optional[str] = None  # Sanitized endpoint pattern only
    status_code: Optional[int] = None
    
    # Performance metrics
    latency_ms: Optional[float] = None
    size_bytes: Optional[int] = None  # Without content identification
    
    # Operational context
    user_agent_category: Optional[str] = None  # Categorized, not raw user agent
    client_ip_hash: Optional[str] = None  # Hashed IP for rate limiting analysis
    
    def __post_init__(self):
        """Ensure request events are properly categorized."""
        self.source_component = "http_handler"
        self.operation_category = "http_request"
        
        # Determine sensitivity based on endpoint and status
        if self.status_code and self.status_code >= 400:
            self.sensitivity_level = "sensitive"
        elif self.endpoint_pattern and any(pattern in (self.endpoint_pattern or "") 
                                         for pattern in ["/embed", "/extract", "/proof"]):
            self.sensitivity_level = "sensitive"
        else:
            self.sensitivity_level = "standard"


@dataclass  
class ErrorEvent(AnalyticsEvent):
    """Analytics event for error occurrences with sanitized context."""
    
    event_type: EventType = EventType.ERROR
    sensitivity_level: str = "sensitive"  # Errors are always sensitive
    
    # Error classification
    error_type: Optional[str] = None
    error_category: Optional[str] = None
    
    # Sanitized context (never includes payloads or sensitive data)
    sanitized_context: Dict[str, Any] = field(default_factory=dict)
    stack_trace_hash: Optional[str] = None  # Hashed stack trace for pattern analysis
    
    # Request context (sanitized)
    request_method: Optional[str] = None
    endpoint_pattern: Optional[str] = None  # Sanitized pattern only
    
    def __post_init__(self):
        """Ensure error events are properly categorized."""
        self.source_component = "error_handler"
        self.operation_category = "error_processing"
        self.requires_redaction = True


@dataclass
class PerformanceEvent(AnalyticsEvent):
    """Analytics event for performance monitoring without content correlation."""
    
    event_type: EventType = EventType.PERFORMANCE
    
    # Operation categorization (never specific content)
    operation_type: Optional[str] = None  # e.g., "steganography", "cryptography", "database"
    operation_duration_ms: Optional[float] = None
    
    # Resource utilization
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None
    io_operations: Optional[int] = None
    
    # Performance metrics
    throughput_ops_per_sec: Optional[float] = None
    queue_depth: Optional[int] = None
    
    def __post_init__(self):
        """Ensure performance events are categorized correctly.""" 
        self.source_component = "performance_monitor"
        self.operation_category = "performance_monitoring"
        self.sensitivity_level = "minimal"  # Performance data is least sensitive
        self.requires_redaction = False


@dataclass
class SystemEvent(AnalyticsEvent):
    """Analytics event for system state and health monitoring."""
    
    event_type: EventType = EventType.SYSTEM
    
    # System state
    component_name: Optional[str] = None
    health_status: Optional[str] = None  # healthy, degraded, unhealthy
    
    # System metrics
    uptime_seconds: Optional[float] = None
    active_connections: Optional[int] = None
    pending_operations: Optional[int] = None
    
    # Configuration state
    config_version: Optional[str] = None
    feature_flags: Dict[str, bool] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure system events are categorized correctly."""
        self.source_component = "system_monitor"
        self.operation_category = "system_monitoring"
        self.sensitivity_level = "minimal"
        self.requires_redaction = False


@dataclass
class PrivacyEvent(AnalyticsEvent):
    """Analytics event for privacy violations and compliance issues."""
    
    event_type: EventType = EventType.PRIVACY_VIOLATION
    sensitivity_level: str = "high"  # Privacy events require special handling
    
    # Privacy violation details
    violation_type: Optional[str] = None
    violation_severity: Optional[str] = None  # low, medium, high, critical
    
    # Detection context
    detection_component: Optional[str] = None
    detection_rule: Optional[str] = None
    
    # Remediation
    remediation_action: Optional[str] = None
    remediation_status: Optional[str] = None
    
    def __post_init__(self):
        """Ensure privacy events are handled with maximum care."""
        self.source_component = "privacy_monitor"
        self.operation_category = "privacy_compliance"
        self.requires_redaction = True


def create_request_event(
    method: str,
    endpoint_pattern: str, 
    status_code: int,
    latency_ms: float,
    size_bytes: Optional[int] = None,
    correlation_id: Optional[str] = None
) -> RequestEvent:
    """Create a sanitized request event from HTTP request data."""
    
    event = RequestEvent(
        method=method.upper() if method else "UNKNOWN",
        endpoint_pattern=endpoint_pattern,
        status_code=status_code,
        latency_ms=max(0.0, latency_ms),
        size_bytes=max(0, size_bytes) if size_bytes is not None else None,
    )
    
    if correlation_id:
        event.correlation_id = correlation_id
        
    return event


def create_error_event(
    error_type: str,
    error_category: str,
    sanitized_context: Dict[str, Any],
    correlation_id: Optional[str] = None
) -> ErrorEvent:
    """Create a sanitized error event from exception data."""
    
    event = ErrorEvent(
        error_type=error_type,
        error_category=error_category,
        sanitized_context=sanitized_context.copy(),
    )
    
    if correlation_id:
        event.correlation_id = correlation_id
        
    return event


def create_performance_event(
    operation_type: str,
    duration_ms: float,
    cpu_percent: Optional[float] = None,
    memory_mb: Optional[float] = None,
    correlation_id: Optional[str] = None
) -> PerformanceEvent:
    """Create a performance monitoring event."""
    
    event = PerformanceEvent(
        operation_type=operation_type,
        operation_duration_ms=max(0.0, duration_ms),
        cpu_percent=max(0.0, cpu_percent) if cpu_percent is not None else None,
        memory_mb=max(0.0, memory_mb) if memory_mb is not None else None,
    )
    
    if correlation_id:
        event.correlation_id = correlation_id
        
    return event


def create_system_event(
    component_name: str,
    health_status: str,
    uptime_seconds: Optional[float] = None,
    correlation_id: Optional[str] = None
) -> SystemEvent:
    """Create a system health monitoring event."""
    
    event = SystemEvent(
        component_name=component_name,
        health_status=health_status,
        uptime_seconds=max(0.0, uptime_seconds) if uptime_seconds is not None else None,
    )
    
    if correlation_id:
        event.correlation_id = correlation_id
        
    return event