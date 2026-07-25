"""Configuration management for privacy-safe analytics system."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class RedactionPatterns:
    """Patterns for identifying sensitive data in various contexts."""
    
    # Field name patterns that indicate sensitive data
    field_patterns: List[str] = field(default_factory=lambda: [
        # Cryptographic data patterns
        r'nullifier',
        r'.*secret',
        r'.*proof',
        r'.*witness',
        r'.*commitment',
        r'field_element',
        r'circuit_input',
        r'proof_data',
        r'witness_data',
        
        # Wallet and signature patterns  
        r'.*signature',
        r'private_key',
        r'secret_key',
        r'wallet',
        r'authorization',
        
        # Credential and identity patterns
        r'credential',
        r'identity',
        r'silent_witness',
        r'credentialsecret',
        r'nullifiersecret',
        
        # File and content patterns
        r'.*video',
        r'.*content',
        r'.*payload',
        r'file_data',
        r'metadata_hash',
        r'video_hash',
        r'source_hash',
        
        # Network and transaction patterns
        r'tx_.*',
        r'transaction',
        r'stellar',
        r'address',
    ])
    
    # Value patterns that indicate sensitive content
    value_patterns: List[str] = field(default_factory=lambda: [
        # Hex patterns that might be hashes or keys
        r'^[0-9a-fA-F]{32,}$',
        # Base64 patterns that might be encoded data
        r'^[A-Za-z0-9+/]{20,}={0,2}$',
        # UUID patterns
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    ])
    
    # File path patterns that contain sensitive information
    file_patterns: List[str] = field(default_factory=lambda: [
        r'.*\.mp4$',
        r'.*\.avi$', 
        r'.*\.mov$',
        r'.*\.mkv$',
        r'.*video.*',
        r'.*proof.*',
        r'.*witness.*',
        r'.*secret.*',
    ])


@dataclass(frozen=True)
class MetricsConfig:
    """Configuration for metrics collection and export."""
    
    enabled: bool = True
    collection_interval_seconds: float = 60.0
    retention_days: int = 30
    
    # Endpoint pattern sanitization
    sanitize_endpoints: bool = True
    max_endpoint_patterns: int = 1000
    
    # Performance monitoring
    enable_latency_tracking: bool = True
    enable_resource_tracking: bool = True
    enable_operation_categorization: bool = True
    
    # Export configuration
    prometheus_enabled: bool = True
    prometheus_path: str = "/analytics/metrics"
    
    # Rate limiting for metrics endpoints
    max_requests_per_hour: int = 3600
    max_export_size_mb: int = 100


@dataclass(frozen=True)  
class LogConfig:
    """Configuration for log processing and sanitization."""
    
    enabled: bool = True
    max_log_level: str = "INFO"
    retention_days: int = 7
    
    # Context sanitization
    sanitize_stack_traces: bool = True
    sanitize_request_headers: bool = True
    max_context_size_bytes: int = 10240
    
    # Error classification
    classify_errors: bool = True
    track_error_patterns: bool = True
    
    # Export configuration
    json_export_enabled: bool = True
    json_export_path: str = "/analytics/logs"
    
    # Correlation and tracing
    generate_correlation_ids: bool = True
    correlation_id_header: str = "X-Correlation-ID"


@dataclass(frozen=True)
class ExportConfig:
    """Configuration for analytics data export and verification."""
    
    enabled: bool = True
    
    # Export formats
    prometheus_format: bool = True
    json_format: bool = True
    
    # Compression and batching
    compress_exports: bool = True
    max_batch_size: int = 10000
    export_interval_minutes: int = 5
    
    # Privacy verification
    verify_before_export: bool = True
    fail_on_sensitive_data: bool = True
    
    # Audit and integrity
    create_audit_trail: bool = True
    verify_data_integrity: bool = True
    
    # External analytics integration
    external_endpoints: List[str] = field(default_factory=list)
    external_auth_tokens: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RetentionConfig:
    """Configuration for data retention and purging."""
    
    # Retention periods
    metrics_retention_days: int = 30
    logs_retention_days: int = 7
    audit_retention_days: int = 90
    
    # Purging configuration  
    enable_automatic_purging: bool = True
    purge_check_interval_hours: int = 24
    
    # Privacy compliance
    honor_deletion_requests: bool = True
    purge_on_privacy_violation: bool = True


@dataclass(frozen=True)
class SecurityConfig:
    """Security configuration for analytics system."""
    
    # Authentication
    require_authentication: bool = True
    api_key_header: str = "X-Analytics-API-Key"
    
    # Rate limiting
    enable_rate_limiting: bool = True
    requests_per_minute: int = 60
    burst_limit: int = 120
    
    # Encryption
    encrypt_storage: bool = True
    encrypt_transmission: bool = True
    
    # Access control
    allowed_client_ips: List[str] = field(default_factory=list)
    require_tls: bool = True
    
    # Audit and monitoring
    audit_access_attempts: bool = True
    monitor_suspicious_activity: bool = True


@dataclass(frozen=True) 
class AnalyticsConfig:
    """Complete configuration for the privacy-safe analytics system."""
    
    # Core system configuration
    enabled: bool = True
    environment: str = "development"
    
    # Component configurations
    redaction_patterns: RedactionPatterns = field(default_factory=RedactionPatterns)
    metrics_config: MetricsConfig = field(default_factory=MetricsConfig)
    logging_config: LogConfig = field(default_factory=LogConfig)
    export_config: ExportConfig = field(default_factory=ExportConfig)
    retention_config: RetentionConfig = field(default_factory=RetentionConfig)
    security_config: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Privacy and compliance
    privacy_mode: str = "strict"  # strict, standard, minimal
    compliance_reporting: bool = True
    
    # Performance and scaling
    async_processing: bool = True
    max_concurrent_operations: int = 100
    processing_timeout_seconds: float = 30.0


def load_analytics_config() -> AnalyticsConfig:
    """Load analytics configuration from environment variables and defaults."""
    
    # Core configuration
    enabled = _bool_env("ANALYTICS_ENABLED", True)
    environment = os.getenv("ANALYTICS_ENVIRONMENT", os.getenv("APP_ENV", "development"))
    privacy_mode = os.getenv("ANALYTICS_PRIVACY_MODE", "strict").lower()
    
    if privacy_mode not in ("strict", "standard", "minimal"):
        raise ValueError(f"Invalid privacy mode: {privacy_mode}")
    
    # Component configurations with environment overrides
    metrics_config = MetricsConfig(
        enabled=_bool_env("ANALYTICS_METRICS_ENABLED", True),
        collection_interval_seconds=_float_env("ANALYTICS_METRICS_INTERVAL", 60.0),
        retention_days=_int_env("ANALYTICS_METRICS_RETENTION_DAYS", 30),
        prometheus_enabled=_bool_env("ANALYTICS_PROMETHEUS_ENABLED", True),
        prometheus_path=os.getenv("ANALYTICS_PROMETHEUS_PATH", "/analytics/metrics"),
        max_requests_per_hour=_int_env("ANALYTICS_METRICS_RATE_LIMIT", 3600),
    )
    
    logging_config = LogConfig(
        enabled=_bool_env("ANALYTICS_LOGS_ENABLED", True),
        max_log_level=os.getenv("ANALYTICS_LOG_LEVEL", "INFO").upper(),
        retention_days=_int_env("ANALYTICS_LOGS_RETENTION_DAYS", 7),
        sanitize_stack_traces=_bool_env("ANALYTICS_SANITIZE_STACK_TRACES", True),
        sanitize_request_headers=_bool_env("ANALYTICS_SANITIZE_HEADERS", True),
        json_export_enabled=_bool_env("ANALYTICS_JSON_EXPORT_ENABLED", True),
        json_export_path=os.getenv("ANALYTICS_JSON_EXPORT_PATH", "/analytics/logs"),
    )
    
    export_config = ExportConfig(
        enabled=_bool_env("ANALYTICS_EXPORT_ENABLED", True),
        prometheus_format=_bool_env("ANALYTICS_EXPORT_PROMETHEUS", True),
        json_format=_bool_env("ANALYTICS_EXPORT_JSON", True),
        compress_exports=_bool_env("ANALYTICS_COMPRESS_EXPORTS", True),
        verify_before_export=_bool_env("ANALYTICS_VERIFY_EXPORTS", True),
        fail_on_sensitive_data=_bool_env("ANALYTICS_FAIL_ON_SENSITIVE", True),
    )
    
    security_config = SecurityConfig(
        require_authentication=_bool_env("ANALYTICS_REQUIRE_AUTH", True),
        api_key_header=os.getenv("ANALYTICS_API_KEY_HEADER", "X-Analytics-API-Key"),
        enable_rate_limiting=_bool_env("ANALYTICS_RATE_LIMITING", True),
        requests_per_minute=_int_env("ANALYTICS_RATE_LIMIT_RPM", 60),
        encrypt_storage=_bool_env("ANALYTICS_ENCRYPT_STORAGE", True),
        encrypt_transmission=_bool_env("ANALYTICS_ENCRYPT_TRANSMISSION", True),
        require_tls=_bool_env("ANALYTICS_REQUIRE_TLS", True),
        audit_access_attempts=_bool_env("ANALYTICS_AUDIT_ACCESS", True),
    )
    
    return AnalyticsConfig(
        enabled=enabled,
        environment=environment,
        privacy_mode=privacy_mode,
        metrics_config=metrics_config,
        logging_config=logging_config,
        export_config=export_config,
        security_config=security_config,
        compliance_reporting=_bool_env("ANALYTICS_COMPLIANCE_REPORTING", True),
        async_processing=_bool_env("ANALYTICS_ASYNC_PROCESSING", True),
        max_concurrent_operations=_int_env("ANALYTICS_MAX_CONCURRENT", 100),
        processing_timeout_seconds=_float_env("ANALYTICS_PROCESSING_TIMEOUT", 30.0),
    )


def _bool_env(name: str, default: bool) -> bool:
    """Parse boolean environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    """Parse integer environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"{name} must be non-negative")
    return parsed


def _float_env(name: str, default: float) -> float:
    """Parse float environment variable."""
    value = os.getenv(name) 
    if value is None:
        return default
    parsed = float(value)
    if parsed < 0:
        raise ValueError(f"{name} must be non-negative")
    return parsed


def _str_env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Get string environment variable."""
    return os.getenv(name, default)