from __future__ import annotations

try:
    from analytics.config import (
        ANALYTICS_CONFIG_SCHEMA_VERSION,
        ANALYTICS_ROLLOUT_PHASE,
        AnalyticsConfig,
        AnalyticsFeatureFlags,
        AnalyticsLimits,
        AnalyticsPersistenceConfig,
        AnalyticsRolloutConfig,
        CryptoDomainVersion,
        ExportConfig,
        SamplingConfig,
        load_analytics_config,
    )
except Exception:
    pass

try:
    from analytics.events import (
        ANALYTICS_EVENT_SCHEMA_VERSION,
        EVENT_ALLOWLIST,
        EVENT_CATEGORIES,
        EventAllowlist,
        EventCategory,
        EventLifecycleState,
        EventOperationStatus,
        EventPayload,
        TrackedEvent,
        create_event,
        event_is_allowed,
        transition_event_state,
    )
except Exception:
    pass

try:
    from analytics.consent import (
        CONSENT_GRACE_PERIOD_SECONDS,
        CONSENT_SCHEMA_VERSION,
        ConsentDecision,
        ConsentManager,
        ConsentSource,
        ConsentState,
        ConsentStatus,
        DEFAULT_CONSENT_STATE,
    )
except Exception:
    pass

try:
    from analytics.session_protection import (
        MAX_REPLAY_WINDOW_SECONDS,
        NONCE_TTL_SECONDS,
        REPLAY_PROTECTION_VERSION,
        SessionReplayError,
        SessionReplayGuard,
        SessionReplayOutcome,
    )
except Exception:
    pass

try:
    from analytics.sampling import (
        SAMPLING_DOMAIN_VERSION,
        SamplingDecision,
        SamplingOutcome,
        Sampler,
        compute_sampling_token,
        deterministic_sample_decision,
    )
except Exception:
    pass

try:
    from analytics.redaction import (
        CRYPTO_DOMAIN_VERSION,
        DEFAULT_CAP_BYTES,
        DEFAULT_MAX_DEPTH,
        DEFAULT_MAX_TOTAL_NODES,
        DURABLE_LEAK_CATEGORIES,
        PROOF_PAYLOAD_KEY_HINTS,
        RedactionConfig,
        RedactionEngine,
        RedactionOutcome,
        RedactionPatterns,
        SENSITIVE_FIELD_CATEGORIES,
        WALLET_SIGNATURE_KEY_HINTS,
        WITNESS_MEDIA_KEY_HINTS,
        cap_value_bytes,
        stable_encode_key,
        versioned_domain_tag,
    )
except Exception:
    pass

try:
    from analytics.log_processor import (
        EXPORT_LOG_VERSION,
        ErrorTelemetryConfig,
        LogEntry,
        LogProcessor,
        export_json_logs,
        import_json_logs,
        sanitize_error_context,
        validate_log_export_safety,
    )
except Exception:
    pass

try:
    from analytics.metrics_collector import (
        AnalyticsOperationalMetrics,
        MetricDomain,
        RecoverySignal,
        SaturationSignal,
        operational_collector,
    )
except Exception:
    pass

try:
    from analytics.export_manager import (
        ALLOWED_TENANT_EXPORT_CLASSES,
        DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES,
        EXPORT_FORMAT_VERSION,
        EXPORT_POLICY_DEFAULT,
        ExportArtifact,
        ExportedRecordClassBinding,
        ExportManager,
        ExportMaterialExclusionError,
        ExportPolicy,
        ManifestVerificationError,
        RedactionPolicyBinding,
        TENANT_CLASS_FIELD_ALLOWLISTS,
        TENANT_EXPORT_MANIFEST_DOMAIN_TAG,
        TENANT_MANIFEST_SCHEMA_VERSION,
        TenantExportBundle,
        TenantExportManifest,
        assert_class_records_safe_by_construction,
        build_tenant_export_manifest,
        verify_tenant_export_manifest,
    )
except Exception:
    try:
        from backend.analytics.export_manager import (
            ALLOWED_TENANT_EXPORT_CLASSES,
            DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES,
            EXPORT_FORMAT_VERSION,
            EXPORT_POLICY_DEFAULT,
            ExportArtifact,
            ExportedRecordClassBinding,
            ExportManager,
            ExportMaterialExclusionError,
            ExportPolicy,
            ManifestVerificationError,
            RedactionPolicyBinding,
            TENANT_CLASS_FIELD_ALLOWLISTS,
            TENANT_EXPORT_MANIFEST_DOMAIN_TAG,
            TENANT_MANIFEST_SCHEMA_VERSION,
            TenantExportBundle,
            TenantExportManifest,
            assert_class_records_safe_by_construction,
            build_tenant_export_manifest,
            verify_tenant_export_manifest,
        )
    except Exception:
        pass

try:
    from analytics.analytics_engine import (
        AnalyticsEngine,
        AnalyticsError,
        EngineHealthSnapshot,
        RequestContext,
        get_engine,
        set_engine,
    )
except Exception:
    pass

try:
    from analytics.routes import register_analytics_routes
except Exception:
    pass

__all__ = [
    "ANALYTICS_CONFIG_SCHEMA_VERSION",
    "ANALYTICS_ROLLOUT_PHASE",
    "AnalyticsConfig",
    "AnalyticsFeatureFlags",
    "AnalyticsLimits",
    "AnalyticsPersistenceConfig",
    "AnalyticsRolloutConfig",
    "CryptoDomainVersion",
    "ExportConfig",
    "SamplingConfig",
    "load_analytics_config",
    "ANALYTICS_EVENT_SCHEMA_VERSION",
    "EVENT_ALLOWLIST",
    "EVENT_CATEGORIES",
    "EventAllowlist",
    "EventCategory",
    "EventLifecycleState",
    "EventOperationStatus",
    "EventPayload",
    "TrackedEvent",
    "create_event",
    "event_is_allowed",
    "transition_event_state",
    "CONSENT_GRACE_PERIOD_SECONDS",
    "CONSENT_SCHEMA_VERSION",
    "ConsentDecision",
    "ConsentManager",
    "ConsentSource",
    "ConsentState",
    "ConsentStatus",
    "DEFAULT_CONSENT_STATE",
    "MAX_REPLAY_WINDOW_SECONDS",
    "NONCE_TTL_SECONDS",
    "REPLAY_PROTECTION_VERSION",
    "SessionReplayError",
    "SessionReplayGuard",
    "SessionReplayOutcome",
    "SAMPLING_DOMAIN_VERSION",
    "SamplingDecision",
    "SamplingOutcome",
    "Sampler",
    "compute_sampling_token",
    "deterministic_sample_decision",
    "CRYPTO_DOMAIN_VERSION",
    "DEFAULT_CAP_BYTES",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_TOTAL_NODES",
    "DURABLE_LEAK_CATEGORIES",
    "PROOF_PAYLOAD_KEY_HINTS",
    "RedactionConfig",
    "RedactionEngine",
    "RedactionOutcome",
    "RedactionPatterns",
    "SENSITIVE_FIELD_CATEGORIES",
    "WALLET_SIGNATURE_KEY_HINTS",
    "WITNESS_MEDIA_KEY_HINTS",
    "cap_value_bytes",
    "stable_encode_key",
    "versioned_domain_tag",
    "EXPORT_LOG_VERSION",
    "ErrorTelemetryConfig",
    "LogEntry",
    "LogProcessor",
    "export_json_logs",
    "import_json_logs",
    "sanitize_error_context",
    "validate_log_export_safety",
    "AnalyticsOperationalMetrics",
    "MetricDomain",
    "RecoverySignal",
    "SaturationSignal",
    "operational_collector",
    "ALLOWED_TENANT_EXPORT_CLASSES",
    "DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES",
    "EXPORT_FORMAT_VERSION",
    "ExportArtifact",
    "ExportedRecordClassBinding",
    "ExportManager",
    "ExportMaterialExclusionError",
    "ExportPolicy",
    "EXPORT_POLICY_DEFAULT",
    "ManifestVerificationError",
    "RedactionPolicyBinding",
    "TENANT_CLASS_FIELD_ALLOWLISTS",
    "TENANT_EXPORT_MANIFEST_DOMAIN_TAG",
    "TENANT_MANIFEST_SCHEMA_VERSION",
    "TenantExportBundle",
    "TenantExportManifest",
    "assert_class_records_safe_by_construction",
    "build_tenant_export_manifest",
    "verify_tenant_export_manifest",
    "AnalyticsEngine",
    "AnalyticsError",
    "EngineHealthSnapshot",
    "RequestContext",
    "get_engine",
    "set_engine",
    "register_analytics_routes",
]
