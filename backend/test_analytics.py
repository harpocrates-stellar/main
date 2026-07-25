"""Unit tests for privacy-safe analytics system."""

import time
from typing import Dict, Any

from analytics.redaction import RedactionEngine, RedactionPatterns
from analytics.events import (
    AnalyticsEvent, 
    EventType, 
    create_request_event, 
    create_error_event,
    create_performance_event
)
from analytics.config import AnalyticsConfig, MetricsConfig, LogConfig
from analytics.analytics_engine import AnalyticsEngine
from analytics.metrics_collector import PrivacySafeMetricsCollector


class TestRedactionEngine:
    """Test suite for RedactionEngine privacy guarantees."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.patterns = RedactionPatterns()
        self.redaction_engine = RedactionEngine(self.patterns)
    
    def test_sensitive_field_redaction(self):
        """Test that sensitive field names are properly redacted."""
        
        test_data = {
            "proof_data": "sensitive_proof_content",
            "wallet_signature": "0x123456789abcdef",
            "nullifier_secret": "field_element_12345",
            "video_hash": "abcd1234efgh5678",
            "normal_field": "safe_content"
        }
        
        result = self.redaction_engine.sanitize(test_data)
        
        # Sensitive fields should be redacted
        assert result.data["proof_data"] == "[REDACTED]"
        assert result.data["wallet_signature"] == "[REDACTED]"
        assert result.data["nullifier_secret"] == "[REDACTED]"
        assert result.data["video_hash"] == "[REDACTED]"
        
        # Normal fields should remain
        assert result.data["normal_field"] == "safe_content"
        
        # Should report redactions
        assert result.has_redactions()
        assert len(result.redacted_fields) >= 4
    
    def test_sensitive_value_patterns(self):
        """Test that sensitive value patterns are detected."""
        
        test_data = {
            "id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  # 64-char hex
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # Base64-like
            "uuid": "550e8400-e29b-41d4-a716-446655440000",  # UUID
            "normal_id": "12345",  # Short, should be safe
            "message": "Hello world"  # Normal text
        }
        
        result = self.redaction_engine.sanitize(test_data)
        
        # Long hex should be redacted
        assert result.data["id"] == "[REDACTED]"
        # Base64 pattern should be redacted
        assert result.data["token"] == "[REDACTED]"
        # UUID should be redacted
        assert result.data["uuid"] == "[REDACTED]"
        
        # Short values should remain
        assert result.data["normal_id"] == "12345"
        assert result.data["message"] == "Hello world"
    
    def test_recursive_structure_sanitization(self):
        """Test that nested structures are recursively sanitized."""
        
        test_data = {
            "outer": {
                "proof_data": "sensitive_content",
                "inner": {
                    "wallet_signature": "0x123456789abcdef",
                    "safe_data": "normal_content"
                },
                "list_field": [
                    {"nullifier": "secret_value"},
                    {"normal": "safe_value"}
                ]
            }
        }
        
        result = self.redaction_engine.sanitize(test_data)
        
        # Check nested redaction
        assert result.data["outer"]["proof_data"] == "[REDACTED]"
        assert result.data["outer"]["inner"]["wallet_signature"] == "[REDACTED]"
        assert result.data["outer"]["inner"]["safe_data"] == "normal_content"
        assert result.data["outer"]["list_field"][0]["nullifier"] == "[REDACTED]"
        assert result.data["outer"]["list_field"][1]["normal"] == "safe_value"
    
    def test_endpoint_pattern_sanitization(self):
        """Test endpoint pattern sanitization removes sensitive identifiers."""
        
        test_cases = [
            ("/api/proof/0123456789abcdef0123456789abcdef01234567", "/api/proof/{id}"),
            ("/api/video/upload/user123", "/api/video/upload/{id}"),
            ("/embed?hash=abcd1234", "/embed"),
            ("/extract/550e8400-e29b-41d4-a716-446655440000", "/extract/{id}"),
            ("/api/normal/endpoint", "/api/normal/endpoint"),
        ]
        
        for original, expected in test_cases:
            sanitized = self.redaction_engine.sanitize_endpoint_pattern(original)
            assert sanitized == expected, f"Failed for {original}: got {sanitized}, expected {expected}"
    
    def test_error_context_sanitization(self):
        """Test error context sanitization preserves safe debugging info."""
        
        error_context = {
            "method": "POST",
            "endpoint": "/api/proof/abc123def456",
            "proof_data": "sensitive_proof_content",
            "wallet_signature": "0x123456789abcdef",
            "status_code": 500,
            "timestamp": time.time(),
            "correlation_id": "req_123456",
            "user_agent": "Mozilla/5.0..."
        }
        
        sanitized = self.redaction_engine.sanitize_error_context(error_context)
        
        # Safe fields should remain
        assert sanitized["method"] == "POST"
        assert sanitized["status_code"] == 500
        assert "timestamp" in sanitized
        assert "correlation_id" in sanitized
        
        # Endpoint should be sanitized
        assert sanitized["endpoint_pattern"] == "/api/proof/{id}"
        
        # Sensitive fields should not appear
        assert "proof_data" not in sanitized
        assert "wallet_signature" not in sanitized
    
    def test_export_safety_validation(self):
        """Test export safety validation catches sensitive data."""
        
        # Safe export data
        safe_data = {
            "metrics": {
                "http_requests_total": 1000,
                "avg_response_time": 0.25
            },
            "timestamp": time.time()
        }
        
        is_safe, violations = self.redaction_engine.validate_export_safety(safe_data)
        assert is_safe
        assert len(violations) == 0
        
        # Unsafe export data
        unsafe_data = {
            "metrics": {
                "http_requests_total": 1000,
                "proof_data": "sensitive_content"  # This should be caught
            },
            "timestamp": time.time()
        }
        
        is_safe, violations = self.redaction_engine.validate_export_safety(unsafe_data)
        assert not is_safe
        assert len(violations) > 0


class TestAnalyticsEvents:
    """Test suite for analytics event creation and classification."""
    
    def test_request_event_creation(self):
        """Test request event creation and classification."""
        
        # Normal request
        event = create_request_event(
            method="GET",
            endpoint_pattern="/api/health", 
            status_code=200,
            latency_ms=150.5,
            size_bytes=1024
        )
        
        assert event.event_type == EventType.REQUEST
        assert event.method == "GET"
        assert event.endpoint_pattern == "/api/health"
        assert event.status_code == 200
        assert event.latency_ms == 150.5
        assert event.size_bytes == 1024
        assert event.sensitivity_level == "standard"
        
        # Sensitive endpoint request
        sensitive_event = create_request_event(
            method="POST",
            endpoint_pattern="/api/proof/generate",
            status_code=500,
            latency_ms=2000.0
        )
        
        assert sensitive_event.sensitivity_level == "sensitive"
    
    def test_error_event_creation(self):
        """Test error event creation with proper classification."""
        
        error_context = {
            "method": "POST",
            "endpoint": "/api/embed",
            "status_code": 500,
            "correlation_id": "req_123"
        }
        
        event = create_error_event(
            error_type="ValueError",
            error_category="validation_error", 
            sanitized_context=error_context
        )
        
        assert event.event_type == EventType.ERROR
        assert event.error_type == "ValueError"
        assert event.error_category == "validation_error"
        assert event.sensitivity_level == "sensitive"  # Errors are always sensitive
        assert event.requires_redaction
    
    def test_performance_event_creation(self):
        """Test performance event creation without content correlation."""
        
        event = create_performance_event(
            operation_type="steganography",
            duration_ms=500.0,
            cpu_percent=45.5,
            memory_mb=128.0
        )
        
        assert event.event_type == EventType.PERFORMANCE
        assert event.operation_type == "steganography"
        assert event.operation_duration_ms == 500.0
        assert event.cpu_percent == 45.5
        assert event.memory_mb == 128.0
        assert event.sensitivity_level == "minimal"  # Performance data is least sensitive
        assert not event.requires_redaction


class TestMetricsCollector:
    """Test suite for privacy-safe metrics collection."""
    
    def setup_method(self):
        """Set up test fixtures."""
        config = MetricsConfig()
        redaction_engine = RedactionEngine(RedactionPatterns())
        self.collector = PrivacySafeMetricsCollector(config, redaction_engine)
    
    def test_request_metrics_collection(self):
        """Test HTTP request metrics collection with sanitized endpoints."""
        
        # Record some requests
        self.collector.record_request("GET", "/api/proof/abc123", 200, 0.150, 1024)
        self.collector.record_request("POST", "/api/embed", 201, 2.5, 5242880)
        self.collector.record_request("GET", "/api/proof/def456", 404, 0.050)
        
        # Get metrics summary
        summary = self.collector.get_metrics_summary()
        
        # Should have sanitized request counts
        assert len(summary["request_counts"]) > 0
        
        # Endpoints should be sanitized (no actual IDs)
        endpoint_patterns = [key[1] for key in summary["request_counts"].keys()]
        assert "/api/proof/{id}" in endpoint_patterns
        assert "/api/embed" in endpoint_patterns
        
        # Should not contain actual proof IDs
        for pattern in endpoint_patterns:
            assert "abc123" not in pattern
            assert "def456" not in pattern
    
    def test_operation_performance_tracking(self):
        """Test operation performance tracking without content details."""
        
        # Record various operations
        self.collector.record_operation_performance("embed_video", 2.5, 60.0, 256.0, 150)
        self.collector.record_operation_performance("generate_proof", 5.0, 80.0, 512.0, 75)
        self.collector.record_operation_performance("database_query", 0.1, 10.0, 64.0, 25)
        
        summary = self.collector.get_metrics_summary()
        
        # Should categorize operations generically
        assert "steganography" in summary["operation_counts"]
        assert "cryptography" in summary["operation_counts"] 
        assert "database" in summary["operation_counts"]
        
        # Should not contain specific operation details
        for category in summary["operation_counts"].keys():
            assert "embed_video" not in category
            assert "generate_proof" not in category
    
    def test_prometheus_export_format(self):
        """Test Prometheus metrics export format compliance."""
        
        # Record some data
        self.collector.record_request("GET", "/health", 200, 0.05)
        self.collector.record_operation_performance("health_check", 0.05, 5.0, 32.0)
        
        # Export to Prometheus format
        prometheus_output = self.collector.get_prometheus_metrics()
        
        # Should be valid Prometheus format
        assert "# HELP" in prometheus_output
        assert "# TYPE" in prometheus_output
        assert "harpocrates_http_requests_total" in prometheus_output
        
        # Should not contain sensitive data
        assert "proof" not in prometheus_output.lower()
        assert "wallet" not in prometheus_output.lower()
        assert "secret" not in prometheus_output.lower()
    
    def test_rate_limiting_metrics(self):
        """Test rate limiting violation tracking with anonymized clients."""
        
        # Record rate limit violations
        self.collector.record_rate_limit_violation("192.168.1.100", "/api/embed")
        self.collector.record_rate_limit_violation("10.0.0.5", "/api/proof/generate")
        
        summary = self.collector.get_metrics_summary()
        
        # Should have rate limit violations recorded
        assert len(summary["rate_limit_violations"]) > 0
        
        # Client IPs should be hashed, not exposed
        for key in summary["rate_limit_violations"].keys():
            assert "192.168.1.100" not in key
            assert "10.0.0.5" not in key


class TestAnalyticsEngine:
    """Test suite for analytics engine integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        config = AnalyticsConfig(
            enabled=True,
            privacy_mode="strict"
        )
        self.analytics_engine = AnalyticsEngine(config)
    
    def test_request_processing_with_privacy(self):
        """Test request processing maintains privacy guarantees."""
        
        # Process a request with sensitive context
        context = {
            "proof_data": "sensitive_proof_content",
            "wallet_signature": "0x123456789abcdef",
            "normal_field": "safe_content"
        }
        
        correlation_id = self.analytics_engine.process_request(
            method="POST",
            endpoint="/api/proof/abc123def456",
            status_code=200,
            duration_seconds=1.5,
            upload_bytes=2048,
            context=context
        )
        
        # Should return a correlation ID
        assert correlation_id is not None
        assert isinstance(correlation_id, str)
        
        # Verify metrics were recorded safely
        metrics = self.analytics_engine.get_metrics_export("json")
        assert metrics is not None
        
        # Sensitive data should not appear in metrics
        assert "proof_data" not in metrics
        assert "wallet_signature" not in metrics
        assert "abc123def456" not in metrics
    
    def test_error_processing_with_sanitization(self):
        """Test error processing sanitizes sensitive context."""
        
        test_error = ValueError("Invalid proof format")
        error_context = {
            "method": "POST", 
            "endpoint": "/api/proof/generate",
            "proof_data": "sensitive_proof_content",
            "status_code": 400
        }
        
        correlation_id = self.analytics_engine.process_error(
            error=test_error,
            context=error_context
        )
        
        # Should return correlation ID
        assert correlation_id is not None
        
        # Get error statistics
        error_stats = self.analytics_engine.log_processor.get_error_statistics()
        
        # Should have error categories without sensitive data
        assert "error_categories" in error_stats
        assert len(error_stats["error_categories"]) > 0
    
    def test_system_health_monitoring(self):
        """Test system health monitoring without sensitive component details."""
        
        # Record health for various components
        self.analytics_engine.record_system_health("database", "healthy", 50.0)
        self.analytics_engine.record_system_health("stellar_network", "degraded", 2000.0)
        self.analytics_engine.record_system_health("video_processor", "unhealthy")
        
        # Get system status
        status = self.analytics_engine.get_system_status()
        
        # Should have component health without exposing sensitive details
        assert "component_health" in status
        
        # Component names should be sanitized
        component_names = list(status["component_health"].keys())
        for name in component_names:
            assert "database" in name or "blockchain" in name or "service" in name
    
    def test_performance_monitoring_categories(self):
        """Test performance monitoring uses operation categories."""
        
        # Record performance for various operations
        self.analytics_engine.record_performance("embed_secret_video", 2.5, 60.0, 256.0)
        self.analytics_engine.record_performance("generate_witness_proof", 5.0, 80.0, 512.0)  
        self.analytics_engine.record_performance("query_user_database", 0.1, 10.0, 64.0)
        
        # Get system status
        status = self.analytics_engine.get_system_status()
        
        # Should categorize operations generically
        operation_counts = status.get("system_state", {})
        
        # Should not contain specific operation names with sensitive content
        status_str = str(status)
        assert "embed_secret_video" not in status_str
        assert "generate_witness_proof" not in status_str
        assert "query_user_database" not in status_str
    
    def test_cleanup_and_retention(self):
        """Test data cleanup respects retention policies."""
        
        # Process some events
        self.analytics_engine.process_request("GET", "/test", 200, 0.1)
        self.analytics_engine.record_performance("test_operation", 0.5)
        
        # Perform cleanup
        cleanup_stats = self.analytics_engine.cleanup_old_data()
        
        # Should return cleanup statistics
        assert isinstance(cleanup_stats, dict)
        assert "cleanup_timestamp" in cleanup_stats


class TestPrivacyProperties:
    """Test suite for verifying privacy properties hold across the system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = AnalyticsConfig(privacy_mode="strict")
        self.analytics_engine = AnalyticsEngine(self.config)
    
    def test_comprehensive_sensitive_data_redaction(self):
        """Property 1: Comprehensive Sensitive Data Redaction."""
        
        # Create data structure with various sensitive data types
        test_data = {
            "video_content": "binary_video_data_12345",
            "cryptographic_proof": {
                "proof_data": "zkproof_content",
                "witness_data": "witness_secret_123", 
                "nullifier": "nullifier_field_element"
            },
            "wallet_info": {
                "signature": "0x123456789abcdef0123456789abcdef01234567",
                "private_key": "secret_key_content"
            },
            "credentials": {
                "silent_witness": "credential_secret",
                "identity_commitment": "field_element_456"
            },
            "normal_data": {
                "status": "success",
                "timestamp": time.time()
            }
        }
        
        result = self.analytics_engine.redaction_engine.sanitize(test_data)
        
        # All sensitive data should be redacted while preserving structure
        assert result.data["video_content"] == "[REDACTED]"
        assert result.data["cryptographic_proof"]["proof_data"] == "[REDACTED]"
        assert result.data["cryptographic_proof"]["witness_data"] == "[REDACTED]"
        assert result.data["cryptographic_proof"]["nullifier"] == "[REDACTED]"
        assert result.data["wallet_info"]["signature"] == "[REDACTED]"
        assert result.data["wallet_info"]["private_key"] == "[REDACTED]"
        assert result.data["credentials"]["silent_witness"] == "[REDACTED]"
        assert result.data["credentials"]["identity_commitment"] == "[REDACTED]"
        
        # Normal data should remain intact
        assert result.data["normal_data"]["status"] == "success"
        assert isinstance(result.data["normal_data"]["timestamp"], float)
        
        # Should report redactions
        assert result.has_redactions()
        assert len(result.redacted_fields) >= 8
    
    def test_sanitized_endpoint_pattern_usage(self):
        """Property 2: Sanitized Endpoint Pattern Usage."""
        
        sensitive_endpoints = [
            "/api/proof/0123456789abcdef0123456789abcdef01234567",
            "/api/video/upload/user_sensitive_id_12345",
            "/embed?video_hash=abcdef123456&user=secret_user",
            "/extract/550e8400-e29b-41d4-a716-446655440000/metadata"
        ]
        
        for endpoint in sensitive_endpoints:
            # Process request through analytics
            self.analytics_engine.process_request(
                method="POST",
                endpoint=endpoint, 
                status_code=200,
                duration_seconds=1.0
            )
        
        # Get metrics to verify sanitization
        metrics = self.analytics_engine.get_metrics_export("json")
        
        # Should not contain any sensitive identifiers
        for endpoint in sensitive_endpoints:
            # Extract potential sensitive parts
            sensitive_parts = ["0123456789abcdef", "user_sensitive_id_12345", 
                             "abcdef123456", "secret_user", "550e8400-e29b-41d4"]
            for part in sensitive_parts:
                assert part not in metrics, f"Sensitive part '{part}' found in metrics"
    
    def test_error_context_sanitization(self):
        """Property 3: Error Context Sanitization."""
        
        # Create error with sensitive context
        error = ValueError("Invalid proof format")
        sensitive_context = {
            "method": "POST",
            "endpoint": "/api/proof/abc123def456",
            "proof_data": "sensitive_zkproof_content",
            "witness_data": "secret_witness_12345",
            "wallet_signature": "0x123456789abcdef",
            "status_code": 400,
            "timestamp": time.time(),
            "correlation_id": "req_123456"
        }
        
        # Process error through analytics
        correlation_id = self.analytics_engine.process_error(error, sensitive_context)
        
        # Get logs to verify sanitization
        logs = self.analytics_engine.get_logs_export()
        
        # Should not contain sensitive data
        assert "sensitive_zkproof_content" not in logs
        assert "secret_witness_12345" not in logs
        assert "0x123456789abcdef" not in logs
        assert "abc123def456" not in logs
        
        # Should contain safe debugging info
        assert "ValueError" in logs or correlation_id in logs
    
    def test_export_data_verification(self):
        """Property 7: Export Data Verification."""
        
        # Process some data with mixed sensitivity
        self.analytics_engine.process_request("GET", "/api/proof/sensitive123", 200, 1.0)
        self.analytics_engine.record_performance("embed_secret_operation", 2.0)
        
        # Export metrics
        metrics_export = self.analytics_engine.get_metrics_export("json")
        logs_export = self.analytics_engine.get_logs_export()
        
        # Verify exports contain no sensitive data
        sensitive_patterns = ["sensitive123", "secret", "proof_data", "wallet", 
                            "nullifier", "witness", "credential"]
        
        for pattern in sensitive_patterns:
            assert pattern not in metrics_export.lower(), f"Sensitive pattern '{pattern}' in metrics export"
            assert pattern not in logs_export.lower(), f"Sensitive pattern '{pattern}' in logs export"


def run_all_tests():
    """Run all analytics tests and report results."""
    
    test_classes = [
        TestRedactionEngine,
        TestAnalyticsEvents, 
        TestMetricsCollector,
        TestAnalyticsEngine,
        TestPrivacyProperties
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        test_instance = test_class()
        
        # Get all test methods
        test_methods = [method for method in dir(test_instance) 
                       if method.startswith('test_')]
        
        for test_method in test_methods:
            total_tests += 1
            
            try:
                # Run setup if available
                if hasattr(test_instance, 'setup_method'):
                    test_instance.setup_method()
                
                # Run the test
                getattr(test_instance, test_method)()
                passed_tests += 1
                print(f"✓ {test_class.__name__}.{test_method}")
                
            except Exception as e:
                failed_tests.append(f"{test_class.__name__}.{test_method}: {e}")
                print(f"✗ {test_class.__name__}.{test_method}: {e}")
    
    print(f"\nTest Results: {passed_tests}/{total_tests} passed")
    
    if failed_tests:
        print(f"\nFailed tests:")
        for failure in failed_tests:
            print(f"  - {failure}")
        return False
    else:
        print("All tests passed!")
        return True


if __name__ == "__main__":
    run_all_tests()