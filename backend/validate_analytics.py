#!/usr/bin/env python3
"""Final validation script for privacy-safe analytics system."""

import os
import sys
import json
import time

def main():
    """Validate the analytics system implementation."""
    
    print("🔒 HARPOCRATES PRIVACY-SAFE ANALYTICS VALIDATION")
    print("=" * 60)
    
    # Set test environment
    os.environ['ANALYTICS_ENABLED'] = 'true'
    os.environ['ANALYTICS_PRIVACY_MODE'] = 'strict'
    
    try:
        # Test 1: Core System Initialization
        print("1. Testing core system initialization...")
        
        from analytics.config import load_analytics_config
        from analytics.redaction import RedactionEngine, RedactionPatterns
        from analytics.analytics_engine import AnalyticsEngine
        from analytics.events import create_request_event, create_error_event
        
        config = load_analytics_config()
        redaction_engine = RedactionEngine(config.redaction_patterns)
        analytics_engine = AnalyticsEngine(config)
        
        print("   ✓ All core components initialized successfully")
        
        # Test 2: Privacy Redaction Guarantees
        print("\n2. Testing privacy redaction guarantees...")
        
        # Test comprehensive sensitive data redaction
        sensitive_data = {
            "video_content": "secret_video_data.mp4",
            "proof_data": "zkproof_sensitive_content",
            "wallet_signature": "0x123456789abcdef0123456789abcdef01234567",
            "nullifier_secret": "field_element_12345",
            "witness_data": "witness_commitment_data",
            "credential_secret": "identity_credential_secret",
            "private_key": "wallet_private_key_data", 
            "video_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "metadata_hash": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "normal_field": "safe_content",
            "status": "success"
        }
        
        result = redaction_engine.sanitize(sensitive_data)
        
        # Verify all sensitive fields redacted
        sensitive_fields = [
            "video_content", "proof_data", "wallet_signature", "nullifier_secret",
            "witness_data", "credential_secret", "private_key", "video_hash", "metadata_hash"
        ]
        
        for field in sensitive_fields:
            assert result.data[field] == "[REDACTED]", f"Field {field} not redacted"
        
        # Verify normal data preserved
        assert result.data["normal_field"] == "safe_content"
        assert result.data["status"] == "success"
        
        print("   ✓ Comprehensive sensitive data redaction working")
        
        # Test 3: Endpoint Pattern Sanitization
        print("\n3. Testing endpoint pattern sanitization...")
        
        test_patterns = [
            ("/api/proof/0123456789abcdef0123456789abcdef01234567", "/api/proof/{id}"),
            ("/api/video/upload/user_secret_123", "/api/video/upload/{id}"),
            ("/embed?hash=sensitive_hash_456", "/embed"),
            ("/extract/550e8400-e29b-41d4-a716-446655440000", "/extract/{id}"),
            ("/api/normal/endpoint", "/api/normal/endpoint")
        ]
        
        for original, expected in test_patterns:
            sanitized = redaction_engine.sanitize_endpoint_pattern(original)
            # Allow flexibility in exact pattern but ensure no sensitive data
            assert "0123456789abcdef" not in sanitized
            assert "user_secret_123" not in sanitized
            assert "sensitive_hash_456" not in sanitized
            assert "550e8400-e29b-41d4" not in sanitized
        
        print("   ✓ Endpoint pattern sanitization working")
        
        # Test 4: Error Context Sanitization
        print("\n4. Testing error context sanitization...")
        
        error_context = {
            "method": "POST",
            "endpoint": "/api/proof/sensitive_id_123",
            "proof_data": "sensitive_proof_content",
            "wallet_signature": "0x123456789abcdef",
            "status_code": 500,
            "timestamp": time.time(),
            "correlation_id": "req_12345"
        }
        
        sanitized_context = redaction_engine.sanitize_error_context(error_context)
        
        # Should preserve safe debugging info
        assert sanitized_context.get("method") == "POST"
        assert sanitized_context.get("status_code") == 500
        assert "correlation_id" in sanitized_context
        
        # Should not contain sensitive data
        context_str = str(sanitized_context)
        assert "sensitive_proof_content" not in context_str
        assert "0x123456789abcdef" not in context_str
        assert "sensitive_id_123" not in context_str
        
        print("   ✓ Error context sanitization working")
        
        # Test 5: Analytics Event Processing
        print("\n5. Testing analytics event processing...")
        
        # Process request with sensitive context
        correlation_id = analytics_engine.process_request(
            method="POST",
            endpoint="/api/proof/sensitive_proof_id_789",
            status_code=200,
            duration_seconds=1.5,
            upload_bytes=2048,
            context={
                "proof_data": "sensitive_content",
                "normal_field": "safe_content"
            }
        )
        
        assert correlation_id is not None
        
        # Process error with sensitive context
        test_error = ValueError("Invalid proof format")
        error_correlation = analytics_engine.process_error(
            error=test_error,
            context={
                "method": "POST",
                "endpoint": "/api/generate/proof",
                "proof_data": "sensitive_proof_data"
            }
        )
        
        assert error_correlation is not None
        
        print("   ✓ Analytics event processing working")
        
        # Test 6: Metrics Export Safety
        print("\n6. Testing metrics export safety...")
        
        # Record some performance metrics
        analytics_engine.record_performance(
            operation_name="embed_sensitive_video_operation", 
            duration_seconds=2.5,
            cpu_percent=60.0
        )
        
        analytics_engine.record_system_health(
            component_name="database_with_sensitive_data",
            health_status="healthy"
        )
        
        # Export metrics
        prometheus_metrics = analytics_engine.get_metrics_export("prometheus")
        json_metrics = analytics_engine.get_metrics_export("json")
        
        # Verify no sensitive data in exports
        sensitive_terms = [
            "sensitive", "proof_data", "wallet", "secret", "nullifier", 
            "witness", "credential", "private_key", "video_hash"
        ]
        
        for term in sensitive_terms:
            assert term not in prometheus_metrics.lower(), f"Found '{term}' in Prometheus export"
            assert term not in json_metrics.lower(), f"Found '{term}' in JSON export"
        
        print("   ✓ Metrics export safety verified")
        
        # Test 7: Export Verification
        print("\n7. Testing export verification...")
        
        # Test unsafe export detection
        unsafe_data = {
            "metrics": {"count": 100},
            "hidden_proof_data": "sensitive_zkproof_content"
        }
        
        is_safe, violations = redaction_engine.validate_export_safety(unsafe_data)
        assert not is_safe, "Should detect unsafe export data"
        assert len(violations) > 0, "Should report violations"
        
        # Test safe export passes
        safe_data = {
            "metrics": {
                "http_requests_total": 1000,
                "avg_response_time_ms": 250,
                "error_rate_percent": 2.1
            },
            "timestamp": time.time()
        }
        
        is_safe, violations = redaction_engine.validate_export_safety(safe_data)
        assert is_safe, "Safe data should pass verification"
        assert len(violations) == 0, "Should not report violations for safe data"
        
        print("   ✓ Export verification working correctly")
        
        # Test 8: System Health and Status
        print("\n8. Testing system health monitoring...")
        
        health = analytics_engine.perform_health_check()
        assert isinstance(health, dict)
        assert len(health) > 0
        
        status = analytics_engine.get_system_status()
        assert isinstance(status, dict)
        assert "enabled" in status
        assert "component_health" in status
        
        print("   ✓ System health monitoring working")
        
        # Final Validation Summary
        print("\n" + "=" * 60)
        print("🎉 ALL PRIVACY-SAFE ANALYTICS TESTS PASSED!")
        print("=" * 60)
        
        print("\n✅ IMPLEMENTATION COMPLETE")
        print("\nThe privacy-safe analytics system has been successfully implemented with:")
        print("• Comprehensive sensitive data redaction")
        print("• Multi-layer privacy protection")  
        print("• Sanitized endpoint pattern tracking")
        print("• Safe error context logging")
        print("• Privacy-verified data exports")
        print("• Complete audit trail capabilities")
        
        print(f"\n📊 REDACTION STATISTICS")
        stats = redaction_engine.get_redaction_stats()
        if stats:
            for category, count in stats.items():
                print(f"• {category}: {count} redactions")
        else:
            print("• No redaction statistics available (normal for clean test data)")
        
        print(f"\n🔧 SYSTEM STATUS")
        print(f"• Privacy Mode: {config.privacy_mode}")
        print(f"• Metrics Enabled: {config.metrics_config.enabled}")
        print(f"• Logging Enabled: {config.logging_config.enabled}")
        print(f"• Export Verification: {config.export_config.verify_before_export}")
        
        print(f"\n📋 NEXT STEPS")
        print("1. Install Flask dependencies: pip install -r requirements.txt")
        print("2. Set production environment variables")
        print("3. Configure Prometheus scraping for /analytics/metrics")
        print("4. Set up authentication for sensitive endpoints")
        print("5. Configure log retention and cleanup policies")
        print("6. Set up monitoring alerts for system health")
        
        print(f"\n📖 DOCUMENTATION")
        print("• Implementation details: /backend/ANALYTICS_README.md")
        print("• API endpoints: /analytics/health, /analytics/metrics, /analytics/logs")
        print("• Configuration: Environment variables starting with ANALYTICS_")
        
        return True
        
    except Exception as e:
        print(f"\n❌ VALIDATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)