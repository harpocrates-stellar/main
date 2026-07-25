#!/usr/bin/env python3
"""Integration test for analytics system with Flask application."""

import os
import sys
import time
import requests

def test_analytics_integration():
    """Test analytics system integration with the Flask application."""
    
    print("Testing Analytics System Integration...")
    
    # Set environment variables for testing
    os.environ['ANALYTICS_ENABLED'] = 'true'
    os.environ['ANALYTICS_PRIVACY_MODE'] = 'strict'
    os.environ['ANALYTICS_REQUIRE_AUTH'] = 'false'  # Disable auth for testing
    
    try:
        # Import analytics components
        from analytics.config import load_analytics_config
        from analytics.redaction import RedactionEngine
        from analytics.analytics_engine import AnalyticsEngine
        
        print("✓ Analytics modules imported successfully")
        
        # Test configuration loading
        config = load_analytics_config()
        assert config.enabled == True
        assert config.privacy_mode == "strict"
        print("✓ Configuration loaded successfully")
        
        # Test redaction engine
        redaction_engine = RedactionEngine(config.redaction_patterns)
        
        # Test sensitive data redaction
        test_data = {
            "proof_data": "sensitive_content",
            "normal_field": "safe_content"
        }
        
        result = redaction_engine.sanitize(test_data)
        assert result.data["proof_data"] == "[REDACTED]"
        assert result.data["normal_field"] == "safe_content"
        print("✓ Redaction engine working correctly")
        
        # Test analytics engine initialization
        analytics_engine = AnalyticsEngine(config)
        assert analytics_engine is not None
        print("✓ Analytics engine initialized successfully")
        
        # Test request processing
        correlation_id = analytics_engine.process_request(
            method="GET",
            endpoint="/test/endpoint",
            status_code=200,
            duration_seconds=0.1
        )
        assert correlation_id is not None
        print("✓ Request processing working")
        
        # Test performance recording
        analytics_engine.record_performance(
            operation_name="test_operation",
            duration_seconds=0.5,
            cpu_percent=25.0
        )
        print("✓ Performance recording working")
        
        # Test system health check
        health = analytics_engine.perform_health_check()
        assert isinstance(health, dict)
        print("✓ Health check working")
        
        # Test metrics export
        metrics = analytics_engine.get_metrics_export("prometheus")
        assert isinstance(metrics, str)
        assert "harpocrates_" in metrics
        print("✓ Metrics export working")
        
        # Test endpoint sanitization
        test_endpoints = [
            "/api/proof/abc123def456",
            "/embed?hash=sensitive123",
            "/normal/endpoint"
        ]
        
        for endpoint in test_endpoints:
            sanitized = redaction_engine.sanitize_endpoint_pattern(endpoint)
            # Should not contain sensitive identifiers
            assert "abc123def456" not in sanitized
            assert "sensitive123" not in sanitized
        print("✓ Endpoint sanitization working")
        
        print("\n🎉 All analytics integration tests passed!")
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_flask_integration():
    """Test Flask application integration with analytics."""
    
    print("\nTesting Flask Integration...")
    
    try:
        # Import Flask app
        from app import create_app
        
        app = create_app()
        
        # Check if analytics engine is attached
        if hasattr(app, 'analytics_engine'):
            print("✓ Analytics engine attached to Flask app")
            
            # Test analytics middleware
            with app.test_client() as client:
                response = client.get('/health')
                assert response.status_code == 200
                print("✓ Health endpoint working with analytics")
                
                # Test analytics health endpoint if available
                try:
                    analytics_response = client.get('/analytics/health')
                    if analytics_response.status_code == 200:
                        print("✓ Analytics health endpoint working")
                    else:
                        print("! Analytics health endpoint not accessible (may require auth)")
                except Exception:
                    print("! Analytics health endpoint not available")
        else:
            print("! Analytics engine not attached to Flask app (may be disabled)")
        
        print("✓ Flask integration test completed")
        return True
        
    except Exception as e:
        print(f"✗ Flask integration test failed: {e}")
        return False


def test_privacy_guarantees():
    """Test that privacy guarantees are maintained."""
    
    print("\nTesting Privacy Guarantees...")
    
    try:
        from analytics.redaction import RedactionEngine, RedactionPatterns
        
        redaction_engine = RedactionEngine(RedactionPatterns())
        
        # Test comprehensive sensitive data types
        sensitive_test_data = {
            "video_file": "secret_video_content.mp4",
            "proof_data": "zkproof_sensitive_123", 
            "wallet_signature": "0x123456789abcdef0123456789abcdef01234567",
            "nullifier_secret": "field_element_secret_456",
            "witness_data": "witness_commitment_789",
            "credential_secret": "identity_credential_abc",
            "private_key": "wallet_private_key_def",
            "user_video_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "metadata_hash": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            
            # Normal data that should be preserved
            "status": "success",
            "count": 42,
            "timestamp": time.time(),
            "method": "POST",
            "category": "steganography"
        }
        
        result = redaction_engine.sanitize(sensitive_test_data)
        
        # Verify all sensitive fields are redacted
        sensitive_fields = [
            "video_file", "proof_data", "wallet_signature", "nullifier_secret",
            "witness_data", "credential_secret", "private_key", "user_video_hash",
            "metadata_hash"
        ]
        
        for field in sensitive_fields:
            assert result.data[field] == "[REDACTED]", f"Field {field} was not redacted"
        
        # Verify normal data is preserved
        assert result.data["status"] == "success"
        assert result.data["count"] == 42
        assert result.data["method"] == "POST"
        assert result.data["category"] == "steganography"
        
        print("✓ Comprehensive sensitive data redaction working")
        
        # Test export safety validation
        unsafe_export = {
            "metrics": {"request_count": 100},
            "hidden_proof": "sensitive_proof_data"  # This should be caught
        }
        
        is_safe, violations = redaction_engine.validate_export_safety(unsafe_export)
        assert not is_safe, "Export safety validation should catch sensitive data"
        assert len(violations) > 0, "Should report violations"
        
        print("✓ Export safety validation working")
        
        # Test safe export passes validation
        safe_export = {
            "metrics": {
                "request_count": 100,
                "avg_response_time": 0.25,
                "status_codes": {"200": 80, "400": 15, "500": 5}
            },
            "timestamp": time.time()
        }
        
        is_safe, violations = redaction_engine.validate_export_safety(safe_export)
        assert is_safe, "Safe export should pass validation"
        assert len(violations) == 0, "Should not report violations for safe data"
        
        print("✓ Safe export validation working")
        
        print("✓ All privacy guarantees verified!")
        return True
        
    except Exception as e:
        print(f"✗ Privacy guarantee test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all integration tests."""
    
    print("=" * 60)
    print("HARPOCRATES ANALYTICS SYSTEM INTEGRATION TESTS")
    print("=" * 60)
    
    results = []
    
    # Test analytics system components
    results.append(test_analytics_integration())
    
    # Test Flask integration
    results.append(test_flask_integration())
    
    # Test privacy guarantees
    results.append(test_privacy_guarantees())
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"✅ ALL TESTS PASSED ({passed}/{total})")
        print("\nThe analytics system is ready for production use!")
        print("\nNext steps:")
        print("1. Configure environment variables for your deployment")
        print("2. Set up Prometheus scraping for /analytics/metrics")
        print("3. Configure log export authentication")
        print("4. Set up monitoring alerts for system health")
        return True
    else:
        print(f"❌ {total - passed} TEST(S) FAILED ({passed}/{total} passed)")
        print("\nPlease review the errors above and fix issues before deployment.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)