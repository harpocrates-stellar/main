#!/usr/bin/env python3
"""Test that analytics integration doesn't break existing functionality."""

import os
import sys
import unittest
from unittest.mock import Mock, patch

def test_analytics_compatibility():
    """Test that analytics integration is compatible with existing Flask app."""
    
    print("Testing Analytics Compatibility with Existing App...")
    
    # Mock the dependencies that might not be available
    with patch.dict('sys.modules', {
        'flask': Mock(),
        'flask_cors': Mock(), 
        'numpy': Mock(),
        'psycopg': Mock(),
        'dotenv': Mock()
    }):
        
        try:
            # Test that analytics modules can be imported
            from analytics.config import AnalyticsConfig, load_analytics_config
            from analytics.redaction import RedactionEngine, RedactionPatterns
            from analytics.analytics_engine import AnalyticsEngine
            from analytics.middleware import AnalyticsMiddleware
            
            print("✓ Analytics modules imported successfully")
            
            # Test configuration with analytics disabled
            os.environ['ANALYTICS_ENABLED'] = 'false'
            config = load_analytics_config()
            assert config.enabled == False
            print("✓ Analytics can be disabled via configuration")
            
            # Test that disabled analytics don't interfere
            analytics_engine = AnalyticsEngine(config)
            
            # These should be no-ops when disabled
            correlation_id = analytics_engine.process_request("GET", "/test", 200, 0.1)
            assert correlation_id == "disabled"
            
            analytics_engine.record_performance("test_op", 0.1)  # Should not crash
            
            print("✓ Disabled analytics don't interfere with operations")
            
            # Test analytics middleware with disabled analytics
            middleware = AnalyticsMiddleware(config=config)
            assert middleware.analytics_engine is None or not middleware.analytics_engine._enabled
            
            print("✓ Analytics middleware handles disabled state correctly")
            
            return True
            
        except Exception as e:
            print(f"✗ Compatibility test failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def test_existing_logging_compatibility():
    """Test that existing logging functionality still works with analytics."""
    
    print("\nTesting Existing Logging Compatibility...")
    
    try:
        # Import existing logging utilities
        from logging_utils import redact_sensitive, log_structured, REDACTED_VALUE
        
        # Test existing redaction functionality
        test_data = {
            "authorization": "Bearer secret_token",
            "proof": "sensitive_proof_data",
            "normal_field": "safe_data"
        }
        
        redacted = redact_sensitive(test_data)
        
        # Verify existing redaction still works
        assert redacted["authorization"] == REDACTED_VALUE
        assert redacted["proof"] == REDACTED_VALUE
        assert redacted["normal_field"] == "safe_data"
        
        print("✓ Existing logging redaction functionality preserved")
        
        return True
        
    except Exception as e:
        print(f"✗ Logging compatibility test failed: {e}")
        return False


def test_existing_metrics_compatibility():
    """Test that existing metrics functionality still works."""
    
    print("\nTesting Existing Metrics Compatibility...")
    
    try:
        from metrics import collector as metrics_collector
        
        # Test existing metrics functionality
        metrics_collector.reset()
        
        # Record a request like the existing system does
        metrics_collector.record_request(
            method="GET",
            endpoint="/test",
            status=200,
            duration_seconds=0.1
        )
        
        # Generate metrics
        metrics_output = metrics_collector.generate_prometheus_metrics()
        assert isinstance(metrics_output, str)
        assert "harpocrates_" in metrics_output
        
        print("✓ Existing metrics functionality preserved")
        
        return True
        
    except Exception as e:
        print(f"✗ Metrics compatibility test failed: {e}")
        return False


def test_app_structure_preservation():
    """Test that app structure and imports are preserved."""
    
    print("\nTesting App Structure Preservation...")
    
    try:
        # Check that our analytics imports don't break the app module structure
        import logging_utils
        import metrics  
        import config
        
        # Verify core functions exist
        assert hasattr(logging_utils, 'redact_sensitive')
        assert hasattr(metrics, 'collector')
        assert hasattr(config, 'load_config')
        
        print("✓ Existing app structure preserved")
        
        # Check that analytics imports are optional
        try:
            import analytics
            print("✓ Analytics module available")
        except ImportError:
            print("! Analytics module not available (expected if dependencies missing)")
        
        return True
        
    except Exception as e:
        print(f"✗ App structure test failed: {e}")
        return False


def main():
    """Run all compatibility tests."""
    
    print("=" * 60)
    print("ANALYTICS COMPATIBILITY TESTS")
    print("=" * 60)
    
    tests = [
        test_analytics_compatibility,
        test_existing_logging_compatibility, 
        test_existing_metrics_compatibility,
        test_app_structure_preservation
    ]
    
    results = []
    for test_func in tests:
        try:
            results.append(test_func())
        except Exception as e:
            print(f"✗ Test {test_func.__name__} crashed: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print("COMPATIBILITY TEST SUMMARY") 
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"✅ ALL COMPATIBILITY TESTS PASSED ({passed}/{total})")
        print("\nThe analytics system is fully compatible with existing functionality!")
        print("Existing CI tests should pass once dependencies are installed.")
        return True
    else:
        print(f"❌ {total - passed} COMPATIBILITY TEST(S) FAILED ({passed}/{total} passed)")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)