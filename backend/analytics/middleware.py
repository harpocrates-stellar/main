"""Flask middleware integration for privacy-safe analytics system."""

from __future__ import annotations

import time
import uuid
from functools import wraps
from typing import Any, Callable, Dict, Optional

from flask import Flask, Request, Response, g, request

from .analytics_engine import AnalyticsEngine
from .config import AnalyticsConfig


class AnalyticsMiddleware:
    """Flask middleware for automatic analytics integration."""
    
    def __init__(self, app: Optional[Flask] = None, config: Optional[AnalyticsConfig] = None):
        """Initialize analytics middleware.
        
        Args:
            app: Flask application instance
            config: Analytics configuration
        """
        
        self.analytics_engine: Optional[AnalyticsEngine] = None
        
        if config:
            self.analytics_engine = AnalyticsEngine(config)
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize middleware with Flask application.
        
        Args:
            app: Flask application instance
        """
        
        if not self.analytics_engine:
            # Load default configuration if not provided
            from .config import load_analytics_config
            config = load_analytics_config()
            if config.enabled:
                self.analytics_engine = AnalyticsEngine(config)
        
        if self.analytics_engine:
            # Register middleware hooks
            app.before_request(self._before_request)
            app.after_request(self._after_request)
            app.teardown_request(self._teardown_request)
            
            # Store reference in app for access elsewhere
            app.analytics_engine = self.analytics_engine
    
    def _before_request(self) -> None:
        """Process request start for analytics."""
        
        if not self.analytics_engine:
            return
        
        # Set up request tracking
        g.analytics_start_time = time.perf_counter()
        g.analytics_correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        g.analytics_request_size = request.content_length or 0
        
        # Record system health for critical endpoints
        if request.path in ['/health', '/metrics']:
            self.analytics_engine.record_system_health(
                component_name="web_service",
                health_status="healthy",
                response_time_ms=None
            )
    
    def _after_request(self, response: Response) -> Response:
        """Process request completion for analytics.
        
        Args:
            response: Flask response object
            
        Returns:
            Unmodified response object
        """
        
        if not self.analytics_engine:
            return response
        
        try:
            # Calculate request duration
            start_time = getattr(g, 'analytics_start_time', time.perf_counter())
            duration = time.perf_counter() - start_time
            
            # Get correlation ID
            correlation_id = getattr(g, 'analytics_correlation_id', str(uuid.uuid4()))
            
            # Add correlation ID to response headers
            response.headers['X-Correlation-ID'] = correlation_id
            
            # Sanitize endpoint pattern
            endpoint_pattern = request.url_rule.rule if request.url_rule else request.path
            
            # Create request context for analytics
            request_context = {
                'method': request.method,
                'endpoint': endpoint_pattern,
                'path': request.path,
                'status_code': response.status_code,
                'content_length': getattr(g, 'analytics_request_size', 0),
                'user_agent': request.headers.get('User-Agent', ''),
                'remote_addr': request.remote_addr,
                'timestamp': time.time(),
            }
            
            # Process request analytics
            self.analytics_engine.process_request(
                method=request.method,
                endpoint=endpoint_pattern,
                status_code=response.status_code,
                duration_seconds=duration,
                upload_bytes=getattr(g, 'analytics_request_size', None),
                correlation_id=correlation_id,
                context=request_context
            )
            
            # Record performance metrics for significant operations
            operation_name = self._classify_operation(request.method, endpoint_pattern)
            if operation_name != "unknown":
                self.analytics_engine.record_performance(
                    operation_name=operation_name,
                    duration_seconds=duration,
                    correlation_id=correlation_id
                )
        
        except Exception as e:
            # Don't let analytics errors affect the response
            self._handle_middleware_error(e, "after_request")
        
        return response
    
    def _teardown_request(self, exception: Optional[Exception]) -> None:
        """Process request teardown and any errors.
        
        Args:
            exception: Exception that occurred during request processing
        """
        
        if not self.analytics_engine:
            return
        
        try:
            if exception:
                # Get request context for error processing
                correlation_id = getattr(g, 'analytics_correlation_id', str(uuid.uuid4()))
                endpoint_pattern = request.url_rule.rule if request.url_rule else request.path
                
                error_context = {
                    'method': request.method,
                    'endpoint': endpoint_pattern,
                    'path': request.path,
                    'correlation_id': correlation_id,
                    'timestamp': time.time(),
                    'request_size': getattr(g, 'analytics_request_size', 0),
                }
                
                # Process error through analytics
                self.analytics_engine.process_error(
                    error=exception,
                    context=error_context,
                    correlation_id=correlation_id
                )
        
        except Exception as e:
            # Don't let analytics errors affect the response
            self._handle_middleware_error(e, "teardown_request")
    
    def _classify_operation(self, method: str, endpoint_pattern: str) -> str:
        """Classify request operation for performance monitoring.
        
        Args:
            method: HTTP method
            endpoint_pattern: URL endpoint pattern
            
        Returns:
            Operation category string
        """
        
        if not endpoint_pattern:
            return "unknown"
        
        endpoint_lower = endpoint_pattern.lower()
        
        # Steganography operations
        if 'embed' in endpoint_lower:
            return "steganography_embed"
        elif 'extract' in endpoint_lower:
            return "steganography_extract"
        
        # Cryptographic operations
        elif 'proof' in endpoint_lower:
            return "cryptography_proof"
        elif 'witness' in endpoint_lower:
            return "cryptography_witness"
        
        # Database operations
        elif 'events' in endpoint_lower and method in ['GET', 'POST']:
            return "database_query"
        
        # Network operations
        elif 'stellar' in endpoint_lower or 'blockchain' in endpoint_lower:
            return "network_stellar"
        
        # File operations
        elif method == 'POST' and any(term in endpoint_lower for term in ['upload', 'file']):
            return "storage_upload"
        
        # System operations
        elif endpoint_lower in ['/health', '/metrics', '/status']:
            return "system_monitoring"
        
        # Authentication operations
        elif 'auth' in endpoint_lower or 'login' in endpoint_lower:
            return "authentication"
        
        return "unknown"
    
    def _handle_middleware_error(self, error: Exception, context: str) -> None:
        """Handle middleware errors without affecting request processing.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
        """
        
        # Log to standard logging, not analytics logging to avoid recursion
        import logging
        logger = logging.getLogger("harpocrates.middleware.errors")
        logger.error(f"Analytics middleware error in {context}: {type(error).__name__}: {error}")


def monitor_operation(operation_name: str):
    """Decorator for monitoring specific operations with analytics.
    
    Args:
        operation_name: Name of the operation being monitored
        
    Returns:
        Decorator function
    """
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get analytics engine from Flask app
            analytics_engine = getattr(request._get_current_object().app, 'analytics_engine', None)
            
            if not analytics_engine:
                # No analytics engine, run function normally
                return func(*args, **kwargs)
            
            start_time = time.perf_counter()
            correlation_id = getattr(g, 'analytics_correlation_id', str(uuid.uuid4()))
            
            try:
                # Execute the function
                result = func(*args, **kwargs)
                
                # Record successful operation
                duration = time.perf_counter() - start_time
                analytics_engine.record_performance(
                    operation_name=operation_name,
                    duration_seconds=duration,
                    correlation_id=correlation_id
                )
                
                return result
                
            except Exception as e:
                # Record operation error
                duration = time.perf_counter() - start_time
                
                error_context = {
                    'operation_name': operation_name,
                    'duration_seconds': duration,
                    'correlation_id': correlation_id,
                    'function_name': func.__name__,
                    'timestamp': time.time(),
                }
                
                analytics_engine.process_error(
                    error=e,
                    context=error_context,
                    correlation_id=correlation_id
                )
                
                # Re-raise the exception
                raise
        
        return wrapper
    return decorator


def require_analytics_auth(api_key_header: str = "X-Analytics-API-Key"):
    """Decorator for requiring authentication on analytics endpoints.
    
    Args:
        api_key_header: Header name containing API key
        
    Returns:
        Decorator function
    """
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify
            
            # Get analytics engine from Flask app
            analytics_engine = getattr(request._get_current_object().app, 'analytics_engine', None)
            
            if not analytics_engine:
                return jsonify({"error": "Analytics system not available"}), 503
            
            # Check for API key
            api_key = request.headers.get(api_key_header)
            if not api_key:
                return jsonify({"error": "Authentication required"}), 401
            
            # Validate API key (basic validation - in production, use proper auth)
            expected_key = analytics_engine.config.security_config.api_key_header
            if api_key != expected_key:
                # Record security event
                analytics_engine.metrics_collector.record_security_event(
                    event_type="invalid_api_key",
                    severity="medium",
                    endpoint_pattern=request.path
                )
                return jsonify({"error": "Invalid API key"}), 403
            
            # Execute the function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def rate_limit_analytics(requests_per_minute: int = 60):
    """Decorator for rate limiting analytics endpoints.
    
    Args:
        requests_per_minute: Maximum requests allowed per minute
        
    Returns:
        Decorator function
    """
    
    # Simple in-memory rate limiting (in production, use Redis or similar)
    _rate_limit_cache: Dict[str, List[float]] = {}
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify
            
            # Get client identifier (IP address in this case)
            client_id = request.remote_addr or "unknown"
            current_time = time.time()
            
            # Clean old requests
            if client_id in _rate_limit_cache:
                cutoff_time = current_time - 60  # 1 minute ago
                _rate_limit_cache[client_id] = [
                    req_time for req_time in _rate_limit_cache[client_id] 
                    if req_time > cutoff_time
                ]
            
            # Check rate limit
            if client_id not in _rate_limit_cache:
                _rate_limit_cache[client_id] = []
            
            if len(_rate_limit_cache[client_id]) >= requests_per_minute:
                # Record rate limit violation
                analytics_engine = getattr(request._get_current_object().app, 'analytics_engine', None)
                if analytics_engine:
                    analytics_engine.metrics_collector.record_rate_limit_violation(
                        client_identifier=client_id,
                        endpoint_pattern=request.path
                    )
                
                return jsonify({"error": "Rate limit exceeded"}), 429
            
            # Record this request
            _rate_limit_cache[client_id].append(current_time)
            
            # Execute the function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator