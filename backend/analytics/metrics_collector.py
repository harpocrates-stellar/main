"""Privacy-safe metrics collection extending existing Harpocrates metrics system."""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple

from .config import MetricsConfig
from .redaction import RedactionEngine


class PrivacySafeMetricsCollector:
    """Enhanced metrics collector with privacy-safe endpoint patterns and operation categorization."""
    
    def __init__(self, config: MetricsConfig, redaction_engine: RedactionEngine):
        self.config = config
        self.redaction_engine = redaction_engine
        self._lock = threading.Lock()
        
        # Request metrics with sanitized patterns
        self._requests_total: Dict[Tuple[str, str, str], int] = {}
        self._request_latency: Dict[Tuple[str, str, str], Dict[str, float]] = {}
        self._upload_size: Dict[Tuple[str, str], Dict[str, float]] = {}
        
        # Operation categorization metrics
        self._operation_duration: Dict[str, Dict[str, float]] = {}
        self._operation_counts: Dict[str, int] = {}
        
        # Resource utilization metrics  
        self._resource_usage: Dict[str, Dict[str, float]] = {}
        
        # System health metrics
        self._health_status: Dict[str, str] = {}
        self._availability_metrics: Dict[str, float] = {}
        
        # Rate limiting and security metrics
        self._rate_limit_violations: Dict[str, int] = {}
        self._security_events: Dict[str, int] = {}
        
        # Endpoint pattern cache for efficiency
        self._endpoint_pattern_cache: Dict[str, str] = {}
        self._pattern_cache_lock = threading.Lock()
        
        # Operation categories
        self.operation_categories = {
            'steganography': ['embed', 'extract', 'hash', 'metadata'],
            'cryptography': ['generate_proof', 'verify_proof', 'witness', 'commitment'],
            'database': ['query', 'insert', 'update', 'delete', 'migration'],
            'network': ['stellar_submit', 'stellar_query', 'http_request', 'websocket'],
            'storage': ['file_read', 'file_write', 'temp_file', 'cleanup'],
            'authentication': ['login', 'logout', 'verify_token', 'refresh'],
            'validation': ['validate_input', 'check_format', 'verify_signature'],
        }
    
    def record_request(
        self,
        method: str,
        endpoint: str, 
        status: int,
        duration_seconds: float,
        upload_bytes: Optional[int] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """Record HTTP request metrics with sanitized endpoint patterns.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: URL path or endpoint rule
            status: HTTP status code
            duration_seconds: Request duration
            upload_bytes: Upload size in bytes (optional)
            correlation_id: Request correlation ID for tracing
        """
        
        if not self.config.enabled:
            return
        
        # Sanitize endpoint pattern
        sanitized_endpoint = self._get_sanitized_endpoint_pattern(endpoint)
        
        clean_method = (method or "UNKNOWN").upper()
        status_str = str(status)
        
        with self._lock:
            # Record request count
            counter_key = (clean_method, sanitized_endpoint, status_str)
            self._requests_total[counter_key] = self._requests_total.get(counter_key, 0) + 1
            
            # Record latency histogram
            if self.config.enable_latency_tracking:
                self._record_latency(counter_key, duration_seconds)
            
            # Record upload size if provided
            if upload_bytes is not None and upload_bytes > 0:
                upload_key = (clean_method, sanitized_endpoint)
                self._record_upload_size(upload_key, upload_bytes)
    
    def record_operation_performance(
        self,
        operation_name: str,
        duration_seconds: float,
        cpu_percent: Optional[float] = None,
        memory_mb: Optional[float] = None,
        io_operations: Optional[int] = None
    ) -> None:
        """Record performance metrics for categorized operations.
        
        Args:
            operation_name: Name of the operation 
            duration_seconds: Operation duration
            cpu_percent: CPU utilization percentage
            memory_mb: Memory usage in MB
            io_operations: Number of I/O operations
        """
        
        if not self.config.enable_operation_categorization:
            return
        
        # Categorize the operation to avoid exposing specific content
        operation_category = self._categorize_operation(operation_name)
        
        with self._lock:
            # Record operation duration
            if operation_category not in self._operation_duration:
                self._operation_duration[operation_category] = {
                    'sum': 0.0,
                    'count': 0,
                    'min': float('inf'),
                    'max': 0.0
                }
            
            stats = self._operation_duration[operation_category]
            stats['sum'] += max(0.0, duration_seconds)
            stats['count'] += 1
            stats['min'] = min(stats['min'], duration_seconds)
            stats['max'] = max(stats['max'], duration_seconds)
            
            # Record operation counts
            self._operation_counts[operation_category] = \
                self._operation_counts.get(operation_category, 0) + 1
            
            # Record resource usage if enabled and provided
            if self.config.enable_resource_tracking:
                self._record_resource_usage(operation_category, cpu_percent, memory_mb, io_operations)
    
    def record_system_health(
        self,
        component_name: str,
        health_status: str,
        response_time_ms: Optional[float] = None,
        active_connections: Optional[int] = None
    ) -> None:
        """Record system health metrics without exposing sensitive component details.
        
        Args:
            component_name: Name of the system component
            health_status: Health status (healthy, degraded, unhealthy)
            response_time_ms: Component response time
            active_connections: Number of active connections
        """
        
        # Sanitize component name to prevent information leakage
        sanitized_component = self._sanitize_component_name(component_name)
        
        with self._lock:
            # Record health status
            self._health_status[sanitized_component] = health_status
            
            # Record availability metrics
            if response_time_ms is not None:
                availability_key = f"{sanitized_component}.response_time"
                self._availability_metrics[availability_key] = max(0.0, response_time_ms)
            
            if active_connections is not None:
                connections_key = f"{sanitized_component}.connections"
                self._availability_metrics[connections_key] = max(0, active_connections)
    
    def record_rate_limit_violation(self, client_identifier: str, endpoint_pattern: str) -> None:
        """Record rate limiting violations with anonymized client data.
        
        Args:
            client_identifier: Client identifier (will be hashed)
            endpoint_pattern: Endpoint pattern where violation occurred
        """
        
        # Hash client identifier to prevent client identification while allowing pattern analysis
        client_hash = self.redaction_engine.hash_for_pattern_analysis(client_identifier)
        sanitized_endpoint = self._get_sanitized_endpoint_pattern(endpoint_pattern)
        
        violation_key = f"{sanitized_endpoint}.{client_hash[:8]}"
        
        with self._lock:
            self._rate_limit_violations[violation_key] = \
                self._rate_limit_violations.get(violation_key, 0) + 1
    
    def record_security_event(self, event_type: str, severity: str, endpoint_pattern: Optional[str] = None) -> None:
        """Record security events without exposing sensitive context.
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            endpoint_pattern: Optional endpoint where event occurred
        """
        
        sanitized_endpoint = "global"
        if endpoint_pattern:
            sanitized_endpoint = self._get_sanitized_endpoint_pattern(endpoint_pattern)
        
        security_key = f"{event_type}.{severity}.{sanitized_endpoint}"
        
        with self._lock:
            self._security_events[security_key] = \
                self._security_events.get(security_key, 0) + 1
    
    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format with privacy guarantees.
        
        Returns:
            Prometheus-formatted metrics string
        """
        
        metrics_lines = []
        
        with self._lock:
            # HTTP request metrics
            metrics_lines.extend(self._format_request_metrics())
            
            # Operation performance metrics
            if self.config.enable_operation_categorization:
                metrics_lines.extend(self._format_operation_metrics())
            
            # Resource utilization metrics
            if self.config.enable_resource_tracking:
                metrics_lines.extend(self._format_resource_metrics())
            
            # System health metrics
            metrics_lines.extend(self._format_health_metrics())
            
            # Security metrics
            metrics_lines.extend(self._format_security_metrics())
        
        return '\n'.join(metrics_lines) + '\n'
    
    def get_metrics_summary(self) -> Dict[str, any]:
        """Get a summary of current metrics for monitoring dashboards.
        
        Returns:
            Dictionary containing sanitized metrics summary
        """
        
        with self._lock:
            return {
                'request_counts': dict(self._requests_total),
                'operation_counts': dict(self._operation_counts),
                'health_status': dict(self._health_status),
                'rate_limit_violations': dict(self._rate_limit_violations),
                'security_events': dict(self._security_events),
                'collection_timestamp': time.time(),
            }
    
    def reset_metrics(self) -> None:
        """Reset all metrics (primarily for testing)."""
        
        with self._lock:
            self._requests_total.clear()
            self._request_latency.clear()
            self._upload_size.clear()
            self._operation_duration.clear()
            self._operation_counts.clear()
            self._resource_usage.clear()
            self._health_status.clear()
            self._availability_metrics.clear()
            self._rate_limit_violations.clear()
            self._security_events.clear()
        
        with self._pattern_cache_lock:
            self._endpoint_pattern_cache.clear()
    
    def _get_sanitized_endpoint_pattern(self, endpoint: str) -> str:
        """Get sanitized endpoint pattern with caching for performance."""
        
        if not endpoint:
            return "unmatched"
        
        # Check cache first
        with self._pattern_cache_lock:
            if endpoint in self._endpoint_pattern_cache:
                return self._endpoint_pattern_cache[endpoint]
            
            # Sanitize and cache
            sanitized = self.redaction_engine.sanitize_endpoint_pattern(endpoint)
            
            # Limit cache size
            if len(self._endpoint_pattern_cache) >= self.config.max_endpoint_patterns:
                # Remove oldest entries (simple FIFO)
                oldest_keys = list(self._endpoint_pattern_cache.keys())[:100]
                for key in oldest_keys:
                    del self._endpoint_pattern_cache[key]
            
            self._endpoint_pattern_cache[endpoint] = sanitized
            return sanitized
    
    def _categorize_operation(self, operation_name: str) -> str:
        """Categorize operation to avoid exposing specific content details."""
        
        if not operation_name:
            return "unknown"
        
        operation_lower = operation_name.lower()
        
        for category, keywords in self.operation_categories.items():
            if any(keyword in operation_lower for keyword in keywords):
                return category
        
        return "unknown"
    
    def _sanitize_component_name(self, component_name: str) -> str:
        """Sanitize system component names to prevent information leakage."""
        
        if not component_name:
            return "unknown"
        
        # Map to generic component categories
        component_lower = component_name.lower()
        
        if any(term in component_lower for term in ['database', 'db', 'sql']):
            return "database"
        elif any(term in component_lower for term in ['redis', 'cache']):
            return "cache"
        elif any(term in component_lower for term in ['stellar', 'blockchain']):
            return "blockchain"
        elif any(term in component_lower for term in ['web', 'http', 'api']):
            return "web_service"
        elif any(term in component_lower for term in ['storage', 'file', 'disk']):
            return "storage"
        else:
            return "service"
    
    def _record_latency(self, counter_key: Tuple[str, str, str], duration_seconds: float) -> None:
        """Record latency histogram data."""
        
        if counter_key not in self._request_latency:
            self._request_latency[counter_key] = {
                'sum': 0.0,
                'count': 0,
                'buckets': {}
            }
        
        latency_data = self._request_latency[counter_key]
        latency_data['sum'] += max(0.0, duration_seconds)
        latency_data['count'] += 1
        
        # Update histogram buckets
        buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float('inf')]
        for bucket in buckets:
            if duration_seconds <= bucket:
                bucket_key = f"le_{bucket}"
                latency_data['buckets'][bucket_key] = latency_data['buckets'].get(bucket_key, 0) + 1
    
    def _record_upload_size(self, upload_key: Tuple[str, str], size_bytes: int) -> None:
        """Record upload size histogram data."""
        
        if upload_key not in self._upload_size:
            self._upload_size[upload_key] = {
                'sum': 0.0,
                'count': 0,
                'buckets': {}
            }
        
        upload_data = self._upload_size[upload_key]
        upload_data['sum'] += max(0, size_bytes)
        upload_data['count'] += 1
        
        # Update histogram buckets
        buckets = [1024, 65536, 1048576, 10485760, 104857600, 262144000, float('inf')]
        for bucket in buckets:
            if size_bytes <= bucket:
                bucket_key = f"le_{bucket}"
                upload_data['buckets'][bucket_key] = upload_data['buckets'].get(bucket_key, 0) + 1
    
    def _record_resource_usage(
        self,
        operation_category: str,
        cpu_percent: Optional[float],
        memory_mb: Optional[float],
        io_operations: Optional[int]
    ) -> None:
        """Record resource usage metrics."""
        
        if operation_category not in self._resource_usage:
            self._resource_usage[operation_category] = {
                'cpu_sum': 0.0,
                'cpu_count': 0,
                'memory_sum': 0.0,
                'memory_count': 0,
                'io_sum': 0,
                'io_count': 0
            }
        
        resource_data = self._resource_usage[operation_category]
        
        if cpu_percent is not None:
            resource_data['cpu_sum'] += max(0.0, cpu_percent)
            resource_data['cpu_count'] += 1
        
        if memory_mb is not None:
            resource_data['memory_sum'] += max(0.0, memory_mb)
            resource_data['memory_count'] += 1
        
        if io_operations is not None:
            resource_data['io_sum'] += max(0, io_operations)
            resource_data['io_count'] += 1
    
    def _format_request_metrics(self) -> List[str]:
        """Format HTTP request metrics for Prometheus export."""
        
        lines = []
        
        # Request total counter
        lines.append('# HELP harpocrates_http_requests_total Total HTTP requests by method, endpoint, and status')
        lines.append('# TYPE harpocrates_http_requests_total counter')
        
        for (method, endpoint, status), count in self._requests_total.items():
            lines.append(
                f'harpocrates_http_requests_total{{method="{method}",endpoint="{endpoint}",status="{status}"}} {count}'
            )
        
        # Request latency histogram
        if self.config.enable_latency_tracking and self._request_latency:
            lines.append('# HELP harpocrates_http_request_duration_seconds HTTP request latency')
            lines.append('# TYPE harpocrates_http_request_duration_seconds histogram')
            
            for (method, endpoint, status), latency_data in self._request_latency.items():
                base_labels = f'method="{method}",endpoint="{endpoint}",status="{status}"'
                
                # Histogram buckets
                for bucket_key, bucket_count in latency_data['buckets'].items():
                    le_value = bucket_key.replace('le_', '')
                    lines.append(
                        f'harpocrates_http_request_duration_seconds_bucket{{{base_labels},le="{le_value}"}} {bucket_count}'
                    )
                
                # Histogram sum and count
                lines.append(f'harpocrates_http_request_duration_seconds_sum{{{base_labels}}} {latency_data["sum"]}')
                lines.append(f'harpocrates_http_request_duration_seconds_count{{{base_labels}}} {latency_data["count"]}')
        
        return lines
    
    def _format_operation_metrics(self) -> List[str]:
        """Format operation performance metrics for Prometheus export."""
        
        lines = []
        
        # Operation duration
        lines.append('# HELP harpocrates_operation_duration_seconds Operation duration by category')
        lines.append('# TYPE harpocrates_operation_duration_seconds summary')
        
        for category, stats in self._operation_duration.items():
            lines.append(f'harpocrates_operation_duration_seconds_sum{{category="{category}"}} {stats["sum"]}')
            lines.append(f'harpocrates_operation_duration_seconds_count{{category="{category}"}} {stats["count"]}')
        
        # Operation counts
        lines.append('# HELP harpocrates_operations_total Total operations by category')
        lines.append('# TYPE harpocrates_operations_total counter')
        
        for category, count in self._operation_counts.items():
            lines.append(f'harpocrates_operations_total{{category="{category}"}} {count}')
        
        return lines
    
    def _format_resource_metrics(self) -> List[str]:
        """Format resource utilization metrics for Prometheus export."""
        
        lines = []
        
        # CPU utilization
        lines.append('# HELP harpocrates_cpu_usage_percent Average CPU usage by operation category')
        lines.append('# TYPE harpocrates_cpu_usage_percent gauge')
        
        for category, resource_data in self._resource_usage.items():
            if resource_data['cpu_count'] > 0:
                avg_cpu = resource_data['cpu_sum'] / resource_data['cpu_count']
                lines.append(f'harpocrates_cpu_usage_percent{{category="{category}"}} {avg_cpu:.2f}')
        
        # Memory utilization
        lines.append('# HELP harpocrates_memory_usage_mb Average memory usage by operation category')
        lines.append('# TYPE harpocrates_memory_usage_mb gauge')
        
        for category, resource_data in self._resource_usage.items():
            if resource_data['memory_count'] > 0:
                avg_memory = resource_data['memory_sum'] / resource_data['memory_count']
                lines.append(f'harpocrates_memory_usage_mb{{category="{category}"}} {avg_memory:.2f}')
        
        return lines
    
    def _format_health_metrics(self) -> List[str]:
        """Format system health metrics for Prometheus export."""
        
        lines = []
        
        # Component health status
        lines.append('# HELP harpocrates_component_health Component health status (1=healthy, 0=unhealthy)')
        lines.append('# TYPE harpocrates_component_health gauge')
        
        for component, status in self._health_status.items():
            health_value = 1 if status == "healthy" else 0
            lines.append(f'harpocrates_component_health{{component="{component}",status="{status}"}} {health_value}')
        
        # Availability metrics
        lines.append('# HELP harpocrates_availability_metrics Various availability metrics')
        lines.append('# TYPE harpocrates_availability_metrics gauge')
        
        for metric_name, value in self._availability_metrics.items():
            lines.append(f'harpocrates_availability_metrics{{metric="{metric_name}"}} {value}')
        
        return lines
    
    def _format_security_metrics(self) -> List[str]:
        """Format security and rate limiting metrics for Prometheus export."""
        
        lines = []
        
        # Rate limit violations
        lines.append('# HELP harpocrates_rate_limit_violations_total Rate limiting violations')
        lines.append('# TYPE harpocrates_rate_limit_violations_total counter')
        
        for violation_key, count in self._rate_limit_violations.items():
            lines.append(f'harpocrates_rate_limit_violations_total{{key="{violation_key}"}} {count}')
        
        # Security events
        lines.append('# HELP harpocrates_security_events_total Security events by type and severity')
        lines.append('# TYPE harpocrates_security_events_total counter')
        
        for event_key, count in self._security_events.items():
            lines.append(f'harpocrates_security_events_total{{event="{event_key}"}} {count}')
        
        return lines