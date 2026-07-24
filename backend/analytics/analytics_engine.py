"""Central analytics engine orchestrating all privacy-safe analytics operations."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Dict, List, Optional

from .config import AnalyticsConfig
from .events import (
    AnalyticsEvent, 
    create_error_event, 
    create_performance_event, 
    create_request_event,
    create_system_event,
    EventType
)
from .log_processor import LogProcessor
from .metrics_collector import PrivacySafeMetricsCollector
from .redaction import RedactionEngine, RedactionPatterns


class AnalyticsEngine:
    """Central orchestrator for privacy-safe analytics with multi-layer redaction."""
    
    def __init__(self, config: Optional[AnalyticsConfig] = None):
        """Initialize analytics engine with configuration.
        
        Args:
            config: Analytics configuration (loads from environment if None)
        """
        
        if config is None:
            from .config import load_analytics_config
            config = load_analytics_config()
        
        self.config = config
        self._enabled = config.enabled
        
        # Initialize core components
        self.redaction_engine = RedactionEngine(config.redaction_patterns)
        self.metrics_collector = PrivacySafeMetricsCollector(config.metrics_config, self.redaction_engine)
        self.log_processor = LogProcessor(config.logging_config, self.redaction_engine)
        
        # Async processing queue and worker
        self._event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._processing_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Thread safety
        self._lock = threading.Lock()
        
        # System state tracking
        self._system_state = {
            'startup_time': time.time(),
            'events_processed': 0,
            'privacy_violations_detected': 0,
            'redactions_performed': 0,
            'last_health_check': time.time(),
        }
        
        # Component health monitoring
        self._component_health = {
            'redaction_engine': 'healthy',
            'metrics_collector': 'healthy', 
            'log_processor': 'healthy',
            'event_processor': 'healthy',
        }
        
        # Performance monitoring
        self._performance_stats = {
            'avg_processing_time_ms': 0.0,
            'events_per_second': 0.0,
            'queue_size': 0,
            'memory_usage_mb': 0.0,
        }
        
        # Start async processing if enabled
        if config.async_processing and self._enabled:
            self._start_async_processing()
    
    def process_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration_seconds: float,
        upload_bytes: Optional[int] = None,
        correlation_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Process HTTP request for analytics with privacy protection.
        
        Args:
            method: HTTP method
            endpoint: Request endpoint 
            status_code: HTTP status code
            duration_seconds: Request duration
            upload_bytes: Upload size in bytes
            correlation_id: Request correlation ID
            context: Additional request context
            
        Returns:
            Correlation ID for request tracking
        """
        
        if not self._enabled:
            return correlation_id or "disabled"
        
        try:
            # Create sanitized request event
            request_event = create_request_event(
                method=method,
                endpoint_pattern=endpoint,
                status_code=status_code, 
                latency_ms=duration_seconds * 1000,
                size_bytes=upload_bytes,
                correlation_id=correlation_id
            )
            
            # Add sanitized context if provided
            if context:
                sanitized_context = self.redaction_engine.sanitize_error_context(context)
                request_event.data.update(sanitized_context)
            
            # Process event through pipeline
            self._process_event_sync(request_event)
            
            return request_event.correlation_id
            
        except Exception as e:
            # Handle analytics processing errors without failing the request
            self._handle_analytics_error(e, "process_request")
            return correlation_id or "error"
    
    def process_error(
        self,
        error: Exception,
        context: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> str:
        """Process error for analytics with comprehensive sanitization.
        
        Args:
            error: Exception that occurred
            context: Error context
            correlation_id: Optional correlation ID
            
        Returns:
            Correlation ID for error tracking
        """
        
        if not self._enabled:
            return correlation_id or "disabled"
        
        try:
            # Use log processor for error handling
            return self.log_processor.process_error(error, context, correlation_id)
            
        except Exception as e:
            # Handle analytics processing errors
            self._handle_analytics_error(e, "process_error")
            return correlation_id or "error"
    
    def record_performance(
        self,
        operation_name: str,
        duration_seconds: float,
        cpu_percent: Optional[float] = None,
        memory_mb: Optional[float] = None,
        io_operations: Optional[int] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """Record performance metrics for operations.
        
        Args:
            operation_name: Name of the operation
            duration_seconds: Operation duration
            cpu_percent: CPU utilization
            memory_mb: Memory usage
            io_operations: I/O operation count
            correlation_id: Optional correlation ID
        """
        
        if not self._enabled:
            return
        
        try:
            # Create performance event
            perf_event = create_performance_event(
                operation_type=operation_name,
                duration_ms=duration_seconds * 1000,
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                correlation_id=correlation_id
            )
            
            # Record in metrics collector
            self.metrics_collector.record_operation_performance(
                operation_name=operation_name,
                duration_seconds=duration_seconds,
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                io_operations=io_operations
            )
            
            # Process event
            self._process_event_sync(perf_event)
            
        except Exception as e:
            self._handle_analytics_error(e, "record_performance")
    
    def record_system_health(
        self,
        component_name: str,
        health_status: str,
        response_time_ms: Optional[float] = None,
        additional_metrics: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record system health metrics.
        
        Args:
            component_name: System component name
            health_status: Health status (healthy, degraded, unhealthy)
            response_time_ms: Component response time
            additional_metrics: Additional health metrics
        """
        
        if not self._enabled:
            return
        
        try:
            # Create system event
            system_event = create_system_event(
                component_name=component_name,
                health_status=health_status,
                uptime_seconds=time.time() - self._system_state['startup_time']
            )
            
            # Add additional metrics if provided
            if additional_metrics:
                sanitized_metrics = self.redaction_engine.sanitize(
                    additional_metrics, 
                    f"health.{component_name}"
                )
                if not sanitized_metrics.has_violations():
                    system_event.data.update(sanitized_metrics.data)
            
            # Record in metrics collector
            self.metrics_collector.record_system_health(
                component_name=component_name,
                health_status=health_status,
                response_time_ms=response_time_ms
            )
            
            # Update internal component health
            with self._lock:
                self._component_health[component_name] = health_status
            
            # Process event
            self._process_event_sync(system_event)
            
        except Exception as e:
            self._handle_analytics_error(e, "record_system_health")
    
    def get_metrics_export(self, format: str = "prometheus") -> str:
        """Export metrics in specified format.
        
        Args:
            format: Export format ("prometheus" or "json")
            
        Returns:
            Formatted metrics string
        """
        
        if not self._enabled:
            return ""
        
        try:
            if format.lower() == "prometheus":
                return self.metrics_collector.get_prometheus_metrics()
            elif format.lower() == "json":
                import json
                metrics = self.metrics_collector.get_metrics_summary()
                
                # Validate export safety
                is_safe, violations = self.redaction_engine.validate_export_safety(metrics)
                if not is_safe:
                    raise ValueError(f"Metrics export contains sensitive data: {violations}")
                
                return json.dumps(metrics, separators=(',', ':'))
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            self._handle_analytics_error(e, "get_metrics_export") 
            return ""
    
    def get_logs_export(
        self,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        compress: bool = True
    ) -> str:
        """Export logs in JSON format.
        
        Args:
            start_time: Start timestamp filter
            end_time: End timestamp filter
            compress: Whether to compress output
            
        Returns:
            JSON formatted logs (optionally compressed)
        """
        
        if not self._enabled:
            return ""
        
        try:
            # Get logs from processor
            logs = self.log_processor.get_logs(start_time, end_time)
            
            # Export through log processor (includes safety validation)
            return self.log_processor.export_json_logs(compress)
            
        except Exception as e:
            self._handle_analytics_error(e, "get_logs_export")
            return ""
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and health information.
        
        Returns:
            Dictionary containing system status information
        """
        
        current_time = time.time()
        
        with self._lock:
            # Update performance stats
            self._update_performance_stats()
            
            status = {
                'enabled': self._enabled,
                'uptime_seconds': current_time - self._system_state['startup_time'],
                'system_state': dict(self._system_state),
                'component_health': dict(self._component_health),
                'performance_stats': dict(self._performance_stats),
                'queue_size': self._event_queue.qsize() if self._event_queue else 0,
                'config_summary': {
                    'privacy_mode': self.config.privacy_mode,
                    'async_processing': self.config.async_processing,
                    'metrics_enabled': self.config.metrics_config.enabled,
                    'logging_enabled': self.config.logging_config.enabled,
                },
                'redaction_stats': self.redaction_engine.get_redaction_stats(),
                'error_stats': self.log_processor.get_error_statistics(),
                'status_timestamp': current_time,
            }
            
        return status
    
    def perform_health_check(self) -> Dict[str, str]:
        """Perform comprehensive health check of all components.
        
        Returns:
            Dictionary mapping component names to health status
        """
        
        health_results = {}
        
        try:
            # Check redaction engine
            test_data = {"test_field": "test_value"}
            result = self.redaction_engine.sanitize(test_data)
            health_results['redaction_engine'] = 'healthy' if result.data else 'unhealthy'
        except Exception:
            health_results['redaction_engine'] = 'unhealthy'
        
        try:
            # Check metrics collector
            self.metrics_collector.record_request("GET", "/health", 200, 0.1)
            health_results['metrics_collector'] = 'healthy'
        except Exception:
            health_results['metrics_collector'] = 'unhealthy'
        
        try:
            # Check log processor
            error_stats = self.log_processor.get_error_statistics()
            health_results['log_processor'] = 'healthy' if error_stats else 'unhealthy'
        except Exception:
            health_results['log_processor'] = 'unhealthy'
        
        # Check event processing
        if self.config.async_processing:
            queue_size = self._event_queue.qsize() if self._event_queue else 0
            if queue_size > 5000:  # Queue getting full
                health_results['event_processor'] = 'degraded'
            else:
                health_results['event_processor'] = 'healthy'
        else:
            health_results['event_processor'] = 'healthy'
        
        # Update internal health state
        with self._lock:
            self._component_health.update(health_results)
            self._system_state['last_health_check'] = time.time()
        
        return health_results
    
    def cleanup_old_data(self) -> Dict[str, int]:
        """Clean up old data according to retention policies.
        
        Returns:
            Dictionary containing cleanup statistics
        """
        
        if not self._enabled:
            return {}
        
        cleanup_stats = {}
        
        try:
            # Clean up old logs
            logs_removed = self.log_processor.clear_old_logs()
            cleanup_stats['logs_removed'] = logs_removed
            
            # Reset redaction statistics if they get too large
            redaction_stats = self.redaction_engine.get_redaction_stats()
            if len(redaction_stats) > 1000:
                self.redaction_engine.reset_stats()
                cleanup_stats['redaction_stats_reset'] = True
            else:
                cleanup_stats['redaction_stats_reset'] = False
            
            # Reset metrics if configured
            # (In production, this might be handled by external systems)
            cleanup_stats['cleanup_timestamp'] = time.time()
            
        except Exception as e:
            self._handle_analytics_error(e, "cleanup_old_data")
            cleanup_stats['cleanup_error'] = str(e)
        
        return cleanup_stats
    
    def shutdown(self) -> None:
        """Gracefully shutdown analytics engine."""
        
        if not self._enabled:
            return
        
        # Signal shutdown
        if self._shutdown_event:
            self._shutdown_event.set()
        
        # Wait for async processing to complete
        if self._processing_task and not self._processing_task.done():
            try:
                # Give it a moment to finish gracefully
                asyncio.create_task(asyncio.wait_for(self._processing_task, timeout=5.0))
            except (asyncio.TimeoutError, RuntimeError):
                # Force cancel if it doesn't finish
                self._processing_task.cancel()
        
        # Perform final cleanup
        self.cleanup_old_data()
        
        # Record shutdown event
        try:
            shutdown_event = AnalyticsEvent(
                event_type=EventType.SHUTDOWN,
                source_component="analytics_engine",
                operation_category="system_lifecycle",
                data={
                    'uptime_seconds': time.time() - self._system_state['startup_time'],
                    'events_processed': self._system_state['events_processed']
                }
            )
            self._process_event_sync(shutdown_event)
        except Exception:
            # Don't fail shutdown on analytics errors
            pass
    
    def _process_event_sync(self, event: AnalyticsEvent) -> None:
        """Process event synchronously through the analytics pipeline.
        
        Args:
            event: Analytics event to process
        """
        
        start_time = time.perf_counter()
        
        try:
            # Apply privacy redaction
            if event.requires_redaction:
                redaction_result = self.redaction_engine.sanitize(
                    event.data, 
                    f"event.{event.event_type.value}"
                )
                
                if redaction_result.has_violations():
                    self._system_state['privacy_violations_detected'] += 1
                    # Don't process events with privacy violations
                    return
                
                if redaction_result.has_redactions():
                    self._system_state['redactions_performed'] += 1
                    event.data = redaction_result.data
            
            # Route event to appropriate processors
            if event.is_metric():
                # Metrics are already recorded via direct metrics_collector calls
                # This just updates statistics
                pass
            
            if event.is_log():
                self.log_processor.process_event(event)
            
            # Update processing statistics
            with self._lock:
                self._system_state['events_processed'] += 1
            
        except Exception as e:
            self._handle_analytics_error(e, f"_process_event_sync.{event.event_type.value}")
        
        finally:
            # Update performance timing
            processing_time = (time.perf_counter() - start_time) * 1000
            self._update_processing_performance(processing_time)
    
    def _start_async_processing(self) -> None:
        """Start asynchronous event processing."""
        
        try:
            # Get or create event loop
            loop = asyncio.get_event_loop()
        except RuntimeError:
            # No event loop in current thread, create one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        # Start processing task
        self._processing_task = loop.create_task(self._async_event_processor())
    
    async def _async_event_processor(self) -> None:
        """Asynchronous event processing worker."""
        
        while not self._shutdown_event.is_set():
            try:
                # Wait for event with timeout
                event = await asyncio.wait_for(
                    self._event_queue.get(), 
                    timeout=1.0
                )
                
                # Process event synchronously (redaction is CPU-bound)
                self._process_event_sync(event)
                
                # Mark task as done
                self._event_queue.task_done()
                
            except asyncio.TimeoutError:
                # Normal timeout, continue loop
                continue
            except Exception as e:
                self._handle_analytics_error(e, "async_event_processor")
    
    def _handle_analytics_error(self, error: Exception, context: str) -> None:
        """Handle analytics processing errors without affecting main application.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
        """
        
        # Update error statistics
        with self._lock:
            if context not in self._system_state:
                self._system_state[f'errors_{context}'] = 0
            self._system_state[f'errors_{context}'] += 1
        
        # Log error to standard logging (not analytics logging to avoid recursion)
        import logging
        logger = logging.getLogger("harpocrates.analytics.errors")
        logger.error(f"Analytics error in {context}: {type(error).__name__}: {error}")
    
    def _update_performance_stats(self) -> None:
        """Update performance statistics."""
        
        current_time = time.time()
        
        # Calculate events per second
        uptime = max(1.0, current_time - self._system_state['startup_time'])
        self._performance_stats['events_per_second'] = \
            self._system_state['events_processed'] / uptime
        
        # Update queue size
        self._performance_stats['queue_size'] = \
            self._event_queue.qsize() if self._event_queue else 0
        
        # Get memory usage (approximate)
        try:
            import psutil
            process = psutil.Process()
            self._performance_stats['memory_usage_mb'] = \
                process.memory_info().rss / 1024 / 1024
        except (ImportError, Exception):
            self._performance_stats['memory_usage_mb'] = 0.0
    
    def _update_processing_performance(self, processing_time_ms: float) -> None:
        """Update processing time statistics.
        
        Args:
            processing_time_ms: Processing time in milliseconds
        """
        
        with self._lock:
            # Simple exponential moving average
            alpha = 0.1
            current_avg = self._performance_stats['avg_processing_time_ms']
            self._performance_stats['avg_processing_time_ms'] = \
                (alpha * processing_time_ms) + ((1 - alpha) * current_avg)