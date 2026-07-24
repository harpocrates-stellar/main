"""Privacy-safe log processing for error telemetry and system events."""

from __future__ import annotations

import json
import logging
import threading
import time
import traceback
import uuid
from typing import Any, Dict, List, Optional

from .config import LogConfig
from .events import AnalyticsEvent, ErrorEvent, EventType
from .redaction import RedactionEngine


class LogProcessor:
    """Privacy-safe log processor with comprehensive context sanitization."""
    
    def __init__(self, config: LogConfig, redaction_engine: RedactionEngine):
        self.config = config
        self.redaction_engine = redaction_engine
        self._lock = threading.Lock()
        
        # In-memory log storage for export (with size limits)
        self._log_entries: List[Dict[str, Any]] = []
        self._max_log_entries = 10000
        
        # Error classification and pattern tracking
        self._error_patterns: Dict[str, int] = {}
        self._error_categories: Dict[str, int] = {}
        
        # Correlation ID tracking
        self._correlation_tracker: Dict[str, Dict[str, Any]] = {}
        
        # Performance metrics for log processing
        self._processing_stats = {
            'logs_processed': 0,
            'errors_classified': 0,
            'redactions_performed': 0,
            'privacy_violations_detected': 0,
        }
        
        # Setup structured logger
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Setup structured logger for analytics events."""
        
        self.logger = logging.getLogger("harpocrates.analytics")
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            
            # Use JSON formatter for structured logging
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            
            self.logger.addHandler(handler)
            self.logger.setLevel(getattr(logging, self.config.max_log_level, logging.INFO))
            self.logger.propagate = False
    
    def process_error(
        self,
        error: Exception,
        context: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> str:
        """Process error with comprehensive context sanitization.
        
        Args:
            error: Exception that occurred
            context: Request/operation context
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            Generated correlation ID for the processed error
        """
        
        if not self.config.enabled:
            return correlation_id or str(uuid.uuid4())
        
        # Generate correlation ID if not provided
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        # Classify the error
        error_classification = self._classify_error(error, context)
        
        # Sanitize the error context
        sanitized_context = self._sanitize_error_context(context, error_classification)
        
        # Create sanitized stack trace
        stack_trace_info = self._sanitize_stack_trace(error)
        
        # Create error event
        error_event = ErrorEvent(
            error_type=type(error).__name__,
            error_category=error_classification['category'],
            sanitized_context=sanitized_context,
            stack_trace_hash=stack_trace_info['hash'],
            correlation_id=correlation_id,
        )
        
        # Add request context if available
        if 'method' in sanitized_context:
            error_event.request_method = sanitized_context['method']
        if 'endpoint_pattern' in sanitized_context:
            error_event.endpoint_pattern = sanitized_context['endpoint_pattern']
        
        # Process and store the error event
        self._process_log_event(error_event, stack_trace_info)
        
        return correlation_id
    
    def process_event(self, event: AnalyticsEvent) -> None:
        """Process any analytics event that should be logged.
        
        Args:
            event: Analytics event to process and log
        """
        
        if not self.config.enabled or not event.is_log():
            return
        
        # Sanitize the event data
        sanitized_event_data = self.redaction_engine.sanitize(
            event.data, 
            f"event.{event.event_type.value}"
        )
        
        if sanitized_event_data.has_violations():
            self._processing_stats['privacy_violations_detected'] += 1
            
            # Log privacy violation separately
            self._log_privacy_violation(event, sanitized_event_data.violations_found)
            return
        
        # Update event with sanitized data
        event.data = sanitized_event_data.data
        
        # Process the sanitized event
        self._process_log_event(event)
    
    def get_logs(
        self, 
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        max_count: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get sanitized log entries for export.
        
        Args:
            start_time: Start timestamp filter
            end_time: End timestamp filter 
            max_count: Maximum number of entries to return
            
        Returns:
            List of sanitized log entries
        """
        
        with self._lock:
            filtered_logs = []
            
            for entry in self._log_entries:
                # Apply time filters
                if start_time and entry.get('timestamp', 0) < start_time:
                    continue
                if end_time and entry.get('timestamp', 0) > end_time:
                    continue
                
                # Verify entry is still safe for export
                is_safe, violations = self.redaction_engine.validate_export_safety(entry)
                if is_safe:
                    filtered_logs.append(entry.copy())
                else:
                    # Log that we're skipping an unsafe entry
                    self._log_export_safety_violation(entry.get('correlation_id'), violations)
            
            # Apply count limit
            if max_count and len(filtered_logs) > max_count:
                filtered_logs = filtered_logs[-max_count:]  # Get most recent
            
            return filtered_logs
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error pattern statistics for monitoring.
        
        Returns:
            Dictionary containing error statistics
        """
        
        with self._lock:
            return {
                'error_patterns': dict(self._error_patterns),
                'error_categories': dict(self._error_categories),
                'processing_stats': dict(self._processing_stats),
                'total_log_entries': len(self._log_entries),
                'collection_timestamp': time.time(),
            }
    
    def clear_old_logs(self, retention_days: Optional[int] = None) -> int:
        """Clear old log entries based on retention policy.
        
        Args:
            retention_days: Days to retain (uses config default if None)
            
        Returns:
            Number of entries removed
        """
        
        retention_days = retention_days or self.config.retention_days
        cutoff_time = time.time() - (retention_days * 24 * 60 * 60)
        
        with self._lock:
            original_count = len(self._log_entries)
            
            # Keep only recent entries
            self._log_entries = [
                entry for entry in self._log_entries
                if entry.get('timestamp', 0) >= cutoff_time
            ]
            
            removed_count = original_count - len(self._log_entries)
            
            # Also clean up pattern tracking for old errors
            self._cleanup_old_patterns(cutoff_time)
            
            return removed_count
    
    def export_json_logs(self, compress: bool = True) -> str:
        """Export logs in JSON format for external analysis.
        
        Args:
            compress: Whether to compress the output
            
        Returns:
            JSON string containing all exportable logs
        """
        
        logs = self.get_logs()
        
        # Create export manifest
        export_data = {
            'metadata': {
                'export_timestamp': time.time(),
                'total_entries': len(logs),
                'privacy_verified': True,
                'redaction_engine_version': '1.0',
            },
            'logs': logs
        }
        
        # Validate export safety
        is_safe, violations = self.redaction_engine.validate_export_safety(export_data)
        if not is_safe:
            raise ValueError(f"Export contains sensitive data: {violations}")
        
        json_output = json.dumps(export_data, separators=(',', ':'), sort_keys=True)
        
        if compress:
            import gzip
            json_bytes = json_output.encode('utf-8')
            compressed = gzip.compress(json_bytes)
            # Return base64 encoded compressed data
            import base64
            return base64.b64encode(compressed).decode('ascii')
        
        return json_output
    
    def _classify_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, str]:
        """Classify error for tracking and analysis.
        
        Args:
            error: Exception to classify
            context: Error context
            
        Returns:
            Dictionary containing error classification
        """
        
        error_type = type(error).__name__
        error_message = str(error)
        
        # Determine error category based on type and context
        if isinstance(error, (ValueError, TypeError)):
            category = "validation_error"
        elif isinstance(error, (ConnectionError, TimeoutError)):
            category = "network_error"
        elif isinstance(error, (PermissionError, OSError)):
            category = "system_error"
        elif 'database' in error_message.lower() or 'sql' in error_message.lower():
            category = "database_error"
        elif 'stellar' in error_message.lower() or 'blockchain' in error_message.lower():
            category = "blockchain_error"
        elif 'steganography' in error_message.lower() or 'embed' in error_message.lower():
            category = "steganography_error"
        elif 'proof' in error_message.lower() or 'witness' in error_message.lower():
            category = "cryptography_error"
        else:
            category = "application_error"
        
        # Determine severity based on context
        severity = "medium"
        if context.get('status_code', 0) >= 500:
            severity = "high"
        elif context.get('status_code', 0) >= 400:
            severity = "medium"
        else:
            severity = "low"
        
        return {
            'type': error_type,
            'category': category,
            'severity': severity,
            'message_hash': self.redaction_engine.hash_for_pattern_analysis(error_message)
        }
    
    def _sanitize_error_context(
        self, 
        context: Dict[str, Any], 
        classification: Dict[str, str]
    ) -> Dict[str, Any]:
        """Sanitize error context for safe logging.
        
        Args:
            context: Original error context
            classification: Error classification data
            
        Returns:
            Sanitized context safe for logging
        """
        
        # Start with error classification (safe data)
        sanitized = {
            'error_type': classification['type'],
            'error_category': classification['category'],
            'error_severity': classification['severity'],
            'message_hash': classification['message_hash'],
        }
        
        # Add safe context fields
        safe_context_fields = {
            'method': str,
            'status_code': int,
            'timestamp': float,
            'correlation_id': str,
            'user_agent_category': str,
        }
        
        for field, expected_type in safe_context_fields.items():
            if field in context:
                value = context[field]
                if isinstance(value, expected_type):
                    # Additional sanitization for specific fields
                    if field == 'method':
                        sanitized[field] = value.upper()[:10]  # Limit length
                    elif field == 'status_code':
                        sanitized[field] = max(100, min(999, value))  # Valid HTTP codes
                    else:
                        sanitized[field] = value
        
        # Sanitize endpoint pattern if present
        if 'endpoint' in context or 'path' in context:
            original_path = context.get('endpoint') or context.get('path', '')
            sanitized['endpoint_pattern'] = self.redaction_engine.sanitize_endpoint_pattern(original_path)
        
        # Add request size information (without content details)
        if 'content_length' in context:
            content_length = context['content_length']
            if isinstance(content_length, int) and content_length >= 0:
                sanitized['request_size_bytes'] = content_length
        
        return sanitized
    
    def _sanitize_stack_trace(self, error: Exception) -> Dict[str, str]:
        """Create sanitized stack trace information.
        
        Args:
            error: Exception with stack trace
            
        Returns:
            Dictionary with sanitized stack trace data
        """
        
        if not self.config.sanitize_stack_traces:
            return {
                'hash': self.redaction_engine.hash_for_pattern_analysis(str(error)),
                'sanitized_trace': '[stack trace sanitization disabled]'
            }
        
        # Get the full stack trace
        full_trace = traceback.format_exception(type(error), error, error.__traceback__)
        
        # Create a hash for pattern analysis
        trace_text = ''.join(full_trace)
        trace_hash = self.redaction_engine.hash_for_pattern_analysis(trace_text)
        
        # Sanitize the stack trace
        sanitized_lines = []
        for line in full_trace:
            # Remove file paths and replace with generic indicators
            sanitized_line = self._sanitize_stack_trace_line(line)
            sanitized_lines.append(sanitized_line)
        
        # Limit the sanitized trace size
        sanitized_trace = ''.join(sanitized_lines)
        if len(sanitized_trace) > self.config.max_context_size_bytes:
            sanitized_trace = sanitized_trace[:self.config.max_context_size_bytes] + "...[truncated]"
        
        return {
            'hash': trace_hash,
            'sanitized_trace': sanitized_trace
        }
    
    def _sanitize_stack_trace_line(self, line: str) -> str:
        """Sanitize a single stack trace line."""
        
        # Replace file paths with generic placeholders
        import re
        
        # Replace absolute paths
        line = re.sub(r'/[^/\s]+/', '/app/', line)
        line = re.sub(r'\\[^\\s]+\\', '\\app\\', line)
        
        # Replace line numbers with generic placeholders (keep error location pattern)
        line = re.sub(r', line \d+', ', line XXX', line)
        
        # Remove potential sensitive variable names in error messages
        # Keep the structure but remove specific values
        line = re.sub(r'"[^"]{20,}"', '"[REDACTED]"', line)
        line = re.sub(r"'[^']{20,}'", "'[REDACTED]'", line)
        
        return line
    
    def _process_log_event(
        self, 
        event: AnalyticsEvent, 
        additional_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Process and store a sanitized log event.
        
        Args:
            event: Analytics event to process
            additional_data: Additional data to include in log entry
        """
        
        with self._lock:
            # Create log entry
            log_entry = {
                'timestamp': event.timestamp,
                'event_type': event.event_type.value,
                'correlation_id': event.correlation_id,
                'source_component': event.source_component,
                'operation_category': event.operation_category,
                'data': event.data.copy()
            }
            
            # Add additional data if provided
            if additional_data:
                log_entry.update(additional_data)
            
            # Update statistics
            self._processing_stats['logs_processed'] += 1
            
            if isinstance(event, ErrorEvent):
                self._processing_stats['errors_classified'] += 1
                
                # Track error patterns
                if event.error_category:
                    self._error_categories[event.error_category] = \
                        self._error_categories.get(event.error_category, 0) + 1
                
                if event.stack_trace_hash:
                    self._error_patterns[event.stack_trace_hash] = \
                        self._error_patterns.get(event.stack_trace_hash, 0) + 1
            
            # Store log entry (with size limit)
            self._log_entries.append(log_entry)
            
            # Enforce size limits
            if len(self._log_entries) > self._max_log_entries:
                # Remove oldest entries
                self._log_entries = self._log_entries[-self._max_log_entries:]
            
            # Emit structured log
            self._emit_structured_log(log_entry)
    
    def _emit_structured_log(self, log_entry: Dict[str, Any]) -> None:
        """Emit structured log entry to configured logger.
        
        Args:
            log_entry: Sanitized log entry to emit
        """
        
        # Determine log level based on event type
        if log_entry.get('event_type') == 'error':
            log_level = logging.ERROR
        elif log_entry.get('event_type') in ('privacy_violation', 'security_event'):
            log_level = logging.WARNING
        else:
            log_level = logging.INFO
        
        # Emit as structured JSON
        self.logger.log(log_level, json.dumps(log_entry, separators=(',', ':')))
    
    def _log_privacy_violation(
        self, 
        original_event: AnalyticsEvent, 
        violations: List[str]
    ) -> None:
        """Log privacy violation detected during event processing.
        
        Args:
            original_event: Original event that contained violations
            violations: List of privacy violations found
        """
        
        violation_entry = {
            'timestamp': time.time(),
            'event_type': 'privacy_violation',
            'correlation_id': original_event.correlation_id,
            'original_event_type': original_event.event_type.value,
            'violations_detected': len(violations),
            'violation_categories': [v.split('.')[0] for v in violations[:5]],  # First part of violation path
            'source_component': 'privacy_monitor',
            'severity': 'high'
        }
        
        self._log_entries.append(violation_entry)
        self.logger.warning(json.dumps(violation_entry, separators=(',', ':')))
    
    def _log_export_safety_violation(
        self, 
        correlation_id: Optional[str], 
        violations: List[str]
    ) -> None:
        """Log export safety violation when preparing data for export.
        
        Args:
            correlation_id: Correlation ID of problematic entry
            violations: List of safety violations
        """
        
        safety_violation_entry = {
            'timestamp': time.time(),
            'event_type': 'export_safety_violation',
            'correlation_id': correlation_id or 'unknown',
            'violations_detected': len(violations),
            'violation_summary': violations[:3],  # First few violations
            'source_component': 'export_validator',
            'severity': 'critical'
        }
        
        self._log_entries.append(safety_violation_entry)
        self.logger.error(json.dumps(safety_violation_entry, separators=(',', ':')))
    
    def _cleanup_old_patterns(self, cutoff_time: float) -> None:
        """Clean up old error patterns and statistics.
        
        Args:
            cutoff_time: Timestamp cutoff for cleanup
        """
        
        # For now, just reset pattern counters when doing cleanup
        # In a more sophisticated implementation, we'd track timestamps per pattern
        if len(self._error_patterns) > 1000:  # Arbitrary limit
            # Keep only the most frequent patterns
            sorted_patterns = sorted(
                self._error_patterns.items(), 
                key=lambda x: x[1], 
                reverse=True
            )
            self._error_patterns = dict(sorted_patterns[:500])
        
        if len(self._error_categories) > 100:
            sorted_categories = sorted(
                self._error_categories.items(),
                key=lambda x: x[1],
                reverse=True
            )
            self._error_categories = dict(sorted_categories[:50])