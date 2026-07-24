"""Multi-pattern data redaction engine for privacy-safe analytics.

This module implements comprehensive sensitive data detection and redaction
using pattern matching, recursive processing, and data structure preservation.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Set, Tuple, Union

from .config import RedactionPatterns


class RedactionResult:
    """Result of a redaction operation with metadata."""
    
    def __init__(self, data: Any, redacted_fields: List[str], violations_found: List[str]):
        self.data = data
        self.redacted_fields = redacted_fields
        self.violations_found = violations_found
        
    def has_redactions(self) -> bool:
        """Check if any redactions were performed."""
        return len(self.redacted_fields) > 0
    
    def has_violations(self) -> bool:
        """Check if any privacy violations were detected."""
        return len(self.violations_found) > 0
    
    def is_safe(self) -> bool:
        """Check if data is safe for analytics use."""
        return not self.has_violations()


class RedactionEngine:
    """Multi-layer redaction engine with pattern-based sensitive data detection."""
    
    def __init__(self, patterns: RedactionPatterns):
        self.patterns = patterns
        self.redaction_marker = "[REDACTED]"
        
        # Compile regex patterns for performance
        self._compiled_field_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in patterns.field_patterns
        ]
        self._compiled_value_patterns = [
            re.compile(pattern) for pattern in patterns.value_patterns
        ]
        self._compiled_file_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in patterns.file_patterns
        ]
        
        # Track redaction statistics
        self._redaction_stats: Dict[str, int] = {}
    
    def sanitize(self, data: Any, context: str = "unknown") -> RedactionResult:
        """Recursively sanitize data structures removing all sensitive content.
        
        Args:
            data: The data structure to sanitize
            context: Context string for tracking redaction sources
            
        Returns:
            RedactionResult with sanitized data and redaction metadata
        """
        redacted_fields: List[str] = []
        violations_found: List[str] = []
        
        sanitized_data = self._sanitize_recursive(
            data, 
            redacted_fields, 
            violations_found,
            path=context,
            depth=0
        )
        
        return RedactionResult(sanitized_data, redacted_fields, violations_found)
    
    def _sanitize_recursive(
        self, 
        data: Any, 
        redacted_fields: List[str],
        violations_found: List[str], 
        path: str,
        depth: int
    ) -> Any:
        """Recursively process data structures for sensitive content."""
        
        # Prevent infinite recursion
        if depth > 20:
            violations_found.append(f"Maximum recursion depth exceeded at {path}")
            return self.redaction_marker
        
        if isinstance(data, dict):
            return self._sanitize_dict(data, redacted_fields, violations_found, path, depth)
        elif isinstance(data, (list, tuple)):
            return self._sanitize_sequence(data, redacted_fields, violations_found, path, depth)
        elif isinstance(data, str):
            return self._sanitize_string(data, redacted_fields, violations_found, path)
        elif isinstance(data, (int, float)):
            return self._sanitize_numeric(data, redacted_fields, violations_found, path)
        else:
            # For other types, check if the value itself is sensitive
            if self._is_sensitive_value(data):
                redacted_fields.append(f"{path}.<{type(data).__name__}>")
                return self.redaction_marker
            return data
    
    def _sanitize_dict(
        self, 
        data: dict, 
        redacted_fields: List[str],
        violations_found: List[str],
        path: str, 
        depth: int
    ) -> dict:
        """Sanitize dictionary structures with field name and value checking."""
        
        result = {}
        
        for key, value in data.items():
            key_str = str(key)
            field_path = f"{path}.{key_str}" if path != "unknown" else key_str
            
            # Check if the field name indicates sensitive data
            if self._is_sensitive_field(key_str):
                redacted_fields.append(field_path)
                result[key] = self.redaction_marker
                self._update_stats(f"field.{key_str}")
            else:
                # Recursively process the value
                result[key] = self._sanitize_recursive(
                    value, redacted_fields, violations_found, field_path, depth + 1
                )
        
        return result
    
    def _sanitize_sequence(
        self, 
        data: Union[list, tuple], 
        redacted_fields: List[str],
        violations_found: List[str],
        path: str, 
        depth: int
    ) -> Union[list, tuple]:
        """Sanitize list and tuple structures."""
        
        sanitized_items = []
        
        for i, item in enumerate(data):
            item_path = f"{path}[{i}]"
            sanitized_item = self._sanitize_recursive(
                item, redacted_fields, violations_found, item_path, depth + 1
            )
            sanitized_items.append(sanitized_item)
        
        # Return same type as input
        return type(data)(sanitized_items)
    
    def _sanitize_string(
        self, 
        data: str, 
        redacted_fields: List[str],
        violations_found: List[str],
        path: str
    ) -> str:
        """Sanitize string values using value pattern matching."""
        
        # Check for sensitive string patterns
        if self._is_sensitive_value(data):
            redacted_fields.append(path)
            self._update_stats(f"value.string")
            return self.redaction_marker
        
        # Check for file paths that might contain sensitive information
        if self._is_sensitive_file_path(data):
            redacted_fields.append(f"{path}.filepath")
            self._update_stats(f"value.filepath")
            return self.redaction_marker
        
        # Check for long strings that might be encoded data
        if len(data) > 1000:  # Arbitrary threshold for potentially large encoded data
            if self._looks_like_encoded_data(data):
                redacted_fields.append(f"{path}.encoded")
                self._update_stats(f"value.encoded")
                return self.redaction_marker
        
        return data
    
    def _sanitize_numeric(
        self, 
        data: Union[int, float], 
        redacted_fields: List[str],
        violations_found: List[str],
        path: str
    ) -> Union[int, float]:
        """Sanitize numeric values that might represent sensitive data."""
        
        # Check for numbers that might be timestamps, hashes, or IDs
        if isinstance(data, int):
            # Very large integers might be encoded sensitive data
            if data > 2**32:  # Larger than typical counters/IDs
                str_data = str(data)
                if len(str_data) > 10 and self._looks_like_encoded_data(str_data):
                    redacted_fields.append(f"{path}.large_int")
                    self._update_stats(f"value.large_int")
                    return 0
        
        return data
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field name indicates sensitive data using compiled patterns."""
        
        for pattern in self._compiled_field_patterns:
            if pattern.search(field_name):
                return True
        
        return False
    
    def _is_sensitive_value(self, value: Any) -> bool:
        """Check if a value contains sensitive data patterns."""
        
        if not isinstance(value, str):
            return False
        
        # Skip very short strings
        if len(value) < 8:
            return False
        
        for pattern in self._compiled_value_patterns:
            if pattern.search(value):
                return True
        
        return False
    
    def _is_sensitive_file_path(self, value: str) -> bool:
        """Check if a string represents a sensitive file path."""
        
        for pattern in self._compiled_file_patterns:
            if pattern.search(value):
                return True
        
        return False
    
    def _looks_like_encoded_data(self, value: str) -> bool:
        """Heuristic check for encoded data (base64, hex, etc.)."""
        
        # Check for high proportion of alphanumeric characters
        if len(value) < 20:
            return False
        
        alnum_count = sum(1 for c in value if c.isalnum())
        alnum_ratio = alnum_count / len(value)
        
        # High alphanumeric ratio suggests encoded data
        if alnum_ratio > 0.8:
            return True
        
        # Check for base64-like patterns
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        base64_count = sum(1 for c in value if c in base64_chars)
        base64_ratio = base64_count / len(value)
        
        if base64_ratio > 0.9:
            return True
        
        # Check for hex-like patterns
        try:
            int(value, 16)
            return len(value) > 32  # Longer hex strings are suspicious
        except ValueError:
            pass
        
        return False
    
    def _update_stats(self, category: str) -> None:
        """Update redaction statistics for monitoring."""
        self._redaction_stats[category] = self._redaction_stats.get(category, 0) + 1
    
    def get_redaction_stats(self) -> Dict[str, int]:
        """Get redaction statistics for monitoring and analysis."""
        return self._redaction_stats.copy()
    
    def reset_stats(self) -> None:
        """Reset redaction statistics (useful for testing)."""
        self._redaction_stats.clear()
    
    def sanitize_endpoint_pattern(self, path: str) -> str:
        """Sanitize URL endpoint patterns to remove sensitive identifiers.
        
        This method converts URL paths to generic patterns suitable for metrics
        while removing any user-provided data or sensitive identifiers.
        
        Args:
            path: URL path to sanitize
            
        Returns:
            Sanitized endpoint pattern safe for analytics
        """
        
        if not path or not isinstance(path, str):
            return "unmatched"
        
        # Remove query parameters and fragments
        path = path.split('?')[0].split('#')[0]
        
        # Convert path segments that look like IDs or hashes to patterns
        segments = path.split('/')
        sanitized_segments = []
        
        for segment in segments:
            if not segment:  # Empty segment (leading slash)
                sanitized_segments.append('')
                continue
            
            # Check if segment looks like a sensitive identifier
            if self._looks_like_id_or_hash(segment):
                sanitized_segments.append('{id}')
            elif segment.lower() in ('proof', 'witness', 'video', 'embed', 'extract'):
                # Keep endpoint names but sanitize any following segments
                sanitized_segments.append(segment.lower())
            elif len(segment) > 50:  # Very long segments are suspicious
                sanitized_segments.append('{long_param}')
            else:
                # Keep normal path segments
                sanitized_segments.append(segment.lower())
        
        sanitized_path = '/'.join(sanitized_segments)
        
        # Ensure we don't leak sensitive patterns but allow normal endpoints
        sensitive_detected = False
        for pattern in self._compiled_field_patterns:
            if pattern.search(sanitized_path):
                sensitive_detected = True
                break
        
        if sensitive_detected:
            return "/api/{sensitive}"
        
        return sanitized_path or "/"
    
    def _looks_like_id_or_hash(self, segment: str) -> bool:
        """Check if a URL segment looks like an ID or hash."""
        
        if len(segment) < 8:
            return False
        
        # UUID pattern
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment.lower()):
            return True
        
        # Hex hash pattern (32+ chars)
        if re.match(r'^[0-9a-fA-F]{32,}$', segment):
            return True
        
        # Base64-like pattern
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', segment):
            return True
        
        # High proportion of numbers/letters suggests ID
        alnum_count = sum(1 for c in segment if c.isalnum())
        if alnum_count / len(segment) > 0.8 and len(segment) > 15:
            return True
        
        return False
    
    def sanitize_error_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize error context for safe logging.
        
        Args:
            context: Error context dictionary
            
        Returns:
            Sanitized context safe for error logs
        """
        
        # Define allowed context fields that are safe for error logging
        safe_fields = {
            'method', 'endpoint_pattern', 'status_code', 'timestamp',
            'correlation_id', 'error_type', 'error_category', 'user_agent_category'
        }
        
        sanitized = {}
        
        for key, value in context.items():
            if key in safe_fields:
                # Even safe fields need value sanitization
                if isinstance(value, str) and key == 'endpoint_pattern':
                    sanitized[key] = self.sanitize_endpoint_pattern(value)
                elif not self._is_sensitive_value(str(value)):
                    sanitized[key] = value
                else:
                    sanitized[key] = self.redaction_marker
            elif key in ('endpoint', 'path'):
                # Convert endpoint/path to sanitized endpoint_pattern
                sanitized['endpoint_pattern'] = self.sanitize_endpoint_pattern(str(value))
            elif not self._is_sensitive_field(key):
                # Allow non-sensitive fields with value sanitization
                result = self.sanitize(value, f"context.{key}")
                if not result.has_violations():
                    sanitized[key] = result.data
        
        return sanitized
    
    def hash_for_pattern_analysis(self, data: str) -> str:
        """Create a hash of sensitive data for pattern analysis without exposing content.
        
        This allows tracking error patterns and frequencies without storing sensitive data.
        
        Args:
            data: String to hash
            
        Returns:
            SHA-256 hash of the input for pattern tracking
        """
        
        if not isinstance(data, str):
            data = str(data)
        
        # Use a salt to prevent rainbow table attacks
        salt = "harpocrates_analytics_pattern_"
        salted_data = salt + data
        
        return hashlib.sha256(salted_data.encode('utf-8')).hexdigest()[:16]
    
    def validate_export_safety(self, export_data: Any) -> Tuple[bool, List[str]]:
        """Validate that export data contains no sensitive information.
        
        Args:
            export_data: Data structure to validate for export
            
        Returns:
            Tuple of (is_safe, list_of_violations)
        """
        
        result = self.sanitize(export_data, "export_validation")
        
        # If any redactions were needed, the export is not safe
        if result.has_redactions():
            return False, result.redacted_fields
        
        # If violations were detected, the export is not safe
        if result.has_violations():
            return False, result.violations_found
        
        return True, []