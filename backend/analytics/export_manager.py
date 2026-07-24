"""Data export and verification system for privacy-safe analytics."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .config import ExportConfig
from .redaction import RedactionEngine


@dataclass
class ExportManifest:
    """Manifest for analytics data exports."""
    
    export_id: str
    timestamp: float
    record_count: int
    verification_hash: str
    privacy_verified: bool
    export_format: str
    compression_enabled: bool
    data_types: List[str]
    retention_policy: str
    client_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert manifest to dictionary."""
        return {
            'export_id': self.export_id,
            'timestamp': self.timestamp,
            'record_count': self.record_count,
            'verification_hash': self.verification_hash,
            'privacy_verified': self.privacy_verified,
            'export_format': self.export_format,
            'compression_enabled': self.compression_enabled,
            'data_types': self.data_types,
            'retention_policy': self.retention_policy,
            'client_id': self.client_id
        }


@dataclass
class AuditRecord:
    """Audit record for export operations."""
    
    audit_id: str
    export_id: str
    timestamp: float
    client_id: Optional[str]
    operation: str  # export, download, delete
    data_types: List[str]
    record_count: int
    verification_status: str  # passed, failed, skipped
    client_ip_hash: Optional[str] = None
    user_agent_hash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit record to dictionary."""
        return {
            'audit_id': self.audit_id,
            'export_id': self.export_id,
            'timestamp': self.timestamp,
            'client_id': self.client_id,
            'operation': self.operation,
            'data_types': self.data_types,
            'record_count': self.record_count,
            'verification_status': self.verification_status,
            'client_ip_hash': self.client_ip_hash,
            'user_agent_hash': self.user_agent_hash
        }


class ExportVerificationError(Exception):
    """Exception raised when export data fails privacy verification."""
    pass


class ExportManager:
    """Manages analytics data export with privacy verification and audit trails."""
    
    def __init__(self, config: ExportConfig, redaction_engine: RedactionEngine):
        self.config = config
        self.redaction_engine = redaction_engine
        
        # Export history and audit trail
        self._export_history: Dict[str, ExportManifest] = {}
        self._audit_trail: List[AuditRecord] = []
        
        # Export cache for performance
        self._export_cache: Dict[str, Tuple[str, float]] = {}  # export_id -> (data, timestamp)
        self._cache_ttl_seconds = 300  # 5 minutes
        
        # Verification statistics
        self._verification_stats = {
            'exports_created': 0,
            'exports_verified': 0,
            'verification_failures': 0,
            'privacy_violations_found': 0,
            'cache_hits': 0,
            'cache_misses': 0,
        }
    
    def create_metrics_export(
        self,
        metrics_data: Dict[str, Any],
        client_id: Optional[str] = None,
        export_format: str = "prometheus"
    ) -> Tuple[str, ExportManifest]:
        """Create metrics export with privacy verification.
        
        Args:
            metrics_data: Raw metrics data to export
            client_id: Optional client identifier
            export_format: Export format ("prometheus" or "json")
            
        Returns:
            Tuple of (exported_data, export_manifest)
        """
        
        if not self.config.enabled:
            raise ValueError("Export functionality is disabled")
        
        # Generate export ID
        export_id = self._generate_export_id()
        
        # Verify data privacy before export
        if self.config.verify_before_export:
            self._verify_export_privacy(metrics_data, "metrics")
        
        # Format data based on requested format
        if export_format.lower() == "prometheus":
            formatted_data = self._format_prometheus_export(metrics_data)
            data_types = ["metrics", "prometheus"]
        elif export_format.lower() == "json":
            formatted_data = self._format_json_export(metrics_data, "metrics")
            data_types = ["metrics", "json"]
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        # Apply compression if enabled
        final_data = formatted_data
        if self.config.compress_exports:
            final_data = self._compress_data(formatted_data)
        
        # Create verification hash
        verification_hash = self._create_verification_hash(final_data)
        
        # Create export manifest
        manifest = ExportManifest(
            export_id=export_id,
            timestamp=time.time(),
            record_count=self._count_records(metrics_data),
            verification_hash=verification_hash,
            privacy_verified=self.config.verify_before_export,
            export_format=export_format,
            compression_enabled=self.config.compress_exports,
            data_types=data_types,
            retention_policy=f"metrics_{self.config.retention_policy if hasattr(self.config, 'retention_policy') else 'standard'}",
            client_id=client_id
        )
        
        # Store export and audit
        self._store_export(export_id, final_data, manifest)
        self._create_audit_record(manifest, "export", client_id)
        
        # Update statistics
        self._verification_stats['exports_created'] += 1
        if self.config.verify_before_export:
            self._verification_stats['exports_verified'] += 1
        
        return final_data, manifest
    
    def create_logs_export(
        self,
        logs_data: List[Dict[str, Any]],
        client_id: Optional[str] = None,
        time_range: Optional[Tuple[float, float]] = None
    ) -> Tuple[str, ExportManifest]:
        """Create logs export with privacy verification.
        
        Args:
            logs_data: Log entries to export
            client_id: Optional client identifier
            time_range: Optional time range filter (start, end)
            
        Returns:
            Tuple of (exported_data, export_manifest)
        """
        
        if not self.config.enabled:
            raise ValueError("Export functionality is disabled")
        
        # Generate export ID
        export_id = self._generate_export_id()
        
        # Filter logs by time range if specified
        filtered_logs = logs_data
        if time_range:
            start_time, end_time = time_range
            filtered_logs = [
                log for log in logs_data
                if start_time <= log.get('timestamp', 0) <= end_time
            ]
        
        # Verify data privacy before export
        if self.config.verify_before_export:
            self._verify_export_privacy(filtered_logs, "logs")
        
        # Create export data structure
        export_data = {
            'metadata': {
                'export_id': export_id,
                'export_timestamp': time.time(),
                'total_entries': len(filtered_logs),
                'time_range': time_range,
                'privacy_verified': self.config.verify_before_export,
                'redaction_engine_version': '1.0'
            },
            'logs': filtered_logs
        }
        
        # Format as JSON
        formatted_data = self._format_json_export(export_data, "logs")
        
        # Apply compression if enabled
        final_data = formatted_data
        if self.config.compress_exports:
            final_data = self._compress_data(formatted_data)
        
        # Create verification hash
        verification_hash = self._create_verification_hash(final_data)
        
        # Create export manifest
        manifest = ExportManifest(
            export_id=export_id,
            timestamp=time.time(),
            record_count=len(filtered_logs),
            verification_hash=verification_hash,
            privacy_verified=self.config.verify_before_export,
            export_format="json",
            compression_enabled=self.config.compress_exports,
            data_types=["logs", "json"],
            retention_policy=f"logs_{self.config.retention_policy if hasattr(self.config, 'retention_policy') else 'standard'}",
            client_id=client_id
        )
        
        # Store export and audit
        self._store_export(export_id, final_data, manifest)
        self._create_audit_record(manifest, "export", client_id)
        
        # Update statistics
        self._verification_stats['exports_created'] += 1
        if self.config.verify_before_export:
            self._verification_stats['exports_verified'] += 1
        
        return final_data, manifest
    
    def get_export(self, export_id: str, client_id: Optional[str] = None) -> Tuple[str, ExportManifest]:
        """Retrieve a previously created export.
        
        Args:
            export_id: Export identifier
            client_id: Optional client identifier for audit
            
        Returns:
            Tuple of (export_data, export_manifest)
        """
        
        # Check cache first
        if export_id in self._export_cache:
            cached_data, cache_time = self._export_cache[export_id]
            if time.time() - cache_time < self._cache_ttl_seconds:
                self._verification_stats['cache_hits'] += 1
                manifest = self._export_history[export_id]
                self._create_audit_record(manifest, "download", client_id)
                return cached_data, manifest
        
        self._verification_stats['cache_misses'] += 1
        
        # Retrieve from storage
        if export_id not in self._export_history:
            raise ValueError(f"Export not found: {export_id}")
        
        manifest = self._export_history[export_id]
        
        # Verify client access (basic check)
        if manifest.client_id and client_id and manifest.client_id != client_id:
            raise PermissionError(f"Access denied to export {export_id}")
        
        # Note: In a real implementation, you'd retrieve from persistent storage
        # For now, we'll return the cached data or raise an error
        if export_id not in self._export_cache:
            raise ValueError(f"Export data no longer available: {export_id}")
        
        cached_data, _ = self._export_cache[export_id]
        
        # Create audit record
        self._create_audit_record(manifest, "download", client_id)
        
        return cached_data, manifest
    
    def list_exports(
        self,
        client_id: Optional[str] = None,
        data_type_filter: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[ExportManifest]:
        """List available exports with optional filtering.
        
        Args:
            client_id: Optional client filter
            data_type_filter: Optional data type filter
            limit: Maximum number of results
            
        Returns:
            List of export manifests
        """
        
        manifests = []
        
        for manifest in self._export_history.values():
            # Apply client filter
            if client_id and manifest.client_id != client_id:
                continue
            
            # Apply data type filter
            if data_type_filter and data_type_filter not in manifest.data_types:
                continue
            
            manifests.append(manifest)
        
        # Sort by timestamp (most recent first)
        manifests.sort(key=lambda m: m.timestamp, reverse=True)
        
        # Apply limit
        if limit and len(manifests) > limit:
            manifests = manifests[:limit]
        
        return manifests
    
    def delete_export(self, export_id: str, client_id: Optional[str] = None) -> bool:
        """Delete an export and its associated data.
        
        Args:
            export_id: Export identifier
            client_id: Optional client identifier for audit
            
        Returns:
            True if successfully deleted
        """
        
        if export_id not in self._export_history:
            return False
        
        manifest = self._export_history[export_id]
        
        # Verify client access
        if manifest.client_id and client_id and manifest.client_id != client_id:
            raise PermissionError(f"Access denied to export {export_id}")
        
        # Remove from storage and cache
        del self._export_history[export_id]
        if export_id in self._export_cache:
            del self._export_cache[export_id]
        
        # Create audit record
        self._create_audit_record(manifest, "delete", client_id)
        
        return True
    
    def get_audit_trail(
        self,
        export_id: Optional[str] = None,
        client_id: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None
    ) -> List[AuditRecord]:
        """Get audit trail with optional filtering.
        
        Args:
            export_id: Optional export ID filter
            client_id: Optional client ID filter
            start_time: Optional start time filter
            end_time: Optional end time filter
            
        Returns:
            List of audit records
        """
        
        if not self.config.create_audit_trail:
            return []
        
        filtered_records = []
        
        for record in self._audit_trail:
            # Apply filters
            if export_id and record.export_id != export_id:
                continue
            if client_id and record.client_id != client_id:
                continue
            if start_time and record.timestamp < start_time:
                continue
            if end_time and record.timestamp > end_time:
                continue
            
            filtered_records.append(record)
        
        # Sort by timestamp (most recent first)
        filtered_records.sort(key=lambda r: r.timestamp, reverse=True)
        
        return filtered_records
    
    def get_verification_stats(self) -> Dict[str, Any]:
        """Get export verification statistics.
        
        Returns:
            Dictionary containing verification statistics
        """
        
        return {
            **self._verification_stats,
            'total_exports': len(self._export_history),
            'cached_exports': len(self._export_cache),
            'audit_records': len(self._audit_trail),
            'stats_timestamp': time.time()
        }
    
    def cleanup_old_exports(self, retention_hours: int = 24) -> int:
        """Clean up old exports based on retention policy.
        
        Args:
            retention_hours: Hours to retain exports
            
        Returns:
            Number of exports cleaned up
        """
        
        cutoff_time = time.time() - (retention_hours * 3600)
        removed_count = 0
        
        # Find exports to remove
        exports_to_remove = []
        for export_id, manifest in self._export_history.items():
            if manifest.timestamp < cutoff_time:
                exports_to_remove.append(export_id)
        
        # Remove old exports
        for export_id in exports_to_remove:
            try:
                self.delete_export(export_id)
                removed_count += 1
            except Exception:
                # Don't fail cleanup on individual export errors
                pass
        
        # Clean up old cache entries
        cache_to_remove = []
        for export_id, (_, cache_time) in self._export_cache.items():
            if cache_time < cutoff_time:
                cache_to_remove.append(export_id)
        
        for export_id in cache_to_remove:
            del self._export_cache[export_id]
        
        # Clean up old audit records (keep longer retention)
        audit_cutoff = time.time() - (retention_hours * 3 * 3600)  # 3x longer
        self._audit_trail = [
            record for record in self._audit_trail
            if record.timestamp >= audit_cutoff
        ]
        
        return removed_count
    
    def _verify_export_privacy(self, data: Any, data_type: str) -> None:
        """Verify export data contains no sensitive information.
        
        Args:
            data: Data to verify
            data_type: Type of data being verified
            
        Raises:
            ExportVerificationError: If sensitive data is found
        """
        
        is_safe, violations = self.redaction_engine.validate_export_safety(data)
        
        if not is_safe:
            self._verification_stats['verification_failures'] += 1
            self._verification_stats['privacy_violations_found'] += len(violations)
            
            if self.config.fail_on_sensitive_data:
                raise ExportVerificationError(
                    f"Export contains sensitive data in {data_type}: {violations[:5]}"
                )
    
    def _format_prometheus_export(self, metrics_data: Dict[str, Any]) -> str:
        """Format metrics data for Prometheus export.
        
        Args:
            metrics_data: Metrics data to format
            
        Returns:
            Prometheus-formatted string
        """
        
        # If the data is already prometheus formatted, return as-is
        if isinstance(metrics_data, str):
            return metrics_data
        
        # Otherwise, convert dict to prometheus format
        lines = []
        timestamp = int(time.time() * 1000)  # Prometheus timestamp
        
        for metric_name, metric_value in metrics_data.items():
            if isinstance(metric_value, dict):
                # Handle nested metrics
                for sub_metric, value in metric_value.items():
                    if isinstance(value, (int, float)):
                        lines.append(f"{metric_name}_{sub_metric} {value} {timestamp}")
            elif isinstance(metric_value, (int, float)):
                lines.append(f"{metric_name} {metric_value} {timestamp}")
        
        return '\n'.join(lines) + '\n'
    
    def _format_json_export(self, data: Any, data_type: str) -> str:
        """Format data for JSON export.
        
        Args:
            data: Data to format
            data_type: Type of data being formatted
            
        Returns:
            JSON-formatted string
        """
        
        # Create export wrapper
        export_wrapper = {
            'export_metadata': {
                'data_type': data_type,
                'export_timestamp': time.time(),
                'format_version': '1.0',
                'privacy_verified': self.config.verify_before_export
            },
            'data': data
        }
        
        return json.dumps(export_wrapper, separators=(',', ':'), sort_keys=True)
    
    def _compress_data(self, data: str) -> str:
        """Compress data using gzip and encode as base64.
        
        Args:
            data: String data to compress
            
        Returns:
            Base64-encoded compressed data
        """
        
        data_bytes = data.encode('utf-8')
        compressed = gzip.compress(data_bytes, compresslevel=6)
        return base64.b64encode(compressed).decode('ascii')
    
    def _create_verification_hash(self, data: str) -> str:
        """Create verification hash for data integrity.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-256 hash of the data
        """
        
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def _count_records(self, data: Any) -> int:
        """Count the number of records in export data.
        
        Args:
            data: Data structure to count
            
        Returns:
            Number of records
        """
        
        if isinstance(data, list):
            return len(data)
        elif isinstance(data, dict):
            # For metrics, count the number of metric families
            return len(data)
        elif isinstance(data, str):
            # For prometheus format, count non-empty lines
            return len([line for line in data.split('\n') if line.strip()])
        else:
            return 1
    
    def _generate_export_id(self) -> str:
        """Generate unique export identifier.
        
        Returns:
            Unique export ID
        """
        
        # Use timestamp + UUID for uniqueness and sortability
        timestamp_ms = int(time.time() * 1000)
        unique_part = str(uuid.uuid4())[:8]
        return f"exp_{timestamp_ms}_{unique_part}"
    
    def _store_export(self, export_id: str, data: str, manifest: ExportManifest) -> None:
        """Store export data and manifest.
        
        Args:
            export_id: Export identifier
            data: Export data
            manifest: Export manifest
        """
        
        # Store manifest
        self._export_history[export_id] = manifest
        
        # Cache the data temporarily
        self._export_cache[export_id] = (data, time.time())
        
        # In a real implementation, you would also persist to external storage
    
    def _create_audit_record(
        self, 
        manifest: ExportManifest, 
        operation: str, 
        client_id: Optional[str] = None
    ) -> None:
        """Create audit record for export operation.
        
        Args:
            manifest: Export manifest
            operation: Operation type (export, download, delete)
            client_id: Optional client identifier
        """
        
        if not self.config.create_audit_trail:
            return
        
        audit_record = AuditRecord(
            audit_id=str(uuid.uuid4()),
            export_id=manifest.export_id,
            timestamp=time.time(),
            client_id=client_id,
            operation=operation,
            data_types=manifest.data_types,
            record_count=manifest.record_count,
            verification_status="passed" if manifest.privacy_verified else "skipped"
        )
        
        self._audit_trail.append(audit_record)
        
        # Limit audit trail size
        if len(self._audit_trail) > 10000:
            # Keep only recent records
            self._audit_trail = self._audit_trail[-5000:]