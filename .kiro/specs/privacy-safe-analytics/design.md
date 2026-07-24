# Design Document

## System Overview

The Privacy-Safe Analytics System provides comprehensive observability, performance monitoring, and error telemetry for the Harpocrates Evidence Protocol while maintaining strict privacy guarantees. The system employs a defense-in-depth approach with multiple layers of data sanitization, redaction, and access controls to ensure that sensitive cryptographic data, videos, and user information never enter analytics pipelines.

## Architecture

### Core Components

#### Analytics Engine
Central orchestrator that coordinates all analytics operations and enforces privacy policies.

```python
class AnalyticsEngine:
    def __init__(self, config: AnalyticsConfig):
        self.redaction_engine = RedactionEngine(config.redaction_patterns)
        self.metrics_collector = MetricsCollector(config.metrics_config)
        self.log_processor = LogProcessor(config.logging_config)
        self.export_manager = ExportManager(config.export_config)
        
    def process_event(self, event: AnalyticsEvent) -> None:
        # Apply multi-layer redaction before any processing
        sanitized_event = self.redaction_engine.sanitize(event)
        
        if sanitized_event.is_metric():
            self.metrics_collector.record(sanitized_event)
        elif sanitized_event.is_log():
            self.log_processor.process(sanitized_event)
```

#### Redaction Engine
Multi-pattern data sanitization component that removes sensitive data through recursive processing.

```python
class RedactionEngine:
    def __init__(self, patterns: RedactionPatterns):
        self.sensitive_field_patterns = patterns.field_patterns
        self.sensitive_value_patterns = patterns.value_patterns
        self.redaction_marker = "[REDACTED]"
        
    def sanitize(self, data: Any) -> Any:
        """Recursively sanitize data structures removing all sensitive content"""
        if isinstance(data, dict):
            return self._sanitize_dict(data)
        elif isinstance(data, (list, tuple)):
            return self._sanitize_sequence(data)
        elif isinstance(data, str):
            return self._sanitize_string(data)
        else:
            return data if not self._is_sensitive_value(data) else self.redaction_marker
            
    def _sanitize_dict(self, data: dict) -> dict:
        result = {}
        for key, value in data.items():
            if self._is_sensitive_field(key):
                result[key] = self.redaction_marker
            else:
                result[key] = self.sanitize(value)
        return result
```

#### Metrics Collector
Aggregates operational metrics using sanitized endpoint patterns and categorized operations.

```python
class MetricsCollector:
    def __init__(self, config: MetricsConfig):
        self.request_counter = Counter()
        self.response_counter = Counter() 
        self.latency_histogram = Histogram()
        self.size_histogram = Histogram()
        self.resource_gauge = Gauge()
        
    def record_request(self, request: SanitizedRequest) -> None:
        # Use only sanitized endpoint patterns
        pattern = self._extract_endpoint_pattern(request.path)
        self.request_counter.inc({
            'endpoint_pattern': pattern,
            'method': request.method
        })
        
    def record_latency(self, operation_category: str, duration: float) -> None:
        # Use operation categories only, never specific content
        self.latency_histogram.observe(duration, {
            'operation_type': operation_category
        })
```

#### Log Processor  
Processes error logs and system events with comprehensive context sanitization.

```python
class LogProcessor:
    def __init__(self, config: LogConfig):
        self.redaction_engine = RedactionEngine(config.redaction_patterns)
        self.correlation_id_generator = CorrelationIDGenerator()
        
    def process_error(self, error: Exception, context: RequestContext) -> None:
        sanitized_context = self._sanitize_error_context(context)
        
        log_entry = {
            'timestamp': time.time(),
            'correlation_id': self.correlation_id_generator.generate(),
            'error_type': type(error).__name__,
            'stack_trace': self._sanitize_stack_trace(error),
            'request_method': context.method,
            'endpoint_pattern': self._sanitize_endpoint(context.path),
            # Never include payloads or response bodies
        }
        
        self._emit_log(log_entry)
```

### Data Flow Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───▶│ Redaction Engine │───▶│ Analytics Engine│
│     Events      │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        │
                       ┌──────────────────┐              │
                       │ Sensitive Data   │              │
                       │   Detection      │              │
                       └──────────────────┘              │
                                                         │
┌─────────────────┐    ┌──────────────────┐              │
│ Metrics Storage │◀───│ Metrics Collector│◀─────────────┤
└─────────────────┘    └──────────────────┘              │
                                                         │
┌─────────────────┐    ┌──────────────────┐              │
│   Log Storage   │◀───│  Log Processor   │◀─────────────┘
└─────────────────┘    └──────────────────┘
```

### Privacy Protection Layers

#### Layer 1: Input Sanitization
All data entering the analytics system passes through immediate sanitization.

```python
class InputSanitizer:
    SENSITIVE_PATTERNS = {
        # Cryptographic data patterns
        'nullifier': r'nullifier|field_element|commitment',
        'proof': r'proof_data|witness_data|circuit_input',
        'wallet': r'signature|private_key|secret_key',
        'credential': r'credential|identity|silent_witness',
        
        # File and content patterns  
        'video': r'video|mp4|avi|mov|metadata_hash',
        'file_content': r'file_data|content|payload',
    }
    
    def sanitize_input(self, data: Any) -> Any:
        """Apply immediate sanitization to all analytics inputs"""
        return self._recursive_sanitize(data, self.SENSITIVE_PATTERNS)
```

#### Layer 2: Context Redaction
Request and response contexts are sanitized before error processing.

```python
class ContextRedactor:
    def redact_request_context(self, context: RequestContext) -> SanitizedContext:
        return SanitizedContext(
            method=context.method,
            endpoint_pattern=self._sanitize_endpoint(context.path),
            timestamp=context.timestamp,
            correlation_id=context.correlation_id,
            # Never include: payloads, headers with auth, response bodies
        )
```

#### Layer 3: Export Verification
All exported data undergoes final verification to ensure no sensitive data leakage.

```python
class ExportVerifier:
    def verify_export_safety(self, export_data: ExportData) -> VerificationResult:
        violations = []
        
        for record in export_data.records:
            if self._contains_sensitive_data(record):
                violations.append(f"Sensitive data found in record {record.id}")
                
        return VerificationResult(
            is_safe=len(violations) == 0,
            violations=violations
        )
```

## Component Interfaces

### Analytics Event Interface
```python
@dataclass
class AnalyticsEvent:
    event_type: EventType
    timestamp: float
    correlation_id: str
    data: Dict[str, Any]
    
    def is_metric(self) -> bool:
        return self.event_type in [EventType.REQUEST, EventType.PERFORMANCE]
        
    def is_log(self) -> bool:
        return self.event_type in [EventType.ERROR, EventType.SYSTEM]
```

### Redaction Interface
```python
class RedactionResult:
    def __init__(self, data: Any, redacted_fields: List[str]):
        self.data = data
        self.redacted_fields = redacted_fields
        
    def has_redactions(self) -> bool:
        return len(self.redacted_fields) > 0
```

### Metrics Interface
```python
class MetricRecord:
    def __init__(self, name: str, value: float, labels: Dict[str, str], timestamp: float):
        self.name = name
        self.value = value
        self.labels = labels  # Only sanitized labels allowed
        self.timestamp = timestamp
```

## Data Models

### Configuration Model
```python
@dataclass
class AnalyticsConfig:
    redaction_patterns: RedactionPatterns
    metrics_config: MetricsConfig
    logging_config: LogConfig
    export_config: ExportConfig
    retention_config: RetentionConfig
    
@dataclass  
class RedactionPatterns:
    field_patterns: List[str]  # Regex patterns for sensitive field names
    value_patterns: List[str]  # Patterns for sensitive values
    file_patterns: List[str]   # Patterns for sensitive file paths
```

### Event Model
```python
class RequestEvent(AnalyticsEvent):
    method: str
    endpoint_pattern: str  # Sanitized pattern only
    status_code: int
    latency_ms: float
    size_bytes: int  # Without content identification
    
class ErrorEvent(AnalyticsEvent):
    error_type: str
    sanitized_context: SanitizedContext
    stack_trace: str  # Sanitized stack trace
```

### Export Model
```python
@dataclass
class ExportManifest:
    export_id: str
    timestamp: float
    record_count: int
    verification_hash: str
    privacy_verified: bool
```

## Error Handling

### Error Classification
```python
class ErrorClassifier:
    def classify_error(self, error: Exception, context: RequestContext) -> ErrorClassification:
        classification = ErrorClassification(
            category=self._get_error_category(error),
            sensitivity_level=self._assess_sensitivity(context),
            redaction_required=self._requires_redaction(error, context)
        )
        return classification
```

### Sanitized Error Reporting
```python
class SafeErrorReporter:
    def report_error(self, error: Exception, context: RequestContext) -> None:
        if self._involves_sensitive_data(context):
            # Heavy redaction for sensitive operations
            sanitized_report = self._create_minimal_report(error, context)
        else:
            # Standard sanitization for non-sensitive operations  
            sanitized_report = self._create_standard_report(error, context)
            
        self.log_processor.process_error(sanitized_report)
```

## Performance Monitoring

### Operation Categorization
```python
class OperationCategorizer:
    CATEGORIES = {
        'steganography': ['embed', 'extract', 'hash'],
        'cryptography': ['generate_proof', 'verify_proof'],  
        'database': ['query', 'insert', 'update'],
        'network': ['stellar_submit', 'stellar_query'],
        'storage': ['file_read', 'file_write']
    }
    
    def categorize_operation(self, operation_name: str) -> str:
        for category, operations in self.CATEGORIES.items():
            if any(op in operation_name.lower() for op in operations):
                return category
        return 'unknown'
```

### Resource Monitoring
```python
class ResourceMonitor:
    def monitor_operation(self, operation_category: str) -> ResourceUsage:
        with self.resource_tracker.track(operation_category) as tracker:
            # Monitor CPU, memory, I/O without correlating to specific content
            return ResourceUsage(
                cpu_percent=tracker.cpu_usage,
                memory_mb=tracker.memory_usage,
                io_operations=tracker.io_count,
                category=operation_category  # Never specific content
            )
```

## Security Controls

### Authentication and Authorization
```python
class AnalyticsAuthenticator:
    def authenticate_client(self, client_credentials: ClientCredentials) -> AuthResult:
        # Verify client certificates and API keys
        if not self._verify_credentials(client_credentials):
            return AuthResult.FAILED
            
        # Check client permissions for analytics data access
        if not self._check_permissions(client_credentials.client_id):
            return AuthResult.UNAUTHORIZED
            
        return AuthResult.SUCCESS
```

### Rate Limiting
```python
class AnalyticsRateLimiter:
    def __init__(self, config: RateLimitConfig):
        self.limits = {
            'metrics_query': RateLimit(requests=1000, window=3600),
            'log_query': RateLimit(requests=500, window=3600),
            'export_request': RateLimit(requests=10, window=3600)
        }
        
    def check_rate_limit(self, client_id: str, operation: str) -> RateLimitResult:
        return self._check_limit(client_id, operation, self.limits[operation])
```

### Encryption
```python
class AnalyticsEncryption:
    def encrypt_transmission(self, data: AnalyticsData) -> EncryptedData:
        # Use TLS 1.3 for all analytics data transmission
        return self.tls_encoder.encrypt(data)
        
    def encrypt_storage(self, data: AnalyticsData) -> EncryptedStorageData:
        # Use AES-256 for analytics data at rest
        return self.aes_encoder.encrypt(data, self.storage_key)
```

## Configuration Management

### Runtime Configuration
```python
class ConfigurationManager:
    def update_config(self, new_config: AnalyticsConfig) -> ConfigUpdateResult:
        # Validate privacy compliance
        validation_result = self._validate_privacy_compliance(new_config)
        if not validation_result.is_valid:
            return ConfigUpdateResult.REJECTED
            
        # Apply configuration atomically
        self._backup_current_config()
        try:
            self._apply_config(new_config)
            self._audit_config_change(new_config)
            return ConfigUpdateResult.SUCCESS
        except Exception as e:
            self._rollback_config()
            return ConfigUpdateResult.FAILED
```

### Environment Profiles
```python
class EnvironmentProfileManager:
    def load_profile(self, environment: str) -> AnalyticsConfig:
        profile_path = f"configs/{environment}/analytics.json"
        base_config = self._load_base_config()
        env_overrides = self._load_environment_overrides(profile_path)
        return self._merge_configs(base_config, env_overrides)
```

## Data Export and Integration

### Prometheus Metrics Export
```python
class PrometheusExporter:
    def export_metrics(self) -> PrometheusMetrics:
        metrics = []
        
        # Export only sanitized, aggregated metrics
        for metric_name, metric_data in self.metrics_collector.get_metrics():
            prometheus_metric = self._convert_to_prometheus_format(
                name=metric_name,
                data=metric_data,
                labels=self._sanitize_labels(metric_data.labels)
            )
            metrics.append(prometheus_metric)
            
        return PrometheusMetrics(metrics)
```

### JSON Log Export
```python
class JSONLogExporter:
    def export_logs(self, time_range: TimeRange) -> JSONLogs:
        logs = self.log_processor.get_logs(time_range)
        
        # Verify all logs are sanitized before export
        sanitized_logs = []
        for log in logs:
            if self.export_verifier.is_safe(log):
                sanitized_logs.append(log)
            else:
                # Log verification failure but continue
                self._log_verification_failure(log.id)
                
        return JSONLogs(sanitized_logs)
```

### Audit Trail
```python
class ExportAuditor:
    def create_audit_record(self, export: AnalyticsExport) -> AuditRecord:
        return AuditRecord(
            export_id=export.export_id,
            timestamp=export.timestamp,
            client_id=export.client_id,
            data_types=export.data_types,
            record_count=export.record_count,
            verification_status=export.verification_status
        )
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Comprehensive Sensitive Data Redaction

*For any* data structure containing sensitive data (videos, cryptographic proofs, wallet signatures, witness credentials, nullifier secrets), the redaction engine SHALL remove all sensitive content while preserving data structure integrity.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 4.2, 4.3, 4.7**

### Property 2: Sanitized Endpoint Pattern Usage

*For any* HTTP request processed by the analytics system, only sanitized endpoint patterns SHALL be used in metrics collection, never containing sensitive identifiers or user-provided data.

**Validates: Requirements 1.7, 1.8, 2.8**

### Property 3: Error Context Sanitization

*For any* error occurrence involving sensitive data processing, the log processor SHALL redact all sensitive context while preserving essential debugging information (error type, stack trace, method, endpoint pattern, timestamp, correlation ID).

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**

### Property 4: Recursive Data Structure Processing

*For any* nested data structure (JSON objects, arrays, nested dictionaries), the redaction engine SHALL process all levels recursively, identifying and redacting sensitive field names and values according to pattern matching rules.

**Validates: Requirements 4.1, 4.3, 4.6, 4.8**

### Property 5: Performance Monitoring Privacy

*For any* performance monitoring operation, the analytics system SHALL use only operation categories and SHALL NOT correlate performance data with specific content or create content-identifiable patterns.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8**

### Property 6: Health Monitoring Sanitization 

*For any* system health check failure or alert generation, the analytics system SHALL include only non-sensitive system state information and SHALL NOT expose sensitive operational context.

**Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8**

### Property 7: Export Data Verification

*For any* analytics data export operation, the system SHALL verify complete sensitive data removal and maintain data integrity verification throughout the export process.

**Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8**

### Property 8: Privacy Compliance Enforcement

*For any* data collection or processing operation, the analytics system SHALL enforce data minimization, purpose limitation, and user privacy protection without creating profiles or behavior tracking capabilities.

**Validates: Requirements 8.1, 8.2, 8.4, 8.5, 8.6, 8.7**

### Property 9: Configuration Privacy Validation

*For any* configuration change or runtime update, the system SHALL validate privacy compliance, support rollback capabilities, and audit all modifications while maintaining environment-specific profile support.

**Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8**

### Property 10: Security Control Enforcement

*For any* analytics client interaction or data transmission, the system SHALL enforce authentication, encryption, rate limiting, access control, and comprehensive monitoring of all analytics data access attempts.

**Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8**

## Implementation Considerations

### Technology Integration
- Integrate with existing Flask application structure
- Utilize existing logging_utils and metrics modules as foundation
- Extend current database connection patterns for analytics storage
- Leverage existing configuration management patterns

### Performance Optimization
- Implement lazy evaluation for redaction operations
- Use efficient pattern matching algorithms for sensitive data detection
- Cache sanitized endpoint patterns to reduce processing overhead
- Implement streaming processing for large log volumes

### Monitoring Integration
- Support Prometheus metrics exposition format
- Provide JSON structured logging compatible with ELK stack
- Enable integration with existing observability tools
- Support custom dashboard and alerting integration

### Scalability Considerations
- Design for horizontal scaling of analytics processing
- Implement efficient data partitioning for time-series analytics data
- Support distributed redaction processing for high-volume scenarios
- Enable analytics data archival and compression strategies