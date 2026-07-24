# Privacy-Safe Analytics System

## Overview

The Harpocrates Privacy-Safe Analytics System provides comprehensive observability, performance monitoring, and error telemetry while ensuring that sensitive data (videos, cryptographic proofs, wallet signatures, witness credentials, secrets) cannot be captured, logged, or transmitted through analytics channels.

## Architecture

The system employs a defense-in-depth approach with multiple layers of data sanitization:

### Core Components

1. **RedactionEngine** - Multi-pattern data sanitization with recursive processing
2. **MetricsCollector** - Privacy-safe HTTP and performance metrics collection  
3. **LogProcessor** - Error logging with comprehensive context sanitization
4. **AnalyticsEngine** - Central orchestrator with event processing pipeline
5. **ExportManager** - Data export with privacy verification and audit trails

### Privacy Protection Layers

- **Layer 1: Input Sanitization** - All data entering analytics passes through immediate sanitization
- **Layer 2: Context Redaction** - Request/response contexts sanitized before processing
- **Layer 3: Export Verification** - All exported data verified to contain no sensitive information

## Configuration

### Environment Variables

```bash
# Core Analytics Configuration
ANALYTICS_ENABLED=true
ANALYTICS_ENVIRONMENT=production
ANALYTICS_PRIVACY_MODE=strict  # strict, standard, minimal

# Metrics Configuration  
ANALYTICS_METRICS_ENABLED=true
ANALYTICS_METRICS_INTERVAL=60
ANALYTICS_METRICS_RETENTION_DAYS=30
ANALYTICS_PROMETHEUS_ENABLED=true
ANALYTICS_PROMETHEUS_PATH=/analytics/metrics

# Logging Configuration
ANALYTICS_LOGS_ENABLED=true
ANALYTICS_LOG_LEVEL=INFO
ANALYTICS_LOGS_RETENTION_DAYS=7
ANALYTICS_SANITIZE_STACK_TRACES=true
ANALYTICS_JSON_EXPORT_ENABLED=true

# Export Configuration
ANALYTICS_EXPORT_ENABLED=true
ANALYTICS_EXPORT_PROMETHEUS=true
ANALYTICS_EXPORT_JSON=true
ANALYTICS_COMPRESS_EXPORTS=true
ANALYTICS_VERIFY_EXPORTS=true
ANALYTICS_FAIL_ON_SENSITIVE=true

# Security Configuration
ANALYTICS_REQUIRE_AUTH=true
ANALYTICS_API_KEY_HEADER=X-Analytics-API-Key
ANALYTICS_RATE_LIMITING=true
ANALYTICS_RATE_LIMIT_RPM=60
ANALYTICS_ENCRYPT_STORAGE=true
ANALYTICS_REQUIRE_TLS=true
```

### Privacy Modes

- **strict** - Maximum privacy protection, aggressive redaction
- **standard** - Balanced privacy and observability 
- **minimal** - Minimal redaction for development environments

## Usage

### Flask Integration

The analytics system automatically integrates with Flask applications:

```python
from analytics.middleware import AnalyticsMiddleware
from analytics.routes import setup_analytics_routes

# Initialize analytics middleware
analytics_middleware = AnalyticsMiddleware(app)

# Setup analytics routes
setup_analytics_routes(app, analytics_middleware.analytics_engine)
```

### Manual Event Recording

```python
from analytics.middleware import monitor_operation

@monitor_operation("steganography_embed")
def embed_video():
    # Your operation code here
    pass

# Or directly with analytics engine
analytics_engine.record_performance(
    operation_name="proof_generation",
    duration_seconds=2.5,
    cpu_percent=65.0,
    memory_mb=256.0
)
```

## API Endpoints

### Health and Status

- `GET /analytics/health` - Analytics system health check
- `GET /analytics/status` - Comprehensive system status

### Metrics Export

- `GET /analytics/metrics?format=prometheus` - Prometheus metrics export
- `GET /analytics/metrics?format=json` - JSON metrics export

### Logs Export (Authentication Required)

- `GET /analytics/logs?start_time=<timestamp>&end_time=<timestamp>` - Export logs
- `GET /analytics/exports` - List available exports
- `GET /analytics/exports/<export_id>` - Download specific export
- `DELETE /analytics/exports/<export_id>` - Delete export

### Administration (Authentication Required)

- `GET /analytics/config` - Get configuration information
- `GET /analytics/audit` - Get audit trail
- `POST /analytics/cleanup` - Trigger data cleanup
- `GET /analytics/redaction-stats` - Get redaction statistics

## Privacy Guarantees

### Sensitive Data Protection

The system ensures the following data **never** appears in analytics:

- **Video Content**: Video files, metadata, hashes identifying specific content
- **Cryptographic Proofs**: Proof data, witness data, commitments, field elements
- **Wallet Information**: Signatures, private keys, addresses 
- **Credentials**: Silent witness credentials, identity commitments, nullifier secrets
- **User Data**: Filenames, user-provided identifiers, personal information

### Data Redaction Patterns

Sensitive data is identified by:

- **Field Names**: `proof_data`, `wallet_signature`, `nullifier_secret`, `video_hash`, etc.
- **Value Patterns**: Long hex strings, base64-encoded data, UUIDs
- **File Paths**: Video file extensions, paths containing sensitive terms

### Endpoint Sanitization

URL paths are sanitized to remove sensitive identifiers:

```
/api/proof/0123456789abcdef... → /api/proof/{id}
/embed?video_hash=abc123... → /embed  
/api/user/sensitive_user_id → /api/user/{id}
```

## Metrics Collected

### HTTP Request Metrics

- Request counts by method, sanitized endpoint pattern, and status code
- Request latency distributions 
- Upload size histograms (without content identification)

### Performance Metrics

- Operation duration by category (steganography, cryptography, database, network)
- Resource utilization (CPU, memory, I/O) by operation category
- System health and availability metrics

### Error Metrics

- Error counts and patterns by category and severity
- Sanitized error context for debugging
- Stack trace hashes for pattern analysis (without sensitive content)

### Security Metrics

- Rate limiting violations (with anonymized client identifiers)
- Authentication failures and security events
- Access patterns for analytics endpoints

## Operational Procedures

### Monitoring Setup

1. **Prometheus Integration**
   ```yaml
   # prometheus.yml
   scrape_configs:
     - job_name: 'harpocrates-analytics'
       static_configs:
         - targets: ['localhost:5050']
       metrics_path: '/analytics/metrics'
   ```

2. **Grafana Dashboard**
   - Import the provided dashboard configuration
   - Monitor request rates, error rates, and performance metrics
   - Set up alerts for system health degradation

### Log Analysis

1. **Export Logs**
   ```bash
   # Export last 24 hours of logs
   curl -H "X-Analytics-API-Key: your-key" \
        "http://localhost:5050/analytics/logs?start_time=$(date -d '1 day ago' +%s)"
   ```

2. **Log Format**
   ```json
   {
     "timestamp": 1642680000.0,
     "event_type": "error",
     "correlation_id": "req_123456",
     "error_type": "ValueError", 
     "error_category": "validation_error",
     "sanitized_context": {
       "method": "POST",
       "endpoint_pattern": "/api/embed",
       "status_code": 400
     }
   }
   ```

### Data Retention

- **Metrics**: 30 days (configurable)
- **Logs**: 7 days (configurable) 
- **Audit Records**: 90 days (configurable)
- **Exports**: 24 hours (configurable)

Automatic cleanup runs every 24 hours.

### Backup and Recovery

1. **Configuration Backup**
   ```bash
   # Backup analytics configuration
   curl -H "X-Analytics-API-Key: your-key" \
        http://localhost:5050/analytics/config > analytics-config.json
   ```

2. **Metrics Export for Archival**
   ```bash
   # Export metrics for long-term storage
   curl http://localhost:5050/analytics/metrics?format=json > metrics-archive.json
   ```

## Security Considerations

### Authentication

- All sensitive endpoints require API key authentication
- API keys should be rotated regularly
- Use TLS for all analytics communications

### Rate Limiting

- Default: 60 requests per minute per client
- Configurable per endpoint type
- Automatic blocking of excessive requests

### Access Control

- Metrics endpoints are public (Prometheus standard)
- Log and admin endpoints require authentication
- Client IP allowlisting available for production

### Audit Trail

All analytics access is logged:

```json
{
  "audit_id": "audit_123456",
  "export_id": "exp_1642680000_abc123",
  "timestamp": 1642680000.0,
  "client_id": "monitoring_system",
  "operation": "export",
  "data_types": ["logs", "json"],
  "record_count": 1500,
  "verification_status": "passed"
}
```

## Troubleshooting

### Common Issues

1. **Analytics Not Recording Data**
   - Check `ANALYTICS_ENABLED=true`
   - Verify Flask middleware initialization
   - Check logs for initialization errors

2. **Export Contains Sensitive Data Error**
   - Review redaction patterns configuration
   - Check privacy mode setting
   - Verify `ANALYTICS_FAIL_ON_SENSITIVE=true` setting

3. **High Memory Usage**
   - Reduce retention periods
   - Enable compression for exports  
   - Increase cleanup frequency

4. **Missing Metrics in Prometheus**
   - Verify metrics endpoint accessibility
   - Check authentication configuration
   - Confirm Prometheus scrape configuration

### Debug Mode

Enable debug logging for troubleshooting:

```bash
ANALYTICS_LOG_LEVEL=DEBUG python app.py
```

### Health Checks

Monitor analytics system health:

```bash
curl http://localhost:5050/analytics/health
```

Expected response:
```json
{
  "status": "healthy",
  "components": {
    "redaction_engine": "healthy",
    "metrics_collector": "healthy", 
    "log_processor": "healthy",
    "event_processor": "healthy"
  },
  "timestamp": 1642680000.0
}
```

## Privacy Impact Assessment

### Data Minimization

The system collects only operationally necessary data:
- HTTP request patterns (not content)
- Error types and categories (not details)
- Performance metrics by operation category
- System health indicators

### Purpose Limitation

Analytics data is used exclusively for:
- System monitoring and alerting
- Performance optimization
- Error debugging and resolution
- Capacity planning

### Retention and Deletion

- Automatic data purging based on retention policies
- Manual deletion capabilities for compliance requests
- Secure deletion ensuring data cannot be recovered

### Privacy by Design

- Default deny for sensitive data collection
- Multi-layer redaction with fail-safe defaults
- Export verification preventing accidental data leaks
- Comprehensive audit trails for accountability

## Compliance

### GDPR Compliance

- Data minimization by default
- Purpose limitation enforcement
- Right to erasure support
- Privacy impact documentation

### Security Standards

- Encryption in transit and at rest
- Authentication and authorization controls
- Audit logging for all access
- Secure configuration defaults

## Support and Maintenance

### Monitoring

Monitor these key metrics:
- Analytics system health status
- Redaction engine performance  
- Export verification success rate
- Privacy violation detection rate

### Updates

- Regular security updates for dependencies
- Privacy pattern updates as needed
- Configuration review and updates
- Performance optimization as system scales

For support, check the troubleshooting section above or review the audit logs for detailed error information.