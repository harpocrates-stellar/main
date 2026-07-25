"""Flask routes for analytics endpoints with authentication and rate limiting."""

from __future__ import annotations

import time
from typing import Optional

from flask import Blueprint, Response, jsonify, request

from .export_manager import ExportManager
from .middleware import rate_limit_analytics, require_analytics_auth


def create_analytics_blueprint(analytics_engine) -> Blueprint:
    """Create Flask blueprint for analytics endpoints.
    
    Args:
        analytics_engine: AnalyticsEngine instance
        
    Returns:
        Flask blueprint with analytics routes
    """
    
    bp = Blueprint('analytics', __name__, url_prefix='/analytics')
    
    # Create export manager
    export_manager = ExportManager(
        analytics_engine.config.export_config,
        analytics_engine.redaction_engine
    )
    
    @bp.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for analytics system."""
        
        try:
            health_status = analytics_engine.perform_health_check()
            
            overall_status = "healthy"
            if any(status == "unhealthy" for status in health_status.values()):
                overall_status = "unhealthy"
            elif any(status == "degraded" for status in health_status.values()):
                overall_status = "degraded"
            
            return jsonify({
                "status": overall_status,
                "components": health_status,
                "timestamp": time.time()
            }), 200 if overall_status == "healthy" else 503
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e),
                "timestamp": time.time()
            }), 500
    
    @bp.route('/metrics', methods=['GET'])
    @rate_limit_analytics(requests_per_minute=120)  # Higher limit for metrics
    def export_metrics():
        """Export metrics in Prometheus format."""
        
        try:
            format_type = request.args.get('format', 'prometheus').lower()
            
            if format_type not in ['prometheus', 'json']:
                return jsonify({"error": "Supported formats: prometheus, json"}), 400
            
            metrics_data = analytics_engine.get_metrics_export(format_type)
            
            if format_type == 'prometheus':
                return Response(
                    metrics_data,
                    mimetype='text/plain; version=0.0.4; charset=utf-8'
                )
            else:
                return Response(
                    metrics_data,
                    mimetype='application/json'
                )
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/logs', methods=['GET'])
    @require_analytics_auth()
    @rate_limit_analytics(requests_per_minute=30)
    def export_logs():
        """Export logs in JSON format with authentication."""
        
        try:
            # Parse query parameters
            start_time = request.args.get('start_time', type=float)
            end_time = request.args.get('end_time', type=float)
            compress = request.args.get('compress', 'true').lower() == 'true'
            
            # Validate time range
            if start_time and end_time and start_time > end_time:
                return jsonify({"error": "Invalid time range"}), 400
            
            # Create export
            logs_data = analytics_engine.log_processor.get_logs(start_time, end_time)
            export_data, manifest = export_manager.create_logs_export(
                logs_data=logs_data,
                client_id=request.headers.get('X-Client-ID'),
                time_range=(start_time, end_time) if start_time and end_time else None
            )
            
            # Return export with manifest headers
            response = Response(
                export_data,
                mimetype='application/json' if not compress else 'application/octet-stream'
            )
            
            response.headers['X-Export-ID'] = manifest.export_id
            response.headers['X-Record-Count'] = str(manifest.record_count)
            response.headers['X-Privacy-Verified'] = str(manifest.privacy_verified)
            response.headers['X-Verification-Hash'] = manifest.verification_hash
            
            if compress:
                response.headers['Content-Encoding'] = 'gzip'
                response.headers['Content-Disposition'] = f'attachment; filename=logs_{manifest.export_id}.json.gz'
            
            return response
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/exports', methods=['GET'])
    @require_analytics_auth()
    @rate_limit_analytics()
    def list_exports():
        """List available exports with filtering."""
        
        try:
            # Parse query parameters
            client_id = request.headers.get('X-Client-ID')
            data_type_filter = request.args.get('data_type')
            limit = request.args.get('limit', type=int)
            
            # Get exports list
            manifests = export_manager.list_exports(
                client_id=client_id,
                data_type_filter=data_type_filter,
                limit=limit
            )
            
            # Convert to JSON-safe format
            exports_list = [manifest.to_dict() for manifest in manifests]
            
            return jsonify({
                "exports": exports_list,
                "total": len(exports_list),
                "timestamp": time.time()
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/exports/<export_id>', methods=['GET'])
    @require_analytics_auth()
    @rate_limit_analytics()
    def get_export(export_id: str):
        """Retrieve a specific export by ID."""
        
        try:
            client_id = request.headers.get('X-Client-ID')
            
            # Get export data
            export_data, manifest = export_manager.get_export(
                export_id=export_id,
                client_id=client_id
            )
            
            # Determine content type based on format
            if manifest.compression_enabled:
                mimetype = 'application/octet-stream'
                encoding = 'gzip'
            elif 'json' in manifest.data_types:
                mimetype = 'application/json'
                encoding = None
            else:
                mimetype = 'text/plain'
                encoding = None
            
            response = Response(export_data, mimetype=mimetype)
            
            # Add manifest headers
            response.headers['X-Export-ID'] = manifest.export_id
            response.headers['X-Record-Count'] = str(manifest.record_count)
            response.headers['X-Privacy-Verified'] = str(manifest.privacy_verified)
            response.headers['X-Verification-Hash'] = manifest.verification_hash
            response.headers['X-Data-Types'] = ','.join(manifest.data_types)
            
            if encoding:
                response.headers['Content-Encoding'] = encoding
            
            return response
            
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/exports/<export_id>', methods=['DELETE'])
    @require_analytics_auth()
    @rate_limit_analytics()
    def delete_export(export_id: str):
        """Delete a specific export."""
        
        try:
            client_id = request.headers.get('X-Client-ID')
            
            success = export_manager.delete_export(
                export_id=export_id,
                client_id=client_id
            )
            
            if success:
                return jsonify({
                    "message": "Export deleted successfully",
                    "export_id": export_id,
                    "timestamp": time.time()
                })
            else:
                return jsonify({"error": "Export not found"}), 404
                
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/status', methods=['GET'])
    def system_status():
        """Get comprehensive system status information."""
        
        try:
            status = analytics_engine.get_system_status()
            
            # Add export manager statistics
            status['export_stats'] = export_manager.get_verification_stats()
            
            return jsonify(status)
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/audit', methods=['GET'])
    @require_analytics_auth()
    @rate_limit_analytics()
    def get_audit_trail():
        """Get audit trail with filtering."""
        
        try:
            # Parse query parameters
            export_id = request.args.get('export_id')
            client_id = request.args.get('client_id') or request.headers.get('X-Client-ID')
            start_time = request.args.get('start_time', type=float)
            end_time = request.args.get('end_time', type=float)
            
            # Get audit records
            audit_records = export_manager.get_audit_trail(
                export_id=export_id,
                client_id=client_id,
                start_time=start_time,
                end_time=end_time
            )
            
            # Convert to JSON-safe format
            audit_list = [record.to_dict() for record in audit_records]
            
            return jsonify({
                "audit_records": audit_list,
                "total": len(audit_list),
                "timestamp": time.time()
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/config', methods=['GET'])
    @require_analytics_auth()
    def get_configuration():
        """Get current analytics configuration (sanitized)."""
        
        try:
            # Return sanitized configuration information
            config_info = {
                "enabled": analytics_engine.config.enabled,
                "environment": analytics_engine.config.environment,
                "privacy_mode": analytics_engine.config.privacy_mode,
                "components": {
                    "metrics_enabled": analytics_engine.config.metrics_config.enabled,
                    "logging_enabled": analytics_engine.config.logging_config.enabled,
                    "export_enabled": analytics_engine.config.export_config.enabled,
                },
                "retention": {
                    "metrics_days": analytics_engine.config.retention_config.metrics_retention_days,
                    "logs_days": analytics_engine.config.retention_config.logs_retention_days,
                    "audit_days": analytics_engine.config.retention_config.audit_retention_days,
                },
                "security": {
                    "authentication_required": analytics_engine.config.security_config.require_authentication,
                    "rate_limiting_enabled": analytics_engine.config.security_config.enable_rate_limiting,
                    "encryption_enabled": analytics_engine.config.security_config.encrypt_storage,
                },
                "timestamp": time.time()
            }
            
            return jsonify(config_info)
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/cleanup', methods=['POST'])
    @require_analytics_auth()
    @rate_limit_analytics(requests_per_minute=10)  # Lower limit for cleanup operations
    def cleanup_data():
        """Trigger cleanup of old analytics data."""
        
        try:
            # Parse cleanup parameters
            retention_hours = request.json.get('retention_hours', 24) if request.is_json else 24
            
            # Perform cleanup
            analytics_cleanup = analytics_engine.cleanup_old_data()
            export_cleanup = export_manager.cleanup_old_exports(retention_hours)
            
            cleanup_results = {
                "analytics_cleanup": analytics_cleanup,
                "exports_removed": export_cleanup,
                "retention_hours": retention_hours,
                "timestamp": time.time()
            }
            
            return jsonify({
                "message": "Cleanup completed successfully",
                "results": cleanup_results
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @bp.route('/redaction-stats', methods=['GET'])
    @require_analytics_auth()
    def get_redaction_stats():
        """Get redaction engine statistics."""
        
        try:
            stats = analytics_engine.redaction_engine.get_redaction_stats()
            
            return jsonify({
                "redaction_stats": stats,
                "timestamp": time.time()
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Error handlers for the blueprint
    @bp.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Endpoint not found"}), 404
    
    @bp.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({"error": "Method not allowed"}), 405
    
    @bp.errorhandler(429)
    def rate_limited(error):
        return jsonify({
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later."
        }), 429
    
    @bp.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500
    
    return bp


def setup_analytics_routes(app, analytics_engine) -> None:
    """Set up analytics routes on Flask application.
    
    Args:
        app: Flask application instance
        analytics_engine: AnalyticsEngine instance
    """
    
    if not analytics_engine or not analytics_engine.config.enabled:
        return
    
    # Create and register analytics blueprint
    analytics_bp = create_analytics_blueprint(analytics_engine)
    app.register_blueprint(analytics_bp)
    
    # Add CORS headers for analytics endpoints if needed
    @app.after_request
    def add_analytics_cors_headers(response):
        # Only add CORS headers for analytics endpoints
        if request.path.startswith('/analytics/'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Analytics-API-Key, X-Client-ID, X-Correlation-ID'
        return response