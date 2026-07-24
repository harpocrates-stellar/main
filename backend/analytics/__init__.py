"""Privacy-Safe Analytics System for Harpocrates Evidence Protocol.

This module provides comprehensive observability, performance monitoring, and error 
telemetry while ensuring that sensitive data (videos, cryptographic proofs, wallet 
signatures, witness credentials, secrets) cannot be captured, logged, or transmitted 
through analytics channels.
"""

from .analytics_engine import AnalyticsEngine
from .config import AnalyticsConfig
from .events import AnalyticsEvent, EventType
from .redaction import RedactionEngine

__all__ = [
    "AnalyticsEngine",
    "AnalyticsConfig", 
    "AnalyticsEvent",
    "EventType",
    "RedactionEngine",
]