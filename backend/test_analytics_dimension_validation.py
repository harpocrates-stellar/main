import pytest
from analytics.analytics_engine import AnalyticsEngine, RequestContext
from analytics.events import EventLifecycleState

@pytest.fixture
def engine():
    # Minimal engine initialization without external dependencies
    return AnalyticsEngine()

def test_reject_hash_label(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"evidence_hash": "a3f5c6d7e8f9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_hash"

def test_reject_filename_label(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"evidence_file": "uploads/evidence123.png"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_filename"
