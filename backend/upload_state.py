from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


class UploadStatus(enum.Enum):
    """Upload lifecycle states."""
    RECEIVING = "receiving"
    HASHING = "hashing"
    VALIDATING = "validating"
    PERSISTING = "persisting"
    CONFIRMING = "confirming"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class UploadState:
    """Tracks the state and progress of a streaming upload."""
    
    upload_id: str
    status: UploadStatus
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    bytes_received: int = 0
    content_type: Optional[str] = None
    filename: Optional[str] = None
    temp_path: Optional[str] = None
    computed_hash: Optional[str] = None
    error_message: Optional[str] = None
    
    def transition_to(self, new_status: UploadStatus, error_message: Optional[str] = None) -> None:
        """Transition to a new status with validation."""
        if not self._is_valid_transition(self.status, new_status):
            raise ValueError(f"Invalid transition from {self.status.value} to {new_status.value}")
        
        self.status = new_status
        self.updated_at = time.time()
        
        if new_status == UploadStatus.FAILED:
            self.error_message = error_message
    
    def _is_valid_transition(self, from_status: UploadStatus, to_status: UploadStatus) -> bool:
        """Validate state transition according to the upload lifecycle."""
        # Any state can transition to FAILED
        if to_status == UploadStatus.FAILED:
            return True
        
        # Define valid state transitions
        valid_transitions = {
            UploadStatus.RECEIVING: [UploadStatus.HASHING],
            UploadStatus.HASHING: [UploadStatus.VALIDATING],
            UploadStatus.VALIDATING: [UploadStatus.PERSISTING],
            UploadStatus.PERSISTING: [UploadStatus.CONFIRMING],
            UploadStatus.CONFIRMING: [UploadStatus.COMPLETE],
            UploadStatus.COMPLETE: [],  # Terminal state
            UploadStatus.FAILED: [],    # Terminal state
        }
        
        return to_status in valid_transitions.get(from_status, [])
    
    @property
    def is_terminal(self) -> bool:
        """Check if the upload is in a terminal state."""
        return self.status in {UploadStatus.COMPLETE, UploadStatus.FAILED}
    
    @property
    def duration_seconds(self) -> float:
        """Calculate the total duration of the upload so far."""
        return self.updated_at - self.created_at
    
    def to_log_dict(self) -> dict[str, object]:
        """Convert to a dictionary safe for logging (no sensitive data)."""
        return {
            "upload_id": self.upload_id,
            "status": self.status.value,
            "bytes_received": self.bytes_received,
            "duration_seconds": round(self.duration_seconds, 3),
            "error_type": self._get_error_type() if self.error_message else None,
        }
    
    def _get_error_type(self) -> Optional[str]:
        """Extract error type from error message for metrics (no sensitive data)."""
        if not self.error_message:
            return None
        
        message_lower = self.error_message.lower()
        
        if "size" in message_lower or "limit" in message_lower or "413" in message_lower:
            return "size_limit"
        elif "timeout" in message_lower or "deadline" in message_lower:
            return "timeout"
        elif "parse" in message_lower or "multipart" in message_lower:
            return "parse_error"
        elif "storage" in message_lower or "disk" in message_lower or "write" in message_lower:
            return "storage_error"
        elif "contract" in message_lower or "stellar" in message_lower:
            return "contract_error"
        else:
            return "unknown"


class UploadManager:
    """Manages active upload states and provides lifecycle operations."""
    
    def __init__(self) -> None:
        self._active_uploads: dict[str, UploadState] = {}
    
    def create_upload(self, content_type: Optional[str] = None, filename: Optional[str] = None) -> UploadState:
        """Create a new upload with a unique ID."""
        upload_id = str(uuid.uuid4())
        upload_state = UploadState(
            upload_id=upload_id,
            status=UploadStatus.RECEIVING,
            content_type=content_type,
            filename=filename,
        )
        self._active_uploads[upload_id] = upload_state
        return upload_state
    
    def get_upload(self, upload_id: str) -> Optional[UploadState]:
        """Get an upload by ID."""
        return self._active_uploads.get(upload_id)
    
    def remove_upload(self, upload_id: str) -> None:
        """Remove an upload from active tracking."""
        self._active_uploads.pop(upload_id, None)
    
    def get_active_count(self) -> int:
        """Get the number of currently active uploads."""
        return len(self._active_uploads)
    
    def cleanup_terminal_uploads(self) -> int:
        """Remove uploads that have reached terminal states. Returns count removed."""
        terminal_ids = [
            upload_id for upload_id, upload_state in self._active_uploads.items()
            if upload_state.is_terminal
        ]
        
        for upload_id in terminal_ids:
            del self._active_uploads[upload_id]
        
        return len(terminal_ids)
    
    def list_active_uploads(self) -> list[UploadState]:
        """Get all currently active uploads."""
        return list(self._active_uploads.values())


# Global upload manager instance
upload_manager = UploadManager()