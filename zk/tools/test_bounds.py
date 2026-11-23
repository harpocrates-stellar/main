import json
import pytest
from unittest.mock import MagicMock
from build_circuits import _generate_aggregator

def test_generate_aggregator_rejects_oversized_disclosure_list(capsys):
    """Ensure the witness preparation rejects >8 predicates before allocation."""
    # 9 hashes = oversized list
    video_hashes = ["0" * 64] * 9

    # Dummy toolchain (it should fail before using this)
    mock_toolchain = MagicMock()

    result = _generate_aggregator(
        video_hashes=video_hashes,
        credential_secret="123",
        nullifier_secret="456",
        output_dir=None,
        toolchain=mock_toolchain,
    )

    # Exit code 0 means it handled the error gracefully and printed JSON
    assert result == 0

    captured = capsys.readouterr()
    err_output = json.loads(captured.out)

    assert err_output["type"] == "error"
    assert err_output["reasonCode"] == "oversized"
    assert "disclosure predicate list size must be between 1 and 8" in err_output["detail"]
