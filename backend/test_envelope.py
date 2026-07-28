import unittest
from datetime import datetime, timedelta, timezone

from envelope import (
    canonical_encode,
    canonical_decode,
    validate,
    SchemaValidationError,
)

class EnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.valid_metadata = {
            "protocol": "harpocrates",
            "version": 1,
            "tier": "silent",
            "sourceHash": "a" * 64,
            "proofId": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def test_canonical_encode_decode(self):
        encoded = canonical_encode(self.valid_metadata)
        decoded = canonical_decode(encoded)
        self.assertEqual(decoded, self.valid_metadata)

    def test_missing_field(self):
        del self.valid_metadata["tier"]
        with self.assertRaises(SchemaValidationError):
            validate(self.valid_metadata)

    def test_invalid_version(self):
        self.valid_metadata["version"] = 2
        with self.assertRaises(SchemaValidationError):
            validate(self.valid_metadata)

    def test_unknown_fields_preserved(self):
        metadata_with_unknown = self.valid_metadata.copy()
        metadata_with_unknown["unknown_field"] = "value"
        encoded = canonical_encode(metadata_with_unknown)
        decoded = canonical_decode(encoded)
        self.assertEqual(decoded["unknown_field"], "value")

    def test_invalid_hash(self):
        self.valid_metadata["sourceHash"] = "invalid"
        with self.assertRaises(SchemaValidationError):
            validate(self.valid_metadata)

if __name__ == "__main__":
    unittest.main()
