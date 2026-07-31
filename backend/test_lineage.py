import unittest

from lineage import (
    LineageValidationError,
    canonical_lineage_manifest,
    lineage_manifest_digest,
    validate_lineage_graph,
    redaction_replay_binding,
    validate_redaction_witness_binding,
)
from verifier_inputs import REDACTION_WITNESS_DOMAIN_TAG


class LineageManifestTests(unittest.TestCase):
    def _manifest(self) -> dict:
        return {
            "parentProofIds": ["a" * 64],
            "operationType": "redact",
            "parametersDigest": "c" * 64,
            "toolIdentity": "harpocrates-studio",
            "toolVersion": "1.2.3",
            "outputDigest": "d" * 64,
            "network": "testnet",
            "actorAddress": "GABC123",
        }

    def _witness(self, manifest: dict) -> dict:
        operation = (4).to_bytes(32, "big")
        frame = b"\x01" * 32 + b"\x02" * 32 + operation + redaction_replay_binding(manifest) + REDACTION_WITNESS_DOMAIN_TAG
        return {"schema": "redaction_witness/v1", "publicInputs": frame.hex(), "proof": "ab" * 64}

    def test_accepts_manifest_bound_redaction_witness_frame(self) -> None:
        manifest = self._manifest()
        validate_redaction_witness_binding(manifest, self._witness(manifest))

    def test_rejects_redaction_witness_replay_for_different_claim(self) -> None:
        manifest = self._manifest()
        witness = self._witness(manifest)
        manifest["outputDigest"] = "e" * 64
        with self.assertRaises(LineageValidationError):
            validate_redaction_witness_binding(manifest, witness)

    def test_rejects_redaction_witness_wrong_operation(self) -> None:
        manifest = self._manifest()
        witness = self._witness(manifest)
        manifest["operationType"] = "crop"
        with self.assertRaises(LineageValidationError):
            validate_redaction_witness_binding(manifest, witness)

    def test_canonical_lineage_manifest_is_stable(self) -> None:
        manifest = {
            "parentProofIds": ["a" * 64, "b" * 64],
            "operationType": "crop",
            "parametersDigest": "c" * 64,
            "toolIdentity": "harpocrates-studio",
            "toolVersion": "1.2.3",
            "outputDigest": "d" * 64,
            "network": "testnet",
            "actorAddress": "GABC123",
        }
        first = canonical_lineage_manifest(manifest)
        second = canonical_lineage_manifest(manifest)
        self.assertEqual(first, second)
        self.assertEqual(lineage_manifest_digest(manifest), lineage_manifest_digest(manifest))

    def test_rejects_unsupported_operation(self) -> None:
        with self.assertRaises(LineageValidationError):
            canonical_lineage_manifest({
                "parentProofIds": ["a" * 64],
                "operationType": "unsupported",
                "parametersDigest": "c" * 64,
                "toolIdentity": "harpocrates-studio",
                "toolVersion": "1.2.3",
                "outputDigest": "d" * 64,
                "network": "testnet",
                "actorAddress": "GABC123",
            })

    def test_rejects_excessive_fanout(self) -> None:
        with self.assertRaises(LineageValidationError):
            canonical_lineage_manifest({
                "parentProofIds": ["a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64],
                "operationType": "compose",
                "parametersDigest": "c" * 64,
                "toolIdentity": "harpocrates-studio",
                "toolVersion": "1.2.3",
                "outputDigest": "d" * 64,
                "network": "testnet",
                "actorAddress": "GABC123",
            })

    def test_rejects_direct_cycle(self) -> None:
        output = "a" * 64
        with self.assertRaises(LineageValidationError) as ctx:
            validate_lineage_graph(
                parent_proof_ids=[output],
                depth=1,
                actor_address="GABC123",
                output_digest=output,
            )
        self.assertIn("cycle", str(ctx.exception).lower())

    def test_rejects_missing_actor_address(self) -> None:
        with self.assertRaises(LineageValidationError):
            validate_lineage_graph(
                parent_proof_ids=["a" * 64],
                depth=1,
                actor_address="",
            )

    def test_accepts_valid_lineage_graph(self) -> None:
        # Should not raise
        validate_lineage_graph(
            parent_proof_ids=["a" * 64, "b" * 64],
            depth=1,
            actor_address="GABC123",
            output_digest="c" * 64,
        )
