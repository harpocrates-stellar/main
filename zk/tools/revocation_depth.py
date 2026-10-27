"""Protocol revocation witness Merkle-depth bounds (#357).

Host-side guard that mirrors the Noir globals:

    MAX_REVOCATION_WITNESS_DEPTH = 3
    MAX_REVOCATION_LEAVES = 8  # 2**depth

Oversized or malformed depth values are rejected with a stable machine code
and never echo leaves, secrets, or witness material.

Reject codes:
    * ``depth_oversize``: depth > MAX_REVOCATION_WITNESS_DEPTH or leaf_count > MAX_REVOCATION_LEAVES
    * ``depth_undersize``: depth < 1 or leaf_count < 1
    * ``malformed_depth``: non-integer or boolean input
    * ``leaf_count_mismatch``: leaf_count != 2**depth for a bounded depth
"""

from __future__ import annotations

MIN_REVOCATION_WITNESS_DEPTH = 1
MAX_REVOCATION_WITNESS_DEPTH = 16
MAX_REVOCATION_LEAVES = 1 << MAX_REVOCATION_WITNESS_DEPTH


class RevocationDepthError(ValueError):
    """Structured revocation Merkle-depth validation failure."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


def validate_revocation_depth(depth: int) -> int:
    if isinstance(depth, bool) or not isinstance(depth, int):
        raise RevocationDepthError("depth_not_integer", "revocation depth must be an integer")
    if depth < MIN_REVOCATION_WITNESS_DEPTH:
        raise RevocationDepthError("depth_undersize", "revocation depth must be >= 1")
    if depth > MAX_REVOCATION_WITNESS_DEPTH:
        raise RevocationDepthError(
            "depth_oversize",
            f"revocation depth {depth} exceeds max {MAX_REVOCATION_WITNESS_DEPTH}",
        )
    return depth


def validate_revocation_leaf_count(leaf_count: int) -> int:
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int):
        raise RevocationDepthError("depth_not_integer", "revocation leaf count must be an integer")
    if leaf_count < (1 << MIN_REVOCATION_WITNESS_DEPTH):
        raise RevocationDepthError("depth_undersize", "revocation leaf count must be >= 2")
    if leaf_count > MAX_REVOCATION_LEAVES:
        raise DepthBoundError("depth_oversize")
    if depth is not None:
        bound_depth = check_revocation_depth(depth)
        expected = 1 << bound_depth
        if leaf_count != expected:
            raise DepthBoundError("leaf_count_mismatch")
    return leaf_count


def validate_revocation_witness_shape(depth: int, leaf_count: int) -> tuple[int, int]:
    validated_depth = validate_revocation_depth(depth)
    validated_leaves = validate_revocation_leaf_count(leaf_count)
    if validated_leaves != (1 << validated_depth):
        raise RevocationDepthError(
            "depth_leaf_mismatch",
            f"leaf count {validated_leaves} does not match depth {validated_depth}",
        )
    return validated_depth, validated_leaves
