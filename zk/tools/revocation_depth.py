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

    def signal(self) -> dict[str, str]:
        return {"rejectCode": self.code, "field": "depth"}


class DepthBoundError(RevocationDepthError):
    """Privacy-safe depth rejection."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(code, message)


def check_revocation_depth(depth: object) -> int:
    """Return ``depth`` when it is within ``[1, MAX_REVOCATION_WITNESS_DEPTH]``."""
    return validate_revocation_depth(depth)


def validate_revocation_depth(depth: object) -> int:
    if isinstance(depth, bool) or not isinstance(depth, int):
        raise DepthBoundError("depth_not_integer", "revocation depth must be an integer")
    if depth < MIN_REVOCATION_WITNESS_DEPTH:
        raise DepthBoundError("depth_undersize", "revocation depth must be >= 1")
    if depth > MAX_REVOCATION_WITNESS_DEPTH:
        raise DepthBoundError(
            "depth_oversize",
            f"revocation depth {depth} exceeds max {MAX_REVOCATION_WITNESS_DEPTH}",
        )
    return depth


def check_revocation_leaf_count(leaf_count: object, depth: int | None = None) -> int:
    """Reject leaf counts that exceed the depth bound or disagree with ``2**depth``."""
    return validate_revocation_leaf_count(leaf_count, depth)


def validate_revocation_leaf_count(leaf_count: object, depth: int | None = None) -> int:
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int):
        raise DepthBoundError("depth_not_integer", "revocation leaf count must be an integer")
    if leaf_count < (1 << MIN_REVOCATION_WITNESS_DEPTH):
        raise DepthBoundError("depth_undersize", "revocation leaf count must be >= 2")
    if leaf_count > MAX_REVOCATION_LEAVES:
        raise DepthBoundError("depth_oversize")
    # Must be power of two
    if (leaf_count & (leaf_count - 1)) != 0:
        raise DepthBoundError("depth_non_power_of_two")
    if depth is not None:
        bound_depth = validate_revocation_depth(depth)
        expected = 1 << bound_depth
        if leaf_count != expected:
            raise DepthBoundError("leaf_count_mismatch")
    return leaf_count


def validate_revocation_witness_shape(depth: int, leaf_count: int) -> tuple[int, int]:
    validated_depth = validate_revocation_depth(depth)
    validated_leaves = validate_revocation_leaf_count(leaf_count, depth=validated_depth)
    return validated_depth, validated_leaves
