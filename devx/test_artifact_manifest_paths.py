"""Focused tests for #1216: reject artifact manifest paths escaping the release dir."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# The tool lives in zk/tools/, not a package. Add it to sys.path for import.
_TOOLS = Path(__file__).resolve().parents[1] / "zk" / "tools"
sys.path.insert(0, str(_TOOLS))

from artifact_manifest import (  # noqa: E402
    ArtifactPathEscapeError,
    resolve_within_root,
)


def test_in_tree_path_resolves(tmp_path: Path) -> None:
    root = tmp_path / "release"
    (root / "artifacts").mkdir(parents=True)
    (root / "artifacts" / "proof.bin").write_bytes(b"ok")
    resolved = resolve_within_root("artifacts/proof.bin", root)
    assert resolved == (root / "artifacts" / "proof.bin").resolve()


def test_parent_traversal_rejected(tmp_path: Path) -> None:
    root = tmp_path / "release"
    root.mkdir()
    (tmp_path / "outside.bin").write_bytes(b"nope")
    with pytest.raises(ArtifactPathEscapeError) as exc:
        resolve_within_root("../outside.bin", root)
    # Bounded error: names the declared path, never the absolute host path.
    msg = str(exc.value)
    assert "../outside.bin" in msg
    assert str(tmp_path) not in msg


def test_absolute_path_rejected(tmp_path: Path) -> None:
    root = tmp_path / "release"
    root.mkdir()
    with pytest.raises(ArtifactPathEscapeError):
        resolve_within_root("/etc/passwd", root)


def test_symlink_out_rejected(tmp_path: Path) -> None:
    root = tmp_path / "release"
    root.mkdir()
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"secret")
    (root / "link.bin").symlink_to(outside)
    with pytest.raises(ArtifactPathEscapeError) as exc:
        resolve_within_root("link.bin", root)
    assert "link.bin" in str(exc.value)
    assert str(tmp_path) not in str(exc.value)


def test_symlink_within_tree_accepted(tmp_path: Path) -> None:
    root = tmp_path / "release"
    (root / "a").mkdir(parents=True)
    target = root / "a" / "real.bin"
    target.write_bytes(b"ok")
    (root / "alias.bin").symlink_to(target)
    resolved = resolve_within_root("alias.bin", root)
    assert resolved == target.resolve()
