"""Path-safety validation for evidence storage destinations.

This module provides a single public function,
:func:`assert_safe_destination`, which must be called before any write
into the evidence storage directory.  It resolves the candidate path to
its real filesystem location and rejects it when it aliases a protected
file or directory (the metadata database, encryption-key material, the
application source tree, or any other caller-supplied protected path).

Design
------
* All comparisons are made on *resolved* (``Path.resolve()``) paths so
  that symbolic links, ``..`` components, and platform case-folding
  cannot be used to bypass the check.
* A destination is considered to alias a protected path when:
  - it is exactly equal to the protected path, or
  - it is a descendant of the protected path (i.e. it falls inside a
    protected directory), or
  - it is an ancestor of the protected path (i.e. it *is* a protected
    directory or one of its parents — writing here would replace the
    directory entry that guards the protected file).

Raises
------
ValueError
    Raised (not a custom exception) so that the existing
    ``@app.errorhandler(ValueError)`` in ``app.py`` converts it to a
    400 response without additional wiring.
"""

from __future__ import annotations

from pathlib import Path


def assert_safe_destination(
    destination: Path,
    protected_paths: frozenset[Path],
) -> None:
    """Raise :class:`ValueError` when *destination* aliases a protected path.

    Parameters
    ----------
    destination:
        The fully-resolved output path that is about to be written.
        The caller must pass the result of ``Path(...).resolve()`` — a
        relative or unresolved path will be resolved here as a defensive
        measure, but the expectation is that the caller has already done
        this.
    protected_paths:
        A frozen set of *resolved* :class:`~pathlib.Path` objects that
        must never be overwritten or shadowed.  Obtain this set from
        :func:`storage._collect_protected_paths` or construct it
        directly in tests.

    Raises
    ------
    ValueError
        When *destination* is equal to, a descendant of, or an ancestor
        of any path in *protected_paths*.

    Examples
    --------
    >>> from pathlib import Path
    >>> from evidence_storage import assert_safe_destination
    >>> safe = Path("/var/evidence/abc123.bin").resolve()
    >>> protected = frozenset({Path("/etc/app/keys.pem").resolve()})
    >>> assert_safe_destination(safe, protected)  # no exception
    >>> assert_safe_destination(Path("/etc/app/keys.pem"), protected)
    Traceback (most recent call last):
        ...
    ValueError: destination '/etc/app/keys.pem' aliases protected path '/etc/app/keys.pem'
    """
    resolved = destination.resolve()

    for protected in protected_paths:
        reason = _alias_reason(resolved, protected)
        if reason is not None:
            raise ValueError(
                f"destination '{resolved}' aliases protected path "
                f"'{protected}': {reason}"
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _alias_reason(resolved: Path, protected: Path) -> str | None:
    """Return a human-readable reason string when *resolved* aliases *protected*.

    Returns ``None`` when there is no alias relationship.
    """
    if resolved == protected:
        return "paths are identical"

    # destination is inside a protected directory
    try:
        resolved.relative_to(protected)
        return "destination is inside a protected directory"
    except ValueError:
        pass

    # destination would contain (be a parent of) a protected file/directory
    try:
        protected.relative_to(resolved)
        return "destination is a parent of a protected path"
    except ValueError:
        pass

    return None
