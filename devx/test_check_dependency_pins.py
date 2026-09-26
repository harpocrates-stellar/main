"""Tests for devx/check_dependency_pins.py.

Coverage
--------
  Positive: each dependency surface validates cleanly when pinned and in sync.
  Negative: every policy rule fires on unpinned, drifted, or stale input.
  Boundary: file size limit, option/URL lines, lockfileVersion and lock
    version floors, and the finding cap.
  Regression: the committed repository passes end-to-end, so the gate cannot
    land green on a tree it would immediately fail.

No real media, credentials, witnesses, or private keys are used.  The
credential fixture is an obviously fake, short string that only has to match
the shape of a token.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Make devx/ importable when run from the repo root or the devx/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_dependency_pins as cdp

REPO_ROOT = Path(__file__).resolve().parents[1]


# ── shared fixtures ───────────────────────────────────────────────────────────

def _report() -> cdp.Report:
    return cdp.Report()


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return path


def _manifest(**overrides: object) -> dict:
    manifest = {
        "name": "demo",
        "version": "1.0.0",
        "dependencies": {"left-pad": "^1.3.0"},
        "devDependencies": {"vitest": "^3.0.0"},
    }
    manifest.update(overrides)
    return manifest


def _lock(**overrides: object) -> dict:
    lock = {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "demo",
                "version": "1.0.0",
                "dependencies": {"left-pad": "^1.3.0"},
                "devDependencies": {"vitest": "^3.0.0"},
            },
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/vitest": {"version": "3.0.0"},
        },
    }
    lock.update(overrides)
    return lock


CARGO_WORKSPACE = """\
[workspace]
resolver = "2"
members = ["contracts/*"]

[workspace.dependencies]
soroban-sdk = "27"
"""

CARGO_MEMBER = """\
[package]
name = "demo"
version = "1.0.0"
edition = "2021"

[dependencies]
soroban-sdk = { workspace = true }
"""

CARGO_LOCK = """\
version = 4

[[package]]
name = "demo"
version = "1.0.0"

[[package]]
name = "soroban-sdk"
version = "27.0.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""

NARGO_MANIFEST = """\
[package]
name = "demo_circuit"
type = "bin"
compiler_version = ">=1.0.0"

[dependencies]
"""

TOOLCHAIN_LOCK = {
    "format": "harpocrates.zk-toolchain-lock",
    "version": 1,
    "toolchain": {
        "nargo": {"version": "1.0.0-beta.9"},
        "barretenberg": {"version": "0.87.0"},
    },
}


def _cargo_tree(root: Path, lock: str = CARGO_LOCK) -> Path:
    workspace = root / "contracts"
    _write(workspace, "Cargo.toml", CARGO_WORKSPACE)
    _write(workspace, "contracts/demo/Cargo.toml", CARGO_MEMBER)
    if lock is not None:
        _write(workspace, "Cargo.lock", lock)
    return workspace


def _zk_tree(root: Path, lock: dict | None = None) -> Path:
    _write(
        root,
        "zk/toolchain.lock.json",
        json.dumps(TOOLCHAIN_LOCK if lock is None else lock, indent=2),
    )
    _write(root, "zk/noir/demo/Nargo.toml", NARGO_MANIFEST)
    return root


def _pinned_tree(root: Path) -> Path:
    """A minimal repository that passes every check."""
    _write(root, cdp.PIP_MANIFEST, "Flask==3.1.3\n")
    for workspace in cdp.NPM_WORKSPACES:
        _write(root, f"{workspace}/package.json", json.dumps(_manifest()))
        _write(root, f"{workspace}/package-lock.json", json.dumps(_lock()))
    _cargo_tree(root)
    _zk_tree(root)
    return root


# ── pip: parse ────────────────────────────────────────────────────────────────

class TestParsePipRequirement(unittest.TestCase):

    def test_parses_name_version(self):
        requirement = cdp.parse_pip_requirement("Flask==3.1.3")
        self.assertEqual(requirement.name, "Flask")
        self.assertEqual(requirement.operator, "==")
        self.assertEqual(requirement.version, "3.1.3")
        self.assertEqual(requirement.canonical_name, "flask")

    def test_parses_extras_and_marker(self):
        requirement = cdp.parse_pip_requirement(
            'psycopg[binary]==3.3.2; python_version >= "3.12"'
        )
        self.assertEqual(requirement.name, "psycopg")
        self.assertEqual(requirement.extras, ("binary",))
        self.assertEqual(requirement.version, "3.3.2")
        self.assertIn("python_version", requirement.marker or "")

    def test_parses_spacing_around_operator(self):
        requirement = cdp.parse_pip_requirement("numpy  ==  2.5.1")
        self.assertEqual(requirement.version, "2.5.1")

    def test_canonical_name_folds_separators(self):
        self.assertEqual(
            cdp.parse_pip_requirement("flask_cors==6.0.5").canonical_name,
            cdp.parse_pip_requirement("flask-cors==6.0.5").canonical_name,
        )

    def test_rejects_bare_name(self):
        with self.assertRaises(cdp.PinError):
            cdp.parse_pip_requirement("Flask")

    def test_rejects_option_line(self):
        with self.assertRaises(cdp.PinError):
            cdp.parse_pip_requirement("-r other-requirements.txt")

    def test_rejects_url(self):
        with self.assertRaises(cdp.PinError):
            cdp.parse_pip_requirement("https://example.invalid/pkg.whl")

    def test_rejects_vcs_and_direct_reference(self):
        for line in ("git+https://example.invalid/pkg.git", "pkg @ https://example.invalid/x"):
            with self.assertRaises(cdp.PinError):
                cdp.parse_pip_requirement(line)


# ── pip: validation ───────────────────────────────────────────────────────────

class TestValidatePipPins(unittest.TestCase):

    def test_accepts_fully_pinned_file(self):
        text = (
            "# pinned\n"
            "Flask==3.1.3\n"
            "psycopg[binary]==3.3.2\n"
            "\n"
            "numpy==2.5.1  # verified with the C2PA fixtures\n"
        )
        self.assertEqual(cdp.validate_pip_pins(text), [])

    def test_accepts_arbitrary_equality_operator(self):
        self.assertEqual(cdp.validate_pip_pins("Flask===3.1.3"), [])

    def test_accepts_line_continuation(self):
        text = 'cryptography==50.0.0; python_version >= \\\n    "3.12"\n'
        self.assertEqual(cdp.validate_pip_pins(text), [])

    def test_rejects_range_operators(self):
        for operator in (">=", "<=", "~=", "!=", ">", "<"):
            messages = cdp.validate_pip_pins(f"Flask{operator}3.1.3")
            self.assertEqual(len(messages), 1, operator)
            self.assertIn("exact '==' pin", messages[0])

    def test_rejects_bare_name(self):
        messages = cdp.validate_pip_pins("Flask")
        self.assertEqual(len(messages), 1)
        self.assertIn("no version specifier", messages[0])

    def test_rejects_wildcard_version(self):
        messages = cdp.validate_pip_pins("numpy==2.*")
        self.assertEqual(len(messages), 1)
        self.assertIn("not a concrete version", messages[0])

    def test_rejects_dist_tag_version(self):
        messages = cdp.validate_pip_pins("numpy==latest")
        self.assertEqual(len(messages), 1)

    def test_rejects_non_numeric_version(self):
        messages = cdp.validate_pip_pins("numpy==stable")
        self.assertEqual(len(messages), 1)
        self.assertIn("does not start with a digit", messages[0])

    def test_rejects_duplicates_after_normalization(self):
        text = "flask-cors==6.0.5\nflask_cors==6.0.5\n"
        messages = cdp.validate_pip_pins(text)
        self.assertEqual(len(messages), 1)
        self.assertIn("duplicate requirement", messages[0])
        self.assertIn("line 1", messages[0])

    def test_rejects_option_and_url_lines(self):
        text = "-r base.txt\nhttps://example.invalid/pkg.whl\n"
        messages = cdp.validate_pip_pins(text)
        self.assertEqual(len(messages), 2)

    def test_rejects_empty_file(self):
        messages = cdp.validate_pip_pins("")
        self.assertEqual(len(messages), 1)
        self.assertIn("no pinned requirements", messages[0])

    def test_reports_line_continuation_at_eof(self):
        messages = cdp.validate_pip_pins("Flask==3.1.3 \\\n")
        self.assertEqual(len(messages), 1)
        self.assertIn("continuation at end of file", messages[0])

    def test_reports_credentials_without_echoing_them(self):
        secret = "ghp_" + "0" * 36
        messages = cdp.validate_pip_pins(f"internal-token=={secret}\n")
        self.assertEqual(len(messages), 1)
        self.assertIn("pasted credential", messages[0])
        self.assertNotIn("0" * 16, messages[0])
        self.assertNotIn(secret, messages[0])

    def test_findings_are_capped(self):
        report = cdp.Report(max_findings=2)
        report.extend_findings(["a", "b", "c"])
        self.assertEqual(report.findings, ["a", "b"])
        self.assertEqual(report.suppressed, 1)

    def test_oversized_manifest_is_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            path.write_bytes(b"#" + b"x" * (cdp.MAX_FILE_BYTES + 1))
            report = _report()
            self.assertIsNone(cdp.read_text(path, report))
            self.assertEqual(report.exit_code(), 2)
            self.assertIn("exceeds", report.unreadable[0])

    def test_size_limit_boundary_is_inclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            path.write_bytes(b"#" + b"x" * (cdp.MAX_FILE_BYTES - 1))
            report = _report()
            self.assertIsNotNone(cdp.read_text(path, report))
            self.assertEqual(report.exit_code(), 0)


# ── npm ───────────────────────────────────────────────────────────────────────

class TestValidateNpmWorkspace(unittest.TestCase):

    def test_accepts_in_sync_workspace(self):
        self.assertEqual(
            cdp.validate_npm_workspace(_manifest(), _lock(), "m", "l"), []
        )

    def test_rejects_missing_lockfile(self):
        messages = cdp.validate_npm_workspace(_manifest(), None, "m", "l")
        self.assertEqual(len(messages), 1)
        self.assertIn("lockfile is missing", messages[0])

    def test_rejects_old_lockfile_version(self):
        messages = cdp.validate_npm_workspace(
            _manifest(), _lock(lockfileVersion=1), "m", "l"
        )
        self.assertEqual(len(messages), 1)
        self.assertIn("predates v2", messages[0])

    def test_rejects_non_integer_lockfile_version(self):
        messages = cdp.validate_npm_workspace(
            _manifest(), _lock(lockfileVersion="3"), "m", "l"
        )
        self.assertEqual(len(messages), 1)
        self.assertIn("must be an integer", messages[0])

    def test_rejects_name_mismatch(self):
        messages = cdp.validate_npm_workspace(
            _manifest(), _lock(name="other"), "m", "l"
        )
        self.assertEqual(len(messages), 1)
        self.assertIn("lock names", messages[0])

    def test_rejects_empty_packages_map(self):
        messages = cdp.validate_npm_workspace(
            _manifest(), _lock(packages={}), "m", "l"
        )
        self.assertEqual(len(messages), 1)
        self.assertIn("'packages' map", messages[0])

    def test_rejects_missing_root_package(self):
        messages = cdp.validate_npm_workspace(
            _manifest(), _lock(packages={"node_modules/left-pad": {}}), "m", "l"
        )
        self.assertTrue(any("no root '' package" in m for m in messages))

    def test_rejects_declaration_added_without_install(self):
        manifest = _manifest()
        manifest["dependencies"]["pako"] = "^3.0.1"
        messages = cdp.validate_npm_workspace(manifest, _lock(), "m", "l")
        self.assertEqual(len(messages), 2)
        self.assertTrue(any("out of sync" in m for m in messages))
        self.assertTrue(any("absent from the lock: pako" in m for m in messages))

    def test_rejects_lock_only_entry(self):
        lock = _lock()
        lock["packages"][""]["dependencies"]["ogl"] = "^1.0.11"
        messages = cdp.validate_npm_workspace(_manifest(), lock, "m", "l")
        self.assertEqual(len(messages), 1)
        self.assertIn("only in the lock: ogl", messages[0])

    def test_rejects_changed_specifier(self):
        lock = _lock()
        lock["packages"][""]["dependencies"]["left-pad"] = "^1.2.0"
        messages = cdp.validate_npm_workspace(_manifest(), lock, "m", "l")
        self.assertEqual(len(messages), 1)
        self.assertIn("^1.3.0 vs ^1.2.0", messages[0])

    def test_rejects_declared_but_unresolved_dependency(self):
        lock = _lock()
        del lock["packages"]["node_modules/vitest"]
        messages = cdp.validate_npm_workspace(_manifest(), lock, "m", "l")
        self.assertEqual(len(messages), 1)
        self.assertIn("declared but not resolved", messages[0])
        self.assertIn("vitest", messages[0])

    def test_resolves_nested_node_modules_entry(self):
        lock = _lock()
        del lock["packages"]["node_modules/vitest"]
        lock["packages"]["node_modules/left-pad/node_modules/vitest"] = {
            "version": "3.0.0"
        }
        self.assertEqual(cdp.validate_npm_workspace(_manifest(), lock, "m", "l"), [])

    def test_rejects_wildcard_and_dist_tag_specifiers(self):
        for spec in ("*", "latest", ""):
            manifest = _manifest(dependencies={"left-pad": spec})
            messages = cdp.validate_npm_workspace(manifest, _lock(), "m", "l")
            self.assertTrue(
                any("glob and dist-tag" in m for m in messages), spec
            )

    def test_rejects_non_registry_source(self):
        manifest = _manifest(dependencies={"left-pad": "git+https://example.invalid/x.git"})
        messages = cdp.validate_npm_workspace(manifest, _lock(), "m", "l")
        self.assertTrue(any("non-registry source" in m for m in messages))

    def test_rejects_non_string_specifier(self):
        messages = cdp.validate_npm_workspace(
            _manifest(dependencies={"left-pad": 1}), _lock(), "m", "l"
        )
        self.assertTrue(any("must be a version string" in m for m in messages))

    def test_rejects_non_object_manifest(self):
        messages = cdp.validate_npm_workspace([], _lock(), "m", "l")
        self.assertEqual(len(messages), 1)
        self.assertIn("JSON object", messages[0])

    def test_rejects_non_object_dependency_section(self):
        messages = cdp.validate_npm_workspace(
            _manifest(dependencies=["left-pad"]), _lock(), "m", "l"
        )
        self.assertTrue(any("must be an object" in m for m in messages))

    def test_dependency_count_is_bounded_in_message(self):
        manifest = _manifest(
            dependencies={f"pkg-{index}": "^1.0.0" for index in range(20)}
        )
        messages = cdp.validate_npm_workspace(manifest, _lock(), "m", "l")
        drift = [m for m in messages if "out of sync" in m]
        self.assertEqual(len(drift), 1)
        self.assertIn("more", drift[0])

    def test_longest_matching_suffix_wins_for_nested_names(self):
        manifest = _manifest(dependencies={"@scope/pkg": "^1.0.0"})
        lock = _lock()
        lock["packages"][""]["dependencies"] = {"@scope/pkg": "^1.0.0"}
        lock["packages"]["node_modules/@scope/pkg"] = {"version": "1.0.0"}
        self.assertEqual(cdp.validate_npm_workspace(manifest, lock, "m", "l"), [])


# ── cargo ─────────────────────────────────────────────────────────────────────

class TestValidateCargoWorkspace(unittest.TestCase):

    def test_accepts_in_sync_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            report = _report()
            self.assertEqual(cdp.validate_cargo_workspace(workspace, report), [])
            self.assertEqual(report.exit_code(), 0)

    def test_missing_lockfile_is_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=None)
            report = _report()
            cdp.validate_cargo_workspace(workspace, report)
            self.assertEqual(report.exit_code(), 2)
            self.assertTrue(any("Cargo.lock" in m for m in report.unreadable))

    def test_rejects_stale_member_version(self):
        lock = CARGO_LOCK.replace('name = "demo"\nversion = "1.0.0"', 'name = "demo"\nversion = "0.9.0"')
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=lock)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("predates the manifest" in m for m in messages))

    def test_rejects_member_absent_from_lock(self):
        lock = CARGO_LOCK.replace('name = "demo"\nversion = "1.0.0"\n\n', "")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=lock)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("absent from" in m for m in messages))

    def test_rejects_registry_dependency_absent_from_lock(self):
        lock = CARGO_LOCK.replace('name = "soroban-sdk"', 'name = "other-sdk"')
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=lock)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("not resolved in" in m for m in messages))

    def test_rejects_unpinned_git_dependency(self):
        member = CARGO_MEMBER + '\n[dependencies.other]\ngit = "https://example.invalid/x"\n'
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "contracts/demo/Cargo.toml", member)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("use 'rev' or 'tag'" in m for m in messages))

    def test_rejects_git_dependency_pinned_by_branch(self):
        member = (
            CARGO_MEMBER
            + '\n[dependencies.other]\ngit = "https://example.invalid/x"\n'
            + 'branch = "main"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "contracts/demo/Cargo.toml", member)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("pinned by branch" in m for m in messages))

    def test_accepts_git_dependency_pinned_by_tag(self):
        member = (
            CARGO_MEMBER
            + '\n[dependencies.other]\ngit = "https://example.invalid/x"\ntag = "v1.0.0"\n'
        )
        lock = CARGO_LOCK + '\n[[package]]\nname = "other"\nversion = "1.0.0"\n'
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=lock)
            _write(workspace, "contracts/demo/Cargo.toml", member)
            self.assertEqual(cdp.validate_cargo_workspace(workspace, _report()), [])

    def test_accepts_local_path_dependency_without_lock_entry(self):
        member = CARGO_MEMBER + '\n[dependencies.helper]\npath = "../helper"\n'
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "contracts/demo/Cargo.toml", member)
            self.assertEqual(cdp.validate_cargo_workspace(workspace, _report()), [])

    def test_rejects_wildcard_version(self):
        workspace_manifest = CARGO_WORKSPACE.replace('soroban-sdk = "27"', 'soroban-sdk = "*"')
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "Cargo.toml", workspace_manifest)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("which floats" in m for m in messages))

    def test_rejects_exact_pin_not_resolved(self):
        workspace_manifest = CARGO_WORKSPACE.replace('soroban-sdk = "27"', 'soroban-sdk = "=27.0.1"')
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "Cargo.toml", workspace_manifest)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("requires '=27.0.1'" in m for m in messages))

    def test_rejects_short_requirement_outside_its_prefix(self):
        workspace_manifest = CARGO_WORKSPACE.replace('soroban-sdk = "27"', 'soroban-sdk = "28"')
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "Cargo.toml", workspace_manifest)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("requires '28'" in m for m in messages))

    def test_accepts_short_requirement_within_its_prefix(self):
        self.assertTrue(cdp._cargo_version_matches("27", "27.0.2"))
        self.assertTrue(cdp._cargo_version_matches("0.87", "0.87.0"))
        self.assertFalse(cdp._cargo_version_matches("0.87", "0.88.0"))
        self.assertFalse(cdp._cargo_version_matches("=1.2.3", "1.2.4"))
        self.assertTrue(cdp._cargo_version_matches("^1.2.3", "1.9.0"))

    def test_rejects_old_lock_version(self):
        lock = CARGO_LOCK.replace("version = 4", "version = 2", 1)
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=lock)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("predates v3" in m for m in messages))

    def test_rejects_empty_lock(self):
        lock = "version = 4\n"
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=lock)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("no [[package]] entries" in m for m in messages))

    def test_rejects_member_pattern_matching_nothing(self):
        workspace_manifest = CARGO_WORKSPACE.replace('["contracts/*"]', '["missing/*"]')
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "Cargo.toml", workspace_manifest)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("matches no Cargo.toml" in m for m in messages))

    def test_rejects_workspace_inheritance_without_definition(self):
        workspace_manifest = CARGO_WORKSPACE.replace('soroban-sdk = "27"', 'other-sdk = "1"')
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "Cargo.toml", workspace_manifest)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(
                any("does not define it in [workspace.dependencies]" in m for m in messages)
            )

    def test_rejects_non_table_dependency_entry(self):
        member = CARGO_MEMBER.replace(
            "soroban-sdk = { workspace = true }",
            "soroban-sdk = { workspace = true }\nhelper = 3",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "contracts/demo/Cargo.toml", member)
            messages = cdp.validate_cargo_workspace(workspace, _report())
            self.assertTrue(any("version string or a table" in m for m in messages))

    def test_invalid_toml_is_a_parse_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp))
            _write(workspace, "contracts/demo/Cargo.toml", "[package\nname = 'demo'\n")
            report = _report()
            cdp.validate_cargo_workspace(workspace, report)
            self.assertEqual(report.exit_code(), 3)
            self.assertTrue(report.parse_errors)

    def test_dev_and_target_dependencies_are_collected(self):
        member = CARGO_MEMBER + (
            '\n[target.\'cfg(unix)\'.dev-dependencies]\nhelper = "1.0.0"\n'
        )
        lock = CARGO_LOCK + '\n[[package]]\nname = "helper"\nversion = "1.0.0"\n'
        with tempfile.TemporaryDirectory() as tmp:
            workspace = _cargo_tree(Path(tmp), lock=lock)
            _write(workspace, "contracts/demo/Cargo.toml", member)
            self.assertEqual(cdp.validate_cargo_workspace(workspace, _report()), [])

    def test_check_cargo_missing_workspace_is_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = _report()
            cdp.check_cargo(Path(tmp), report)
            self.assertEqual(report.exit_code(), 2)


# ── noir ──────────────────────────────────────────────────────────────────────

class TestValidateZkToolchain(unittest.TestCase):

    def test_accepts_pinned_toolchain(self):
        self.assertEqual(cdp.validate_zk_toolchain(TOOLCHAIN_LOCK), [])

    def test_rejects_non_object_lock(self):
        self.assertEqual(len(cdp.validate_zk_toolchain([], "l")), 1)

    def test_rejects_missing_version_field(self):
        lock = dict(TOOLCHAIN_LOCK)
        del lock["version"]
        messages = cdp.validate_zk_toolchain(lock)
        self.assertTrue(any("'version' must be an integer" in m for m in messages))

    def test_rejects_missing_toolchain_table(self):
        messages = cdp.validate_zk_toolchain({"version": 1})
        self.assertTrue(any("'toolchain' mapping is missing" in m for m in messages))

    def test_rejects_floating_tool_versions(self):
        lock = {
            "version": 1,
            "toolchain": {
                "nargo": {"version": "latest"},
                "barretenberg": {"version": "*"},
            },
        }
        messages = cdp.validate_zk_toolchain(lock)
        self.assertEqual(len(messages), 2)

    def test_rejects_missing_tool_entry(self):
        lock = {"version": 1, "toolchain": {"nargo": {"version": "1.0.0"}}}
        messages = cdp.validate_zk_toolchain(lock)
        self.assertTrue(any("barretenberg entry is missing" in m for m in messages))


class TestValidateNargoManifest(unittest.TestCase):

    def _doc(self, body: str) -> dict:
        import tomllib

        return tomllib.loads(textwrap.dedent(body).lstrip("\n"))

    def test_accepts_minimal_manifest(self):
        doc = self._doc(NARGO_MANIFEST)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                cdp.validate_nargo_manifest(doc, "n", Path(tmp)), []
            )

    def test_rejects_missing_compiler_version(self):
        doc = self._doc(
            """
            [package]
            name = "demo"
            type = "bin"
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            messages = cdp.validate_nargo_manifest(doc, "n", Path(tmp))
        self.assertTrue(any("compiler_version is missing" in m for m in messages))

    def test_rejects_non_version_compiler_constraint(self):
        doc = self._doc(
            """
            [package]
            name = "demo"
            compiler_version = "recent"

            [dependencies]
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            messages = cdp.validate_nargo_manifest(doc, "n", Path(tmp))
        self.assertTrue(any("names no version" in m for m in messages))

    def test_rejects_missing_package_name(self):
        doc = self._doc(
            """
            [package]
            compiler_version = ">=1.0.0"
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            messages = cdp.validate_nargo_manifest(doc, "n", Path(tmp))
        self.assertTrue(any("must declare a name" in m for m in messages))

    def test_rejects_plain_string_dependency(self):
        doc = self._doc(NARGO_MANIFEST + 'other = "1.0.0"\n')
        with tempfile.TemporaryDirectory() as tmp:
            messages = cdp.validate_nargo_manifest(doc, "n", Path(tmp))
        self.assertTrue(any("must be a table" in m for m in messages))

    def test_rejects_dangling_path_dependency(self):
        doc = self._doc(NARGO_MANIFEST + '[dependencies.helper]\npath = "../helper"\n')
        with tempfile.TemporaryDirectory() as tmp:
            messages = cdp.validate_nargo_manifest(doc, "n", Path(tmp))
        self.assertTrue(any("does not exist" in m for m in messages))

    def test_accepts_existing_path_dependency(self):
        doc = self._doc(NARGO_MANIFEST + '[dependencies.helper]\npath = "../helper"\n')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "helper").mkdir()
            self.assertEqual(
                cdp.validate_nargo_manifest(doc, "n", root / "circuit"), []
            )

    def test_rejects_unpinned_git_dependency(self):
        doc = self._doc(
            NARGO_MANIFEST + '[dependencies.helper]\ngit = "https://example.invalid/x"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            messages = cdp.validate_nargo_manifest(doc, "n", Path(tmp))
        self.assertTrue(any("without 'rev' or 'tag'" in m for m in messages))

    def test_accepts_pinned_git_dependency(self):
        doc = self._doc(
            NARGO_MANIFEST
            + '[dependencies.helper]\ngit = "https://example.invalid/x"\ntag = "v1"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(cdp.validate_nargo_manifest(doc, "n", Path(tmp)), [])

    def test_check_zk_missing_lock_is_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = _report()
            cdp.check_zk(Path(tmp), report)
            self.assertEqual(report.exit_code(), 2)

    def test_check_zk_reports_no_circuits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _zk_tree(Path(tmp))
            (root / "zk/noir/demo/Nargo.toml").unlink()
            report = _report()
            cdp.check_zk(root, report)
            self.assertEqual(report.exit_code(), 1)
            self.assertIn("no circuit manifests", report.findings[0])

    def test_check_zk_accepts_valid_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = _report()
            cdp.check_zk(_zk_tree(Path(tmp)), report)
            self.assertEqual(report.exit_code(), 0)
            self.assertEqual(len(report.summaries), 1)

    def test_check_zk_invalid_lock_json_is_a_parse_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "zk/toolchain.lock.json", "{not json")
            _write(root, "zk/noir/demo/Nargo.toml", NARGO_MANIFEST)
            report = _report()
            cdp.check_zk(root, report)
            self.assertEqual(report.exit_code(), 3)


# ── report and CLI ────────────────────────────────────────────────────────────

class TestReportAndCli(unittest.TestCase):

    def test_exit_code_precedence(self):
        report = _report()
        report.finding("policy")
        self.assertEqual(report.exit_code(), 1)
        report.parse_errors.append("bad json")
        self.assertEqual(report.exit_code(), 3)
        report.unreadable.append("missing")
        self.assertEqual(report.exit_code(), 2)

    def test_run_checks_missing_root(self):
        report = cdp.run_checks(Path("/nonexistent/harpocrates"))
        self.assertEqual(report.exit_code(), 2)
        self.assertFalse(report.ok())

    def test_run_checks_reports_every_missing_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = cdp.run_checks(Path(tmp))
            self.assertEqual(report.exit_code(), 2)
            self.assertTrue(any("requirements.txt" in m for m in report.unreadable))
            self.assertTrue(any("Cargo.toml" in m for m in report.unreadable))
            self.assertTrue(any("toolchain.lock.json" in m for m in report.unreadable))

    def test_cli_json_reports_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _pinned_tree(Path(tmp))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = cdp.main(["--json", "--root", str(root)])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["counts"]["findings"], 0)
            self.assertEqual(len(payload["summaries"]), 5)

    def test_cli_text_output_flags_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _pinned_tree(Path(tmp))
            _write(root, cdp.PIP_MANIFEST, "Flask>=3.1.3\n")
            stderr, stdout = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                code = cdp.main(["--root", str(root)])
            self.assertEqual(code, 1)
            self.assertIn("dependency pins failed", stderr.getvalue())
            self.assertIn("finding:", stderr.getvalue())

    def test_cli_honours_max_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _pinned_tree(Path(tmp))
            _write(root, cdp.PIP_MANIFEST, "a\nb\nc\n")
            with contextlib.redirect_stderr(io.StringIO()):
                report = cdp.run_checks(root, max_findings=1)
            self.assertEqual(len(report.findings), 1)
            self.assertEqual(report.suppressed, 2)


# ── regression: the committed repository ──────────────────────────────────────

class TestRepositoryIsPinned(unittest.TestCase):

    def test_repository_passes(self):
        """The gate must be green on the tree that introduces it."""
        if not (REPO_ROOT / cdp.PIP_MANIFEST).is_file():
            self.skipTest("repository manifests not available")
        report = cdp.run_checks(REPO_ROOT)
        self.assertEqual(
            report.findings,
            [],
            "unpinned or stale dependency input in the repository",
        )
        self.assertEqual(report.unreadable, [])
        self.assertEqual(report.parse_errors, [])
        self.assertTrue(report.ok())

    def test_repository_requirements_are_all_pinned(self):
        path = REPO_ROOT / cdp.PIP_MANIFEST
        if not path.is_file():
            self.skipTest("requirements.txt not available")
        self.assertEqual(
            cdp.validate_pip_pins(path.read_text(encoding="utf-8")), []
        )


if __name__ == "__main__":
    unittest.main()
