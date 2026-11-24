from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_cli_exports as verify


class VerifyCliExportsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.cli_package = self.root / "cli" / "package.json"
        self.cli_dist = self.root / "cli" / "dist"

    def test_verify_current_tree(self) -> None:
        code = verify.main(["--package", str(self.cli_package), "--dist", str(self.cli_dist)])
        self.assertEqual(code, 0)

    def test_list_exports(self) -> None:
        code = verify.main(["--list", "--package", str(self.cli_package), "--dist", str(self.cli_dist)])
        self.assertEqual(code, 0)

    def test_missing_export_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text(json.dumps({
                "name": "test",
                "exports": {
                    ".": "./dist/index.js",
                    "./foo": "./dist/foo.js",
                }
            }), encoding="utf-8")

            # Create only index.js, not foo.js
            (dist_dir / "index.js").write_text("// index", encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)

    def test_escaping_path_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text(json.dumps({
                "name": "test",
                "exports": {
                    ".": "./dist/index.js",
                    "./escape": "./../outside.js",
                }
            }), encoding="utf-8")

            (dist_dir / "index.js").write_text("// index", encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)

    def test_escaping_path_via_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text(json.dumps({
                "name": "test",
                "exports": {
                    ".": "/absolute/path.js",
                }
            }), encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)

    def test_missing_exports_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text(json.dumps({
                "name": "test",
            }), encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)

    def test_malformed_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text(json.dumps({
                "name": "test",
                "exports": {
                    ".": 123,
                }
            }), encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)

    def test_malformed_package_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text("{ invalid json", encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)

    def test_export_with_import_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text(json.dumps({
                "name": "test",
                "exports": {
                    ".": {
                        "import": "./dist/index.js",
                        "require": "./dist/index.cjs"
                    },
                    "./foo": {
                        "default": "./dist/foo.js"
                    }
                }
            }), encoding="utf-8")

            (dist_dir / "index.js").write_text("// index", encoding="utf-8")
            (dist_dir / "foo.js").write_text("// foo", encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 0)

    def test_export_object_missing_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            package_json.write_text(json.dumps({
                "name": "test",
                "exports": {
                    ".": {
                        "require": "./dist/index.cjs"
                    }
                }
            }), encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)

    def test_path_traversal_with_normalized_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            package_json = tmp_path / "package.json"
            dist_dir = tmp_path / "dist"
            dist_dir.mkdir()

            # This should be rejected as it tries to escape via ../
            package_json.write_text(json.dumps({
                "name": "test",
                "exports": {
                    ".": "./dist/../../outside.js",
                }
            }), encoding="utf-8")

            (dist_dir / "index.js").write_text("// index", encoding="utf-8")

            code = verify.main(["--package", str(package_json), "--dist", str(dist_dir)])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()