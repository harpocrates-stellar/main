"""Tests for deployment container non-root validation gate."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import validate_deployment_containers as vdc


class TestValidateDeploymentContainers(unittest.TestCase):
    def test_default_repo_containers_pass_validation(self):
        code, errors = vdc.validate_all()
        self.assertEqual(code, 0, f"default repo containers must pass validation, got: {errors}")
        self.assertEqual(errors, [])

    def test_missing_file_raises_error(self):
        non_existent = Path("/non/existent/Dockerfile")
        with self.assertRaises(FileNotFoundError):
            vdc.read_text_safe(non_existent)

    def test_empty_file_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        with self.assertRaises(vdc.ContainerValidationError):
            vdc.read_text_safe(path)

    def test_oversized_file_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("A" * (vdc.MAX_FILE_BYTES + 10))
            path = Path(f.name)
        self.addCleanup(path.unlink)
        with self.assertRaises(vdc.ContainerValidationError):
            vdc.read_text_safe(path)

    def test_missing_user_directive_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("FROM python:3.13-slim\nEXPOSE 5050\nCMD ['python']\n")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = vdc.validate_dockerfile(path)
        self.assertTrue(any("missing USER directive" in e for e in errors))

    def test_user_root_explicitly_rejected(self):
        for root_decl in ("USER root", "USER root:root", "USER 0", "USER 0:0"):
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(f"FROM python:3.13-slim\n{root_decl}\nEXPOSE 5050\n")
                path = Path(f.name)
            self.addCleanup(path.unlink)
            errors = vdc.validate_dockerfile(path)
            self.assertTrue(
                any("declares root execution" in e for e in errors),
                f"Expected root execution error for {root_decl}, got: {errors}",
            )

    def test_valid_unprivileged_users_accepted(self):
        for user_decl in (
            "USER harpocrates",
            "USER harpocrates:harpocrates",
            "USER 10001:10001",
            "USER nginx:nginx",
        ):
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(f"FROM alpine\n{user_decl}\nEXPOSE 8080\n")
                path = Path(f.name)
            self.addCleanup(path.unlink)
            errors = vdc.validate_dockerfile(path)
            self.assertEqual(errors, [], f"Expected no errors for {user_decl}, got: {errors}")

    def test_privileged_exposed_port_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("FROM alpine\nUSER appuser\nEXPOSE 80\n")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = vdc.validate_dockerfile(path)
        self.assertTrue(any("exposes privileged port < 1024" in e for e in errors))

    def test_sensitive_literals_in_dockerfile_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("FROM alpine\nENV PASSWORD=supersecret\nUSER appuser\n")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = vdc.validate_dockerfile(path)
        self.assertTrue(any("contains banned sensitive literal pattern" in e for e in errors))

    def test_compose_missing_no_new_privileges_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("services:\n  app:\n    image: test:latest\n    ports:\n      - '5050:5050'\n")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = vdc.validate_compose_file(path)
        self.assertTrue(any("missing 'no-new-privileges:true'" in e for e in errors))

    def test_compose_with_privileged_true_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(
                "services:\n  app:\n    image: test\n    security_opt:\n      - no-new-privileges:true\n    privileged: true\n"
            )
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = vdc.validate_compose_file(path)
        self.assertTrue(any("must not run with privileged: true" in e for e in errors))

    def test_compose_with_root_user_override_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(
                "services:\n  app:\n    image: test\n    security_opt:\n      - no-new-privileges:true\n    user: '0:0'\n"
            )
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = vdc.validate_compose_file(path)
        self.assertTrue(any("compose must not override user to root / 0" in e for e in errors))

    def test_cli_check_flag(self):
        exit_code = vdc.main(["--check"])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
