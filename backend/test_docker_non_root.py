"""Regression and boundary tests for non-root deployment container execution.

Validates that backend and frontend Dockerfiles and docker-compose configurations
execute under dedicated unprivileged non-root users without embedding secrets,
passwords, private keys, or media paths.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent

BACKEND_DOCKERFILE = BACKEND_DIR / "Dockerfile"
FRONTEND_DOCKERFILE = ROOT_DIR / "frontend" / "Dockerfile"
DOCKER_COMPOSE = ROOT_DIR / "docker-compose.yml"
DOCKER_COMPOSE_EXAMPLE = ROOT_DIR / "docker-compose.example.yml"

USER_DIRECTIVE_RE = re.compile(r"^\s*USER\s+(?P<user>[^\s#]+)", re.MULTILINE)
EXPOSE_DIRECTIVE_RE = re.compile(r"^\s*EXPOSE\s+(?P<ports>.+)$", re.MULTILINE)

BANNED_SECRETS = (
    "password",
    "secret",
    "private_key",
    "witness",
    ".mp4",
    "database_url",
    "ghp_",
    "glpat-",
)


def _extract_users(dockerfile_text: str) -> list[str]:
    return [m.group("user").strip() for m in USER_DIRECTIVE_RE.finditer(dockerfile_text)]


def _extract_exposed_ports(dockerfile_text: str) -> list[int]:
    ports: list[int] = []
    for m in EXPOSE_DIRECTIVE_RE.finditer(dockerfile_text):
        for raw in m.group("ports").split():
            clean = raw.split("/")[0].strip()
            if clean.isdigit():
                ports.append(int(clean))
    return ports


class TestDockerNonRoot(unittest.TestCase):
    def test_backend_dockerfile_runs_as_non_root(self):
        text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        users = _extract_users(text)
        self.assertTrue(len(users) >= 1, "backend Dockerfile must declare at least one USER instruction")
        final_user = users[-1]
        self.assertIn("harpocrates", final_user.lower(), f"backend user must be harpocrates, got: {final_user}")
        self.assertNotIn("root", final_user.lower())
        self.assertNotEqual(final_user, "0")

    def test_backend_creates_harpocrates_user_and_group(self):
        text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("groupadd", text)
        self.assertIn("useradd", text)
        self.assertIn("10001", text)
        self.assertIn("--no-install-recommends", text)
        self.assertIn("--chown=harpocrates:harpocrates", text)

    def test_backend_exposed_port_is_unprivileged(self):
        text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        ports = _extract_exposed_ports(text)
        self.assertIn(5050, ports)
        for p in ports:
            self.assertGreaterEqual(p, 1024, f"port {p} must be an unprivileged port (>= 1024)")

    def test_frontend_dockerfile_runs_as_non_root(self):
        text = FRONTEND_DOCKERFILE.read_text(encoding="utf-8")
        users = _extract_users(text)
        self.assertTrue(len(users) >= 1, "frontend Dockerfile must declare at least one USER instruction")
        final_user = users[-1]
        self.assertIn("nginx", final_user.lower(), f"frontend user must be nginx, got: {final_user}")
        self.assertNotIn("root", final_user.lower())
        self.assertNotEqual(final_user, "0")

    def test_frontend_configures_unprivileged_pid_and_cache(self):
        text = FRONTEND_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("/tmp/nginx.pid", text)
        self.assertIn("chown -R nginx:nginx", text)
        self.assertIn("--chown=nginx:nginx", text)

    def test_frontend_exposed_port_is_unprivileged(self):
        text = FRONTEND_DOCKERFILE.read_text(encoding="utf-8")
        ports = _extract_exposed_ports(text)
        self.assertIn(8080, ports)
        for p in ports:
            self.assertGreaterEqual(p, 1024, f"port {p} must be an unprivileged port (>= 1024)")

    def test_compose_files_declare_no_new_privileges(self):
        for compose_path in (DOCKER_COMPOSE, DOCKER_COMPOSE_EXAMPLE):
            text = compose_path.read_text(encoding="utf-8")
            self.assertIn(
                "no-new-privileges:true",
                text.replace(" ", ""),
                f"{compose_path.name} must declare no-new-privileges:true",
            )
            # Ensure neither compose file explicitly runs as root
            self.assertNotIn("privileged: true", text)
            self.assertNotIn("user: root", text)
            self.assertNotIn("user: '0'", text)
            self.assertNotIn('user: "0"', text)

    def test_privacy_cleanliness_across_container_configs(self):
        # Privacy boundary: no credentials, real video paths, or private keys in container manifests
        for path in (BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE, DOCKER_COMPOSE, DOCKER_COMPOSE_EXAMPLE):
            content = path.read_text(encoding="utf-8").lower()
            for token in BANNED_SECRETS:
                self.assertNotIn(
                    token,
                    content,
                    f"{path.name} must not contain banned secret pattern '{token}'",
                )

    def test_user_parser_handles_empty_and_malformed_inputs(self):
        self.assertEqual(_extract_users(""), [])
        self.assertEqual(_extract_users("# Comment only\nRUN true\n"), [])
        self.assertEqual(_extract_users("USER  \t  10001:10001 \n"), ["10001:10001"])

    def test_expose_parser_handles_varied_formats(self):
        self.assertEqual(_extract_exposed_ports("EXPOSE 5050/tcp 5051/udp"), [5050, 5051])
        self.assertEqual(_extract_exposed_ports("EXPOSE invalid"), [])


if __name__ == "__main__":
    unittest.main()
