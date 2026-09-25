#!/usr/bin/env python3
"""Validation gate for Harpocrates deployment containers.

Validates that deployment container specifications (Dockerfiles and docker-compose
manifests) strictly enforce non-root execution, unprivileged port bindings, and
least-privilege security options (no-new-privileges).

Privacy and Safety:
  Never prints or embeds private keys, secrets, passwords, witness values, or real media paths.

Exit codes:
  0 — all container specifications pass validation
  1 — container specification violates security requirements
  2 — file not found, unreadable, or invalid usage
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BACKEND_DOCKERFILE = ROOT / "backend" / "Dockerfile"
DEFAULT_FRONTEND_DOCKERFILE = ROOT / "frontend" / "Dockerfile"
DEFAULT_COMPOSE_FILE = ROOT / "docker-compose.yml"
DEFAULT_COMPOSE_EXAMPLE = ROOT / "docker-compose.example.yml"

MAX_FILE_BYTES = 256 * 1024

USER_RE = re.compile(r"^\s*USER\s+(?P<user>[^\s#]+)", re.MULTILINE)
EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(?P<ports>.+)$", re.MULTILINE)

BANNED_LITERALS = (
    "private_key",
    "secret_key",
    "password",
    "witness_secret",
    "credential_secret",
    "nullifier_secret",
    "postgres://",
    "postgresql://",
    ".mp4",
)


class ContainerValidationError(ValueError):
    """Raised when container configurations violate non-root or security rules."""


def read_text_safe(path: Path) -> str:
    """Reads a file with fail-closed size limits."""
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    size = path.stat().st_size
    if size == 0:
        raise ContainerValidationError(f"file is empty: {path}")
    if size > MAX_FILE_BYTES:
        raise ContainerValidationError(f"file exceeds {MAX_FILE_BYTES} bytes limit: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ContainerValidationError(f"file is not valid UTF-8: {path} ({exc})") from exc


def parse_dockerfile_user(content: str) -> str | None:
    """Extracts the final effective USER instruction from a Dockerfile."""
    matches = list(USER_RE.finditer(content))
    if not matches:
        return None
    return matches[-1].group("user").strip()


def parse_exposed_ports(content: str) -> list[int]:
    """Parses port numbers declared by EXPOSE instructions."""
    ports: list[int] = []
    for match in EXPOSE_RE.finditer(content):
        raw_ports = match.group("ports").split()
        for p in raw_ports:
            # Handle forms like 5050/tcp
            cleaned = p.split("/")[0].strip()
            if cleaned.isdigit():
                ports.append(int(cleaned))
    return ports


def validate_dockerfile(path: Path) -> list[str]:
    """Validates that a Dockerfile executes as non-root and conforms to safety gates."""
    errors: list[str] = []
    content = read_text_safe(path)

    # Privacy scan: ensure no credentials or sensitive tokens are embedded
    content_lower = content.lower()
    for banned in BANNED_LITERALS:
        if banned in content_lower:
            errors.append(f"{path.name}: contains banned sensitive literal pattern")
            break

    user = parse_dockerfile_user(content)
    if not user:
        errors.append(f"{path.name}: missing USER directive (defaults to root)")
    else:
        user_name = user.split(":")[0].strip().lower()
        if user_name in {"root", "0"}:
            errors.append(f"{path.name}: declares root execution ({user})")

    ports = parse_exposed_ports(content)
    for port in ports:
        if port < 1024:
            errors.append(f"{path.name}: exposes privileged port < 1024 ({port})")

    return errors


def validate_compose_file(path: Path) -> list[str]:
    """Validates docker-compose files for no-new-privileges and unprivileged ports."""
    errors: list[str] = []
    content = read_text_safe(path)

    # Privacy check
    content_lower = content.lower()
    for banned in BANNED_LITERALS:
        if banned in content_lower:
            errors.append(f"{path.name}: contains banned sensitive literal pattern")
            break

    # Security check: verify no-new-privileges is present
    if "no-new-privileges:true" not in content and "no-new-privileges: true" not in content:
        errors.append(f"{path.name}: missing 'no-new-privileges:true' security option")

    # Reject explicit privileged mode
    if re.search(r"^\s*privileged:\s*true\b", content, re.MULTILINE):
        errors.append(f"{path.name}: containers must not run with privileged: true")

    # Reject explicit user: root or user: "0"
    if re.search(r"^\s*user:\s*[\"']?(0|root)(:.*)?[\"']?\s*$", content, re.MULTILINE):
        errors.append(f"{path.name}: compose must not override user to root / 0")

    return errors


def validate_all(
    backend_dockerfile: Path = DEFAULT_BACKEND_DOCKERFILE,
    frontend_dockerfile: Path = DEFAULT_FRONTEND_DOCKERFILE,
    compose_file: Path = DEFAULT_COMPOSE_FILE,
    compose_example: Path = DEFAULT_COMPOSE_EXAMPLE,
) -> tuple[int, list[str]]:
    """Runs all deployment container security checks."""
    all_errors: list[str] = []

    for df in (backend_dockerfile, frontend_dockerfile):
        try:
            errs = validate_dockerfile(df)
            all_errors.extend(errs)
        except (FileNotFoundError, ContainerValidationError) as exc:
            all_errors.append(str(exc))

    for cf in (compose_file, compose_example):
        if cf.is_file():
            try:
                errs = validate_compose_file(cf)
                all_errors.extend(errs)
            except (FileNotFoundError, ContainerValidationError) as exc:
                all_errors.append(str(exc))

    exit_code = 1 if all_errors else 0
    return exit_code, all_errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate non-root deployment container specifications")
    parser.add_argument("--check", action="store_true", help="Validate default repository container files")
    parser.add_argument("--backend-dockerfile", type=Path, default=DEFAULT_BACKEND_DOCKERFILE)
    parser.add_argument("--frontend-dockerfile", type=Path, default=DEFAULT_FRONTEND_DOCKERFILE)
    parser.add_argument("--compose-file", type=Path, default=DEFAULT_COMPOSE_FILE)
    parser.add_argument("--compose-example", type=Path, default=DEFAULT_COMPOSE_EXAMPLE)
    args = parser.parse_args(argv)

    try:
        code, errors = validate_all(
            backend_dockerfile=args.backend_dockerfile,
            frontend_dockerfile=args.frontend_dockerfile,
            compose_file=args.compose_file,
            compose_example=args.compose_example,
        )
    except Exception as exc:
        print(f"ERROR: container validation failed to run: {exc}", file=sys.stderr)
        return 2

    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        return 1

    print("PASS: all deployment container specifications enforce non-root execution and security options")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
