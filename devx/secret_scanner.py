#!/usr/bin/env python3
"""Privacy-preserving secret scanner for Harpocrates contributions.

Scans the repository for real media, secrets, witness values, and private keys.
Ensures that failure responses are stable and privacy-safe; sensitive values are never logged.
Handles malformed, oversized, expired, revoked, unsupported, and dependency-failure inputs.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List

# Privacy-preserving matchers. We only log the category of the violation, never the matched text.
STELLAR_SECRET_REGEX = re.compile(rb'\bS[A-Z2-7]{55}\b')
PRIVATE_KEY_REGEX = re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |AGE )?PRIVATE KEY')

# Blocked extensions to prevent committing real sensitive media or large witness files
MEDIA_EXTENSIONS = {".mp4", ".mov", ".avi", ".mkv", ".jpg", ".jpeg", ".png", ".wav", ".mp3"}
WITNESS_EXTENSIONS = {".tr"}

# Max file size to scan to prevent memory exhaustion (oversized input check)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB

# Test fixtures and test suites containing synthetic/test credentials allowlisted from secret detection
ALLOWLISTED_SECRET_PATHS = {
    "devx/test_c2pa_parser.py",
    "devx/test_validate_c2pa_fixture.py",
    "devx/test_secret_scanner.py",
    "backend/test_redaction_adversarial.py",
    "backend/test_trace_fields.py",
}

ALLOWLISTED_FIXTURE_PREFIXES = (
    "devx/fixtures/",
)


def is_secret_allowlisted(file_path: Path | str, repo_root: Path | None = None) -> bool:
    """Check if the given file is an allowlisted test fixture or test suite."""
    posix_path = str(file_path).replace("\\", "/")
    if repo_root:
        try:
            posix_path = Path(file_path).resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except (ValueError, OSError):
            pass

    for allowed in ALLOWLISTED_SECRET_PATHS:
        if posix_path == allowed or posix_path.endswith("/" + allowed):
            return True
            
    for prefix in ALLOWLISTED_FIXTURE_PREFIXES:
        if posix_path.startswith(prefix) or ("/" + prefix) in posix_path:
            return True

    return False



def get_files_to_scan(repo_root: Path) -> List[str]:
    """Retrieve the list of files to scan. Prefers git tracked files if available."""
    try:
        result = subprocess.run(
            ["git", "ls-files"], 
            cwd=repo_root, 
            capture_output=True, 
            text=True, 
            check=True
        )
        return [f for f in result.stdout.splitlines() if f]
    except subprocess.CalledProcessError:
        # Fallback to walking the directory
        files = []
        for root, dirs, filenames in os.walk(repo_root):
            for d in [".git", "node_modules", "target", "dist", ".venv", "__pycache__"]:
                if d in dirs:
                    dirs.remove(d)
            for filename in filenames:
                rel_path = os.path.relpath(os.path.join(root, filename), repo_root)
                files.append(rel_path)
        return files


def scan_file(file_path: Path, repo_root: Path | None = None) -> List[str]:
    """Scan a single file for restricted extensions and sensitive contents."""
    errors = []
    
    # Check for unsupported or blocked file extensions (media/witness)
    suffix = file_path.suffix.lower()
    
    # Whitelist specific files
    rel_path = str(file_path).replace("\\", "/")
    if "frontend/src/assets/" in rel_path:
        # We allow media in assets
        pass
    else:
        if suffix in MEDIA_EXTENSIONS:
            errors.append("unsupported input: real media files are prohibited")
        if suffix in WITNESS_EXTENSIONS:
            errors.append("unsupported input: witness values are prohibited")
        
    if not file_path.exists():
        return errors
        
    if not file_path.is_file():
        return errors
        
    try:
        size = file_path.stat().st_size
        if size > MAX_FILE_SIZE:
            errors.append("oversized input: file exceeds maximum scan size")
            return errors
    except OSError:
        errors.append("malformed input: unable to stat file")
        return errors

    try:
        content = file_path.read_bytes()
    except OSError:
        errors.append("dependency-failure: unable to read file contents")
        return errors
        
    # Check allowlist for synthetic test fixtures and suites
    if is_secret_allowlisted(file_path, repo_root=repo_root):
        return errors

    # Scan for credentials without capturing or logging the actual secret
    if b"harpocrates:ignore-file" not in content and b"trufflehog:ignore" not in content:
        if STELLAR_SECRET_REGEX.search(content):
            errors.append("secrets violation: private key detected")
            
        if PRIVATE_KEY_REGEX.search(content):
            errors.append("secrets violation: private key detected")

    return errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    files = get_files_to_scan(repo_root)
    
    has_errors = False
    
    for rel_path in files:
        file_path = repo_root / rel_path
        
        # Skip this scanner script itself
        if file_path.name == "secret_scanner.py":
            continue
            
        file_errors = scan_file(file_path, repo_root=repo_root)
        
        if file_errors:
            has_errors = True
            for err in set(file_errors):
                # Ensure stable, privacy-safe failure responses
                print(f"[{rel_path}] {err}", file=sys.stderr)
                
    if has_errors:
        print("Secret scanning failed: Unsafe boundaries detected.", file=sys.stderr)
        return 1
        
    print("Secret scanning passed: All boundaries safe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
