from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT_DIR / "zk" / "noir" / "scripts" / "generate-silent-witness-wsl.ps1"


def generate_silent_witness(
    video_hash: str,
    credential_secret: str,
    nullifier_secret: str,
    verifier_scope: str = "0",
    epoch: int = 0,
) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT_PATH),
            "-VideoHash",
            video_hash,
            "-CredentialSecret",
            credential_secret,
            "-NullifierSecret",
            nullifier_secret,
            "-VerifierScope",
            verifier_scope,
            "-Epoch",
            str(epoch),
        ],
        cwd=ROOT_DIR,
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("NOIR_PROOF_TIMEOUT_SECONDS", "180")),
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or "Noir proof generation failed.")

    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)

    raise RuntimeError("Noir proof generator did not return JSON.")
