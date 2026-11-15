from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import statement_descriptor as sd


def _stage_synthetic_repo(tmp_path: Path) -> Path:
    """Copy the minimal reviewed circuit and manifest files into `tmp_path`."""
    files_to_copy = [
        *sd.REVIEWED_SOURCE_PATHS,
        *sd.SCOPED_BROWSER_ARTIFACT_PATHS,
        "zk/toolchain.lock.json",
        "zk/browser.artifacts.manifest.json",
    ]
    for rel in files_to_copy:
        src = REPO_ROOT / rel
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    return tmp_path


def test_committed_scoped_nullifier_descriptor_is_fresh_and_valid() -> None:
    findings = sd.verify_statement_descriptor(
        sd.DEFAULT_DESCRIPTOR_PATH,
        repo_root=REPO_ROOT,
    )
    assert findings == []

    expected = sd.build_statement_descriptor(repo_root=REPO_ROOT)
    committed_bytes = sd.DEFAULT_DESCRIPTOR_PATH.read_bytes()
    assert b"\r" not in committed_bytes
    assert committed_bytes == sd.serialize_descriptor(expected)


def test_descriptor_lists_exact_private_and_public_inputs_and_wire_layout() -> None:
    desc = sd.build_statement_descriptor(repo_root=REPO_ROOT)

    assert desc["format"] == "harpocrates.zk-statement-descriptor"
    assert desc["statement_id"] == "silent_witness/scoped_nullifier_v1"
    assert desc["circuit_version"] == 2
    assert desc["verifier_wire_frame"] == {
        "codec": "hpx-vi/2",
        "field_bytes": 32,
        "frame_id": "silent_witness/v2",
        "public_field_count": 8,
        "total_bytes": 256,
    }

    private_names = [entry["name"] for entry in desc["private_inputs"]]
    assert private_names == ["credential_secret", "nullifier_secret"]
    assert all(entry["visibility"] == "private" for entry in desc["private_inputs"])
    assert [entry["abi_index"] for entry in desc["private_inputs"]] == [0, 1]

    public_names = [entry["name"] for entry in desc["public_inputs"]]
    assert public_names == [
        "video_hash_hi",
        "video_hash_lo",
        "credential_root",
        "nullifier",
        "verifier_scope",
        "epoch",
        "domain_tag",
        "circuit_version",
    ]
    assert all(entry["visibility"] == "public" for entry in desc["public_inputs"])
    assert [entry["abi_index"] for entry in desc["public_inputs"]] == list(range(2, 10))
    assert [entry["wire_byte_offset"] for entry in desc["public_inputs"]] == [
        idx * 32 for idx in range(8)
    ]

    helper = desc["helper_interface"]
    assert [item["name"] for item in helper["inputs"]] == [
        "credential_secret",
        "nullifier_secret",
        "video_hash_hi",
        "video_hash_lo",
        "verifier_scope",
        "epoch",
    ]
    assert [item["name"] for item in helper["public_outputs"]] == [
        "credential_root",
        "nullifier",
        "domain_tag",
    ]


def test_reviewed_source_digests_match_release_compatibility_manifest() -> None:
    compat = json.loads(
        (REPO_ROOT / "release" / "compatibility-manifest.json").read_text(encoding="utf-8")
    )
    pinned_circuits = {
        entry["path"]: entry["sha256"] for entry in compat["artifacts"]
    }
    desc = sd.build_statement_descriptor(repo_root=REPO_ROOT)
    by_path = {
        entry["path"]: entry["lf_sha256"]
        for entry in desc["artifact_bindings"]["reviewed_sources"]
    }

    for rel_path in (
        "zk/noir/silent_witness/src/main.nr",
        "zk/noir/silent_witness/Nargo.toml",
    ):
        assert by_path[rel_path] == pinned_circuits[rel_path]


def test_verify_detects_tampered_descriptor_digest_and_source_drift(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_repo = _stage_synthetic_repo(tmp_path)
    desc_path = fake_repo / "zk" / "scoped_nullifier.statement.json"

    assert sd.main(["write", "--output", str(desc_path)], repo_root=fake_repo) == sd.EXIT_OK
    assert sd.main(["verify", "--descriptor", str(desc_path)], repo_root=fake_repo) == sd.EXIT_OK
    capsys.readouterr()

    # Tamper with descriptor_sha256 directly.
    tampered = json.loads(desc_path.read_text(encoding="utf-8"))
    tampered["descriptor_sha256"] = "0" * 64
    desc_path.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
    assert sd.main(["verify", "--descriptor", str(desc_path)], repo_root=fake_repo) == sd.EXIT_DRIFT
    err_tampered = capsys.readouterr().err
    assert "descriptor_sha256 self-check failed" in err_tampered

    # Restore valid descriptor, then mutate reviewed Noir source without regenerating descriptor.
    assert sd.main(["write", "--output", str(desc_path)], repo_root=fake_repo) == sd.EXIT_OK
    capsys.readouterr()
    main_nr = fake_repo / "zk" / "noir" / "silent_witness" / "src" / "main.nr"
    sentinel_secret = "SYNTHETIC_DO_NOT_ECHO_999111"
    main_nr.write_text(
        main_nr.read_text(encoding="utf-8") + f"\n// {sentinel_secret}\n",
        encoding="utf-8",
    )

    rc_drift = sd.main(["verify", "--descriptor", str(desc_path)], repo_root=fake_repo)
    assert rc_drift == sd.EXIT_DRIFT
    err_drift = capsys.readouterr().err
    assert "artifact_bindings drifted" in err_drift
    assert sentinel_secret not in err_drift


def test_rejects_private_visibility_leak_interleaved_params_and_version_skew(
    tmp_path: Path,
) -> None:
    fake_repo = _stage_synthetic_repo(tmp_path)
    main_nr = fake_repo / "zk" / "noir" / "silent_witness" / "src" / "main.nr"
    original_main = main_nr.read_text(encoding="utf-8")

    # 1. Making credential_secret public must fail closed against scoped_v2 frame.
    main_nr.write_text(
        original_main.replace(
            "credential_secret: Field,",
            "credential_secret: pub Field,",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(sd.DescriptorError) as exc_leak:
        sd.build_statement_descriptor(repo_root=fake_repo)
    assert exc_leak.value.code in ("interleaved_visibility", "signature_schema_mismatch")

    # 2. Making both private inputs public violates scoped_v2 public frame.
    both_pub = original_main.replace(
        "credential_secret: Field,",
        "credential_secret: pub Field,",
        1,
    ).replace(
        "nullifier_secret: Field,",
        "nullifier_secret: pub Field,",
        1,
    )
    main_nr.write_text(both_pub, encoding="utf-8")
    with pytest.raises(sd.DescriptorError) as exc_pub:
        sd.build_statement_descriptor(repo_root=fake_repo)
    assert exc_pub.value.code == "signature_schema_mismatch"

    # 3. Bumping CURRENT_CIRCUIT_VERSION without schema bump fails closed.
    main_nr.write_text(
        original_main.replace(
            "global CURRENT_CIRCUIT_VERSION: u32 = 2;",
            "global CURRENT_CIRCUIT_VERSION: u32 = 3;",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(sd.DescriptorError) as exc_ver:
        sd.build_statement_descriptor(repo_root=fake_repo)
    assert exc_ver.value.code == "circuit_version_mismatch"


def test_published_acir_bytecode_drift_fails_while_volatile_keys_stay_stable(
    tmp_path: Path,
) -> None:
    fake_repo = _stage_synthetic_repo(tmp_path)
    baseline = sd.build_statement_descriptor(repo_root=fake_repo)

    sw_acir_path = fake_repo / "frontend" / "public" / "noir" / "silent_witness.json"
    original_acir = json.loads(sw_acir_path.read_text(encoding="utf-8"))

    # Injecting a lock-declared volatile key (`warnings`) preserves exact normalized digest.
    with_volatile = dict(original_acir, warnings=["synthetic-host-warning"])
    sw_acir_path.write_text(json.dumps(with_volatile), encoding="utf-8")
    after_volatile = sd.build_statement_descriptor(repo_root=fake_repo)
    assert after_volatile["descriptor_sha256"] == baseline["descriptor_sha256"]

    # Mutating semantic bytecode fails closed with reviewed_artifact_drift.
    corrupted = dict(original_acir, bytecode="AAAA_TAMPERED_BYTECODE")
    sw_acir_path.write_text(json.dumps(corrupted), encoding="utf-8")
    with pytest.raises(sd.DescriptorError) as exc_drift:
        sd.build_statement_descriptor(repo_root=fake_repo)
    assert exc_drift.value.code == "reviewed_artifact_drift"


def test_crlf_and_lf_noir_sources_yield_identical_descriptor_digest(
    tmp_path: Path,
) -> None:
    fake_repo = _stage_synthetic_repo(tmp_path)
    lf_desc = sd.build_statement_descriptor(repo_root=fake_repo)

    for rel in sd.REVIEWED_SOURCE_PATHS:
        target = fake_repo / rel
        lf_bytes = target.read_bytes().replace(b"\r\n", b"\n")
        target.write_bytes(lf_bytes.replace(b"\n", b"\r\n"))

    crlf_desc = sd.build_statement_descriptor(repo_root=fake_repo)
    assert crlf_desc["descriptor_sha256"] == lf_desc["descriptor_sha256"]
