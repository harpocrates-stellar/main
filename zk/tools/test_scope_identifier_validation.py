from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import build_circuits as bc
import validate_prover_inputs as vpi

SCHEMA_PATH = REPO_ROOT / "zk" / "noir" / "circuit_input_schema_v1.json"
BN254_MODULUS = vpi.BN254_FIELD_MODULUS


def test_canonical_numeric_scope_field_boundaries() -> None:
    assert vpi.validate_canonical_scope_field("0") == 0
    assert vpi.validate_canonical_scope_field("7") == 7
    assert vpi.validate_canonical_scope_field(0) == 0
    assert vpi.validate_canonical_scope_field(1111) == 1111
    assert (
        vpi.validate_canonical_scope_field(str(BN254_MODULUS - 1))
        == BN254_MODULUS - 1
    )

    with pytest.raises(vpi.ProverInputValidationError) as exc_mod:
        vpi.validate_canonical_scope_field(str(BN254_MODULUS))
    assert exc_mod.value.code == "field_element_out_of_range"
    assert exc_mod.value.field == "verifier_scope"

    with pytest.raises(vpi.ProverInputValidationError) as exc_wrap:
        vpi.validate_canonical_scope_field(str(BN254_MODULUS + 7))
    assert exc_wrap.value.code == "field_element_out_of_range"


@pytest.mark.parametrize(
    "noncanonical_field",
    [
        "",
        "00",
        "07",
        " 0",
        "7 ",
        "7\n",
        "\t7\n",
        "+7",
        "-1",
        "-0",
        "0x0",
        "0x7",
        "0x07",
        "0X07",
        "0x" + "0" * 64,
        "global",
        "v:verifier-alpha:p:default",
        True,
        False,
    ],
)
def test_rejects_noncanonical_scope_field_encodings(
    noncanonical_field: object,
) -> None:
    with pytest.raises(vpi.ProverInputValidationError) as exc_info:
        vpi.validate_canonical_scope_field(noncanonical_field)
    assert exc_info.value.code == "noncanonical_scope_identifier"
    assert exc_info.value.field == "verifier_scope"


@pytest.mark.parametrize(
    "canonical_id",
    [
        "v:verifier-alpha:p:default",
        "v:gcq234567890abcdefghijklmnopqrstuvwxyz12:p:attestation",
        "v:org_1:p:audit_2026",
        "v:" + "a" * 52 + ":p:default",  # exact 64-byte upper bound
    ],
)
def test_canonical_scope_identifier_derivation_matches_seed_vault_spec(
    canonical_id: str,
) -> None:
    assert len(canonical_id) <= 64
    validated = vpi.validate_canonical_scope_identifier(canonical_id)
    assert validated == canonical_id

    expected_digest = hashlib.sha256(
        f"harpocrates:scope:{canonical_id}".encode("ascii")
    ).digest()
    expected_int = int.from_bytes(expected_digest, "big") % BN254_MODULUS
    if expected_int == 0:
        expected_int = 1
    assert vpi.derive_scope_field_from_identifier(canonical_id) == expected_int
    assert vpi.resolve_prover_scope(canonical_id) == str(expected_int)


@pytest.mark.parametrize(
    "ambiguous_identifier",
    [
        # Case variants that look equivalent to lowercase identifiers
        "v:Verifier-Alpha:p:default",
        "v:verifier-alpha:p:Default",
        "V:verifier-alpha:p:default",
        "v:verifier-alpha:P:default",
        "v:GCQ234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12:p:default",
        # Omitted or empty purpose segments
        "v:verifier-alpha",
        "v:verifier-alpha:",
        "v:verifier-alpha:p:",
        "v::p:default",
        # Leading, trailing, or internal whitespace
        " v:verifier-alpha:p:default",
        "v:verifier-alpha:p:default ",
        "v:verifier-alpha :p:default",
        "v:verifier-alpha:p:default\n",
        # Extra colons or malformed separators
        "v:verifier-alpha::p:default",
        "v:verifier--alpha:p:default",
        "v:verifier__alpha:p:default",
        "v:-verifier:p:default",
        "v:verifier_:p:default",
        "v:verifier:sub:p:default",
        "v:verifier:p:default:extra",
        # Unscoped lookalike aliases (global context must be field "0")
        "0",
        "global",
        "unscoped",
        "default",
        "none",
        "null",
        "v:global:p:default",
        "v:unscoped:p:default",
        "v:0:p:default",
        "v:none:p:default",
        "v:null:p:default",
        # Unicode homoglyphs and zero-width / non-ASCII characters
        "v:v\u0435rifier:p:default",  # Cyrillic small ie
        "\uff56:alpha:p:default",  # fullwidth v
        "v:alpha\u200b:p:default",  # zero-width space
        "v:cafe\u0301:p:default",  # combining acute accent
        # Overlong (>64 ASCII bytes)
        "v:" + "a" * 53 + ":p:default",
    ],
)
def test_rejects_equivalent_looking_or_ambiguous_textual_scope_identifiers(
    ambiguous_identifier: str,
) -> None:
    with pytest.raises(vpi.ProverInputValidationError) as exc_info:
        vpi.validate_canonical_scope_identifier(ambiguous_identifier)
    assert exc_info.value.code == "noncanonical_scope_identifier"
    assert ambiguous_identifier not in str(exc_info.value)


def test_prover_inputs_cross_checks_scope_id_and_rejects_mismatch() -> None:
    scope_id = "v:verifier-alpha:p:default"
    derived = str(vpi.derive_scope_field_from_identifier(scope_id))
    schema = vpi.load_schema(SCHEMA_PATH)

    valid_data = {
        "credential_secret": "12345",
        "nullifier_secret": "67890",
        "video_hash_hi": "1",
        "video_hash_lo": "2",
        "verifier_scope": derived,
        "verifier_scope_id": scope_id,
        "epoch": "0",
    }
    vpi.validate_prover_inputs(valid_data, schema=schema)

    mismatched_data = dict(valid_data, verifier_scope="0")
    with pytest.raises(vpi.ProverInputValidationError) as exc_mismatch:
        vpi.validate_prover_inputs(mismatched_data, schema=schema)
    assert exc_mismatch.value.code == "scope_binding_mismatch"
    assert exc_mismatch.value.field == "verifier_scope"


def test_prover_inputs_error_never_echoes_scope_or_secret_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bad_scope = "v:SecretOrgUpper:p:default"
    secret_val = "9876543210987654321"
    toml_path = tmp_path / "Prover.toml"
    toml_path.write_text(
        f'credential_secret = "{secret_val}"\n'
        'nullifier_secret = "67890"\n'
        'video_hash_hi = "1"\n'
        'video_hash_lo = "2"\n'
        f'verifier_scope = "{bad_scope}"\n'
        'epoch = "0"\n',
        encoding="utf-8",
    )

    rc = vpi.main([str(toml_path), "--schema", str(SCHEMA_PATH)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "noncanonical_scope_identifier" in captured.err
    assert bad_scope not in captured.err
    assert bad_scope not in captured.out
    assert secret_val not in captured.err
    assert secret_val not in captured.out


def test_build_circuits_compile_prove_rejects_noncanonical_scope_before_witness(
    tmp_path: Path,
) -> None:
    commands_run: list[list[str]] = []

    def fake_runner(
        cmd: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands_run.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    circuit_dir = tmp_path / "zk" / "noir" / "silent_witness"
    circuit_dir.mkdir(parents=True, exist_ok=True)
    (circuit_dir / "Prover.toml").write_text(
        'credential_secret = "12345"\n'
        'nullifier_secret = "67890"\n'
        'video_hash_hi = "1"\n'
        'video_hash_lo = "2"\n'
        'verifier_scope = "07"\n'
        'epoch = "0"\n',
        encoding="utf-8",
    )

    toolchain = bc.ToolchainInfo(
        expected_nargo="1.0.0-beta.9",
        expected_bb="0.87.0",
        actual_nargo="1.0.0-beta.9",
        actual_bb="0.87.0",
        proving_scheme="ultra_honk",
        oracle_hash="keccak",
    )

    with pytest.raises(bc.BuildError) as exc_info:
        bc.compile_circuit(
            "silent_witness",
            toolchain,
            repo_root=tmp_path,
            runner=fake_runner,
            prove=True,
        )
    assert exc_info.value.exit_code == bc.EXIT_USAGE
    assert "noncanonical_scope_identifier" in str(exc_info.value)
    assert commands_run == []


@pytest.mark.parametrize(
    "cli_args",
    [
        [
            "generate",
            "silent_witness",
            "--video-hash",
            "11" * 32,
            "--credential-secret",
            "12345",
            "--nullifier-secret",
            "67890",
            "--verifier-scope",
            "v:UpperVerifier:p:default",
        ],
        [
            "generate",
            "silent_witness",
            "--video-hash",
            "11" * 32,
            "--credential-secret",
            "12345",
            "--nullifier-secret",
            "67890",
            "--verifier-scope",
            "0x07",
        ],
        [
            "generate",
            "silent_witness",
            "--video-hash",
            "11" * 32,
            "--credential-secret",
            "12345",
            "--nullifier-secret",
            "67890",
            "--verifier-scope",
            "0",
            "--scope-id",
            "v:verifier-alpha:p:default",
        ],
    ],
)
def test_cmd_generate_rejects_noncanonical_or_mismatched_scope_before_subprocess(
    cli_args: list[str],
    tmp_path: Path,
) -> None:
    commands_run: list[list[str]] = []

    def fake_runner(
        cmd: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands_run.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    args = bc.create_parser().parse_args(cli_args)
    with pytest.raises(bc.BuildError) as exc_info:
        bc.cmd_generate(args, repo_root=tmp_path, runner=fake_runner)
    assert exc_info.value.exit_code == bc.EXIT_USAGE
    assert commands_run == []


def test_generate_silent_witness_forwards_canonical_derived_scope_to_prover_toml(
    tmp_path: Path,
) -> None:
    helper_dir = tmp_path / "zk" / "noir" / "silent_witness_helper"
    circuit_dir = tmp_path / "zk" / "noir" / "silent_witness"
    (helper_dir / "src").mkdir(parents=True)
    (circuit_dir / "src").mkdir(parents=True)
    (circuit_dir / "target").mkdir(parents=True)

    (helper_dir / "src" / "main.nr").write_text(
        "fn main(credential_secret: Field, nullifier_secret: Field, video_hash_hi: Field, video_hash_lo: Field, verifier_scope: Field, epoch: Field) -> pub (Field, Field, Field) { (0, 0, 0) }\n",
        encoding="utf-8",
    )
    (circuit_dir / "src" / "main.nr").write_text(
        "fn main(credential_secret: Field, nullifier_secret: Field, video_hash_hi: pub Field, video_hash_lo: pub Field, credential_root: pub Field, nullifier: pub Field, verifier_scope: pub Field, epoch: pub Field, domain_tag: pub Field, circuit_version: pub Field) {}\n",
        encoding="utf-8",
    )
    (circuit_dir / "target" / "proof").write_bytes(b"\xaa" * 64)
    (circuit_dir / "target" / "public_inputs").write_bytes(b"\xbb" * 256)

    captured_circuit_toml: list[str] = []

    def fake_runner(
        cmd: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if cmd[:3] == ["nargo", "execute", "generated_helper"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout="Circuit output: (Field(101), Field(202), Field(303))\n",
                stderr="",
            )
        if cmd[:3] == ["nargo", "execute", "witness"]:
            captured_circuit_toml.append(
                (circuit_dir / "Prover.toml").read_text(encoding="utf-8")
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    toolchain = bc.ToolchainInfo(
        expected_nargo="1.0.0-beta.9",
        expected_bb="0.87.0",
        actual_nargo="1.0.0-beta.9",
        actual_bb="0.87.0",
        proving_scheme="ultra_honk",
        oracle_hash="keccak",
    )

    scope_id = "v:verifier-alpha:p:audit"
    expected_scope_dec = str(vpi.derive_scope_field_from_identifier(scope_id))
    out_dir = tmp_path / "out"

    rc = bc._generate_silent_witness(
        video_hash="11" * 32,
        credential_secret="12345",
        nullifier_secret="67890",
        output_dir=str(out_dir),
        toolchain=toolchain,
        repo_root=tmp_path,
        runner=fake_runner,
        verifier_scope=scope_id,
        epoch=3,
    )
    assert rc == bc.EXIT_OK
    assert len(captured_circuit_toml) == 1
    parsed = vpi.parse_prover_toml(captured_circuit_toml[0])
    assert parsed["verifier_scope"] == expected_scope_dec
    assert parsed["epoch"] == "3"
    assert parsed["circuit_version"] == "2"
