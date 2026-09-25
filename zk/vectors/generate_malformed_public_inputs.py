#!/usr/bin/env python3
"""Regenerate the malformed public-input hex corpus.

``malformed_public_inputs_v1.json`` pins the hex-string decoding boundary that
the structural conformance corpus cannot express: public-input material arrives
as hex text at the backend and browser layers, and those layers must reject the
same malformed strings with ``malformed_hex`` before any framing checks run.

The Soroban registry receives bytes, so it does not consume this file. Backend
and frontend runners drive it:

    backend   backend/test_conformance_vectors.py
    frontend  frontend/src/verifierInputs.conformance.test.ts

    python zk/vectors/generate_malformed_public_inputs.py

Case ids are stable: ``mh-neg-<nnn>-<slug>``. Adding cases is a minor change;
renaming an id or changing a reject code requires bumping ``version`` and a
migration note in docs/zk-conformance-vectors.md.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent / "malformed_public_inputs_v1.json"

CODEC_ID = "hpx-vi/1"
VECTOR_VERSION = 1
FIELD = "public_inputs"


def case(
    case_id: str,
    description: str,
    value: str,
    reject_code: str = "malformed_hex",
) -> dict[str, object]:
    return {
        "id": case_id,
        "field": FIELD,
        "description": description,
        "value": value,
        "expect": {"reject_code": reject_code},
    }


def build_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []

    # ---- parity / nibble boundaries -------------------------------------
    cases.append(
        case(
            "mh-neg-001-single-nibble",
            "A single hex nibble is not a byte; odd length must fail before decode.",
            "0",
        )
    )
    cases.append(
        case(
            "mh-neg-002-odd-length-prefix",
            "Odd-length hex that would otherwise look like a truncated field.",
            "abc",
        )
    )
    cases.append(
        case(
            "mh-neg-003-odd-length-near-frame",
            "319 hex chars (159.5 bytes): one nibble short of a silent-witness frame.",
            "00" * 159 + "0",
        )
    )

    # ---- non-hex alphabet -----------------------------------------------
    cases.append(
        case(
            "mh-neg-010-letter-out-of-range",
            "Latin letters outside a-f must not be accepted as hex digits.",
            "zz" * 64,
        )
    )
    cases.append(
        case(
            "mh-neg-011-high-nibble-g",
            "Embedded non-hex digit mid-string (g) must fail the alphabet check.",
            "00" * 31 + "0g" + "00" * 128,
        )
    )
    cases.append(
        case(
            "mh-neg-012-punctuation",
            "Punctuation separators are not part of the wire alphabet.",
            "00:11",
        )
    )

    # ---- whitespace and control -----------------------------------------
    cases.append(
        case(
            "mh-neg-020-internal-space",
            "Whitespace inside the hex payload must not be silently stripped.",
            "00 11",
        )
    )
    cases.append(
        case(
            "mh-neg-021-newline",
            "Newlines (common copy-paste artifact) must not be accepted.",
            "00\n11",
        )
    )
    cases.append(
        case(
            "mh-neg-022-tab",
            "Tab-separated nibbles must be rejected as malformed hex.",
            "00\t11",
        )
    )
    cases.append(
        case(
            "mh-neg-023-leading-whitespace",
            "Leading whitespace must not be trimmed at the codec boundary.",
            " 00",
        )
    )
    cases.append(
        case(
            "mh-neg-024-trailing-whitespace",
            "Trailing whitespace must not be trimmed at the codec boundary.",
            "00 ",
        )
    )

    # ---- prefixes and decorations ---------------------------------------
    cases.append(
        case(
            "mh-neg-030-0x-prefix",
            "A 0x prefix is a presentation form, not part of the wire alphabet.",
            "0x00",
        )
    )
    cases.append(
        case(
            "mh-neg-031-0x-prefixed-frame-prefix",
            "0x followed by otherwise-legal digits must still fail as malformed hex.",
            "0x" + ("ab" * 8),
        )
    )
    cases.append(
        case(
            "mh-neg-032-hash-prefix",
            "A leading # (CSS/color habit) is not a valid hex wire encoding.",
            "#0011",
        )
    )

    # ---- empty / null-ish presentations ---------------------------------
    # Empty string decodes to empty bytes and is a *length* failure once it
    # reaches framing; keep it out of this corpus. These cases are presentations
    # that look empty-ish but are not valid hex.
    cases.append(
        case(
            "mh-neg-040-null-token",
            "The literal token 'null' must not parse as hex public inputs.",
            "null",
        )
    )
    cases.append(
        case(
            "mh-neg-041-undefined-token",
            "The literal token 'undefined' must not parse as hex public inputs.",
            "undefined",
        )
    )

    # ---- unicode / lookalikes -------------------------------------------
    cases.append(
        case(
            "mh-neg-050-unicode-fullwidth-digit",
            "Fullwidth digit lookalikes must not pass the ASCII hex alphabet check.",
            "００",  # U+FF10 U+FF10
        )
    )
    cases.append(
        case(
            "mh-neg-051-non-ascii-letter",
            "Non-ASCII letters adjacent to hex digits must fail cleanly.",
            "00ffωω",
        )
    )

    return cases


def build_document() -> dict[str, object]:
    return {
        "format": "harpocrates.malformed-public-inputs",
        "version": VECTOR_VERSION,
        "codec": CODEC_ID,
        "description": (
            "Shared malformed public-input hex vectors for the Harpocrates "
            "verifier boundary. Backend and browser layers must reject each "
            "case with malformed_hex before framing checks. Values are "
            "synthetic wire presentations only — never real media, witnesses, "
            "or keys."
        ),
        "regenerate_with": "python zk/vectors/generate_malformed_public_inputs.py",
        "reject_codes": ["malformed_hex"],
        "field": FIELD,
        "cases": build_cases(),
    }


def main() -> None:
    document = build_document()
    seen: set[str] = set()
    for entry in document["cases"]:  # type: ignore[index]
        case_id = entry["id"]  # type: ignore[index]
        if case_id in seen:
            raise SystemExit(f"duplicate case id: {case_id}")
        seen.add(case_id)

    OUT_PATH.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(document['cases'])} cases to {OUT_PATH}")  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
