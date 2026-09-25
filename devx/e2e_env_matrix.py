#!/usr/bin/env python3
"""End-to-end environment matrix for Harpocrates public boundaries.

Runs synthetic local Flask requests across canonical APP_ENV / CORS / limit
profiles. Never uses real media, credentials, witnesses, or private keys.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
DEFAULT_FIXTURE = (
    ROOT / "devx" / "fixtures" / "e2e-env-matrix" / "profiles.json"
)

SENSITIVE_PATTERNS = [
    re.compile(r"credentialsecret", re.I),
    re.compile(r"nullifiersecret", re.I),
    re.compile(r"private[_-]?key", re.I),
    re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
    re.compile(r"witness", re.I),
    re.compile(r"ci-matrix-metrics-token-not-a-secret"),
]

FORBIDDEN_RESPONSE_KEYS = {
    "credentialsecret",
    "nullifiersecret",
    "privatekey",
    "proof",
    "publicinputs",
    "witness",
    "authorization",
}


class MatrixError(RuntimeError):
    pass


def load_profiles(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("profiles"), list):
        raise MatrixError("profiles fixture must be an object with a profiles array")
    if raw.get("schema_version") != 1:
        raise MatrixError("unsupported profiles schema_version")
    return raw


def select_profiles(
    fixture: dict[str, Any], group: str | None
) -> list[dict[str, Any]]:
    profiles = fixture["profiles"]
    if group in (None, "", "all"):
        return list(profiles)
    selected = [p for p in profiles if p.get("group") == group]
    if not selected:
        raise MatrixError(f"no profiles found for group={group!r}")
    return selected


def _normalize_key(key: object) -> str:
    return "".join(c for c in str(key).lower() if c.isalnum())


def assert_privacy_safe(payload: Any, *, context: str) -> None:
    """Fail if responses appear to echo secrets, witnesses, or private keys."""
    blob = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(blob):
            raise MatrixError(f"{context}: response leaked sensitive pattern {pattern.pattern}")

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if _normalize_key(key) in FORBIDDEN_RESPONSE_KEYS:
                    # Stable error envelopes may nest under "error" only as codes/messages.
                    # Reject any echo of raw sensitive field names as keys with non-null values
                    # that look like secrets (long strings).
                    if isinstance(item, str) and len(item) >= 8 and item not in {
                        "[redacted]",
                        "VALIDATION_ERROR",
                        "PAYLOAD_TOO_LARGE",
                    }:
                        raise MatrixError(f"{context}: sensitive key echoed: {key}")
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    if not isinstance(payload, str):
        walk(payload)


@contextmanager
def temporary_env(env: dict[str, str]):
    keys = list(env)
    saved = {k: os.environ.get(k) for k in keys}
    # Clear ambient APP_ENV/CORS that could bleed across profiles.
    bleed = [
        "APP_ENV",
        "CORS_ORIGINS",
        "ALLOW_WILDCARD_CORS",
        "DATABASE_URL",
        "NOIR_WORKER_ENABLED",
        "METRICS_ENABLED",
        "METRICS_TOKEN",
        "EXPOSE_METADATA_HEADER",
        "MAX_JSON_BYTES",
        "MAX_METADATA_BYTES",
        "HARPOCRATES_RELEASE_ID",
        "HARPOCRATES_RELEASE_NETWORK",
        "SECURITY_HEADERS_ENABLED",
    ]
    bleed_saved = {k: os.environ.get(k) for k in bleed}
    try:
        for k in bleed:
            os.environ.pop(k, None)
        os.environ.update(env)
        yield
    finally:
        for k, v in bleed_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _ensure_backend_path() -> None:
    backend = str(BACKEND)
    if backend not in sys.path:
        sys.path.insert(0, backend)


def boot_client(env: dict[str, str]):
    _ensure_backend_path()
    import app as app_module  # type: ignore

    with temporary_env(env):
        flask_app = app_module.create_app()
        return flask_app.test_client(), flask_app


def _json_body(response) -> Any:
    data = response.get_data(as_text=True)
    if not data:
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return data


def run_check(client, name: str) -> dict[str, Any]:
    if name == "health_ok":
        resp = client.get("/health")
        body = _json_body(resp)
        assert_privacy_safe(body, context="health")
        if resp.status_code != 200 or not isinstance(body, dict) or body.get("ok") is not True:
            raise MatrixError(f"health_ok failed: status={resp.status_code} body={body!r}")
        if body.get("service") != "harpocrates-stego":
            raise MatrixError("health_ok: unexpected service identity")
        return {"status": resp.status_code, "ok": True}

    if name == "ready_shape":
        resp = client.get("/ready")
        body = _json_body(resp)
        assert_privacy_safe(body, context="ready")
        if resp.status_code not in {200, 503} or not isinstance(body, dict):
            raise MatrixError(f"ready_shape failed: status={resp.status_code} body={body!r}")
        for key in ("ok", "service", "database", "video_tools"):
            if key not in body:
                raise MatrixError(f"ready_shape missing key {key}")
        return {"status": resp.status_code, "ok": body.get("ok")}

    if name == "schemas_list":
        resp = client.get("/api/schemas")
        body = _json_body(resp)
        assert_privacy_safe(body, context="schemas")
        if resp.status_code not in {200, 404}:
            # 404 is acceptable if schemas route requires DB; still must be privacy-safe.
            raise MatrixError(f"schemas_list unexpected status={resp.status_code}")
        return {"status": resp.status_code}

    if name == "register_malformed":
        resp = client.post(
            "/api/proofs/register",
            data="{not-json",
            content_type="application/json",
        )
        body = _json_body(resp)
        assert_privacy_safe(body, context="register_malformed")
        if resp.status_code not in {400, 415, 422}:
            raise MatrixError(f"register_malformed expected 4xx, got {resp.status_code}")
        return {"status": resp.status_code}

    if name == "register_oversized":
        # Slightly over MAX_JSON_BYTES — size is enforced before richer validation.
        oversized = "{" + ("\"pad\":\"" + ("x" * 4096) + "\"") + "}"
        resp = client.post(
            "/api/proofs/register",
            data=oversized,
            content_type="application/json",
        )
        body = _json_body(resp)
        assert_privacy_safe(body, context="register_oversized")
        if resp.status_code not in {413, 400}:
            raise MatrixError(f"register_oversized expected 413/400, got {resp.status_code}")
        return {"status": resp.status_code}

    if name == "sensitive_payload_redacted":
        payload = {
            "fileName": "synthetic.mp4",
            "videoHash": "aa" * 32,
            "metadataHash": "bb" * 32,
            "proofId": "cc" * 32,
            "tier": "not-a-real-tier",
            "txStatus": "LOCAL_ONLY",
            "credentialSecret": "should-never-echo-credential",
            "nullifierSecret": "should-never-echo-nullifier",
            "witness": "should-never-echo-witness",
            "proof": "should-never-echo-proof-bytes",
        }
        resp = client.post("/api/proofs/register", json=payload)
        body = _json_body(resp)
        assert_privacy_safe(body, context="sensitive_payload_redacted")
        blob = json.dumps(body, default=str)
        for needle in (
            "should-never-echo-credential",
            "should-never-echo-nullifier",
            "should-never-echo-witness",
            "should-never-echo-proof-bytes",
        ):
            if needle in blob:
                raise MatrixError("sensitive_payload_redacted: secret echoed in response")
        if resp.status_code < 400:
            raise MatrixError("sensitive_payload_redacted: expected rejection of invalid tier")
        return {"status": resp.status_code}

    if name == "metrics_token_not_leaked":
        resp = client.get("/metrics")
        body = _json_body(resp) if resp.is_json else resp.get_data(as_text=True)
        assert_privacy_safe(body, context="metrics")
        text = body if isinstance(body, str) else json.dumps(body, default=str)
        if "ci-matrix-metrics-token-not-a-secret" in text:
            raise MatrixError("metrics_token_not_leaked: token appeared in body")
        return {"status": resp.status_code}

    if name == "unsupported_tier_stable":
        payload = {
            "fileName": "synthetic.mp4",
            "videoHash": "aa" * 32,
            "metadataHash": "bb" * 32,
            "proofId": "cc" * 32,
            "tier": "unsupported-tier-xyz",
            "txStatus": "LOCAL_ONLY",
        }
        resp = client.post("/api/proofs/register", json=payload)
        body = _json_body(resp)
        assert_privacy_safe(body, context="unsupported_tier_stable")
        if resp.status_code not in {400, 422}:
            raise MatrixError(f"unsupported_tier_stable expected 400/422, got {resp.status_code}")
        # Prefer stable envelope when present.
        if isinstance(body, dict) and body.get("ok") is False:
            err = body.get("error") or {}
            if not isinstance(err, dict) or "code" not in err:
                raise MatrixError("unsupported_tier_stable: missing stable error.code")
        return {"status": resp.status_code}

    if name == "register_unsupported_network_field_ignored_safely":
        payload = {
            "fileName": "synthetic.mp4",
            "videoHash": "aa" * 32,
            "metadataHash": "bb" * 32,
            "proofId": "dd" * 32,
            "tier": "silent",
            "txStatus": "LOCAL_ONLY",
            "network": "mainnet-should-not-be-trusted-from-client",
            "authorization": "Bearer fake-token-should-not-echo",
        }
        resp = client.post("/api/proofs/register", json=payload)
        body = _json_body(resp)
        assert_privacy_safe(body, context="unsupported_network_field")
        blob = json.dumps(body, default=str)
        if "fake-token-should-not-echo" in blob:
            raise MatrixError("authorization value echoed")
        return {"status": resp.status_code}

    if name == "register_revoked_style_payload_rejected":
        payload = {
            "fileName": "synthetic.mp4",
            "videoHash": "ee" * 32,
            "metadataHash": "ff" * 32,
            "proofId": "11" * 32,
            "tier": "silent",
            "txStatus": "REVOKED_NOT_A_STATUS",
        }
        resp = client.post("/api/proofs/register", json=payload)
        body = _json_body(resp)
        assert_privacy_safe(body, context="revoked_style")
        if resp.status_code < 400:
            raise MatrixError("revoked-style txStatus should be rejected")
        return {"status": resp.status_code}

    raise MatrixError(f"unknown check: {name}")


def run_profile(profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = profile["id"]
    env = {str(k): str(v) for k, v in dict(profile.get("env") or {}).items()}
    expect_boot = bool(profile.get("expect_boot", True))
    result: dict[str, Any] = {
        "id": profile_id,
        "group": profile.get("group"),
        "expect_boot": expect_boot,
        "checks": {},
        "ok": False,
    }

    if not expect_boot:
        _ensure_backend_path()
        import app as app_module  # type: ignore

        try:
            with temporary_env(env):
                app_module.create_app()
            result["error"] = "expected boot failure, but create_app succeeded"
            return result
        except Exception as exc:  # noqa: BLE001 — matrix captures boundary failures
            message = str(exc)
            needle = profile.get("expect_boot_error_substring") or ""
            if needle and needle not in message:
                result["error"] = f"boot failed differently than expected: {message}"
                return result
            result["ok"] = True
            result["boot_error"] = message
            return result

    try:
        client, _app = boot_client(env)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"boot failed: {exc}"
        result["trace"] = traceback.format_exc(limit=4)
        return result

    for check in profile.get("checks") or []:
        try:
            result["checks"][check] = run_check(client, check)
        except Exception as exc:  # noqa: BLE001
            result["checks"][check] = {"ok": False, "error": str(exc)}
            result["error"] = f"check {check} failed: {exc}"
            return result

    result["ok"] = True
    return result


def run_matrix(
    fixture_path: Path,
    group: str | None = None,
) -> dict[str, Any]:
    fixture = load_profiles(fixture_path)
    profiles = select_profiles(fixture, group)
    results = [run_profile(p) for p in profiles]
    failed = [r for r in results if not r.get("ok")]
    return {
        "ok": not failed,
        "schema_version": fixture.get("schema_version"),
        "protocol": fixture.get("protocol"),
        "compatibility": fixture.get("compatibility"),
        "group": group or "all",
        "total": len(results),
        "passed": len(results) - len(failed),
        "failed": len(failed),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=DEFAULT_FIXTURE,
        help="Path to profiles.json fixture",
    )
    parser.add_argument(
        "--group",
        default="all",
        choices=["all", "core", "adversarial"],
        help="Subset of matrix profiles to execute",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON summary",
    )
    args = parser.parse_args(argv)

    summary = run_matrix(args.fixture, None if args.group == "all" else args.group)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"e2e env matrix group={summary['group']} "
            f"passed={summary['passed']}/{summary['total']}"
        )
        for item in summary["results"]:
            mark = "PASS" if item.get("ok") else "FAIL"
            print(f"  [{mark}] {item['id']}")
            if not item.get("ok"):
                print(f"         {item.get('error')}")
        if summary.get("compatibility"):
            print("compatibility:", json.dumps(summary["compatibility"], sort_keys=True))

    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
