from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    app_env: str
    cors_origins: list[str]
    max_content_length: int
    max_metadata_bytes: int
    expose_metadata_header: bool
    noir_worker_enabled: bool
    security_headers_enabled: bool
    # Rate limiting
    ratelimit_enabled: bool
    ratelimit_embed: str
    ratelimit_extract: str
    ratelimit_silent_witness: str
    ratelimit_register: str
    # Proxy trust: comma-separated CIDR prefixes or "none"
    trusted_proxies: list[str]


def load_config() -> AppConfig:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    cors_origins = _csv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    if "*" in cors_origins and os.getenv("ALLOW_WILDCARD_CORS") != "true":
        raise RuntimeError("Wildcard CORS requires ALLOW_WILDCARD_CORS=true")

    return AppConfig(
        app_env=app_env,
        cors_origins=cors_origins,
        max_content_length=_int_env("MAX_CONTENT_LENGTH", 262_144_000),
        max_metadata_bytes=_int_env("MAX_METADATA_BYTES", 16_384),
        expose_metadata_header=_bool_env("EXPOSE_METADATA_HEADER", False),
        noir_worker_enabled=_bool_env("NOIR_WORKER_ENABLED", app_env != "production"),
        security_headers_enabled=_bool_env("SECURITY_HEADERS_ENABLED", True),
        # Rate limiting — defaults are conservative but not test-hostile
        ratelimit_enabled=_bool_env("RATELIMIT_ENABLED", True),
        ratelimit_embed=os.getenv("RATELIMIT_EMBED", "10 per minute"),
        ratelimit_extract=os.getenv("RATELIMIT_EXTRACT", "20 per minute"),
        ratelimit_silent_witness=os.getenv("RATELIMIT_SILENT_WITNESS", "5 per minute"),
        ratelimit_register=os.getenv("RATELIMIT_REGISTER", "30 per minute"),
        trusted_proxies=_csv("TRUSTED_PROXIES", ""),
    )


def _csv(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed <= 0:
        raise RuntimeError(f"{name} must be positive")
    return parsed


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
