from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class AppConfig:
    app_env: str
    cors_origins: list[str]
    max_content_length: int
    max_metadata_bytes: int
    expose_metadata_header: bool
    noir_worker_enabled: bool
    security_headers_enabled: bool
    register_api_key: str | None
    register_api_key_expires: datetime | None


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
        register_api_key=_str_env("REGISTER_API_KEY"),
        register_api_key_expires=_iso8601_env("REGISTER_API_KEY_EXPIRES"),
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


def _str_env(name: str) -> str | None:
    value = os.getenv(name)
    return value.strip() if value and value.strip() else None


def _iso8601_env(name: str) -> datetime | None:
    value = os.getenv(name)
    if not value or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        raise RuntimeError(f"{name} must be a valid ISO 8601 datetime (e.g. 2026-12-31T23:59:59Z)")
    # Ensure the datetime is timezone-aware; assume UTC if no tzinfo provided.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
