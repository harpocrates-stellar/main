from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    app_env: str
    cors_origins: list[str]
    max_content_length: int
    max_video_bytes: int
    max_json_bytes: int
    max_metadata_bytes: int
    expose_metadata_header: bool
    noir_worker_enabled: bool
    security_headers_enabled: bool
    metrics_enabled: bool
    metrics_token: str | None
    metrics_path: str
    retention_classes: dict[str, int]
    retention_worker_enabled: bool
    retention_interval_seconds: int


def load_config() -> AppConfig:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    cors_origins = _csv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    if "*" in cors_origins:
        if app_env == "production":
            raise RuntimeError("Wildcard CORS origins are not permitted in production")
        if os.getenv("ALLOW_WILDCARD_CORS") != "true":
            raise RuntimeError("Wildcard CORS requires ALLOW_WILDCARD_CORS=true")

    return AppConfig(
        app_env=app_env,
        cors_origins=cors_origins,
        max_content_length=_int_env("MAX_CONTENT_LENGTH", 314_572_800),
        max_video_bytes=_int_env("MAX_VIDEO_BYTES", 262_144_000),
        max_json_bytes=_int_env("MAX_JSON_BYTES", 1_048_576),
        max_metadata_bytes=_int_env("MAX_METADATA_BYTES", 16_384),
        expose_metadata_header=_bool_env("EXPOSE_METADATA_HEADER", False),
        noir_worker_enabled=_bool_env("NOIR_WORKER_ENABLED", app_env != "production"),
        security_headers_enabled=_bool_env("SECURITY_HEADERS_ENABLED", True),
        metrics_enabled=_bool_env("METRICS_ENABLED", True),
        metrics_token=_str_env("METRICS_TOKEN"),
        metrics_path=os.getenv("METRICS_PATH", "/metrics").strip(),
        retention_classes=_parse_retention_classes(os.getenv("RETENTION_CLASSES")),
        retention_worker_enabled=_bool_env("RETENTION_WORKER_ENABLED", True),
        retention_interval_seconds=_int_env("RETENTION_INTERVAL_SECONDS", 3600),
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
    if value is None or not value.strip():
        return None
    return value.strip()


def _parse_retention_classes(value: str | None) -> dict[str, int]:
    # Default retention classes if not provided
    if not value or not value.strip():
        return {"default": 30, "short": 7, "long": 365, "forever": -1}
    
    classes = {}
    for pair in value.split(","):
        pair = pair.strip()
        if not pair:
            continue
        try:
            name, days = pair.split(":")
            classes[name.strip()] = int(days.strip())
        except ValueError:
            raise RuntimeError(f"Invalid RETENTION_CLASSES format, expected 'name:days,name:days'")
    
    if "default" not in classes:
        classes["default"] = 30
        
    return classes

