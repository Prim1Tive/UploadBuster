"""Configuration loading and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constants import DEFAULT_CONFIG_PATH


@dataclass(frozen=True)
class UploadBusterConfig:
    user_agents: list[str]
    extensions: dict[str, list[str]]
    null_extensions: list[str]
    magic_bytes: dict[str, list[str]]
    content_types: list[str]
    messages: dict[str, str]


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> UploadBusterConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw: dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))
    config = raw.get("config", {})
    extensions = raw.get("exts", {})

    required = ["user-agents"]
    missing = [key for key in required if key not in config]
    if missing:
        raise ValueError(f"Missing config keys: {', '.join(missing)}")
    if not isinstance(extensions, dict) or not extensions:
        raise ValueError("Config must include non-empty 'exts' mapping")

    return UploadBusterConfig(
        user_agents=list(config["user-agents"]),
        extensions={key: list(value) for key, value in extensions.items() if key != "null"},
        null_extensions=list(extensions.get("null", [])),
        magic_bytes={key: list(value) for key, value in raw.get("magic_bytes", {}).items()},
        content_types=list(raw.get("content_types", [])),
        messages=dict(config.get("+", {})),
    )
