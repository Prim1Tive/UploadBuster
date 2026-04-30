"""Small utility helpers."""

from __future__ import annotations

import json
import logging
import random
import string
from pathlib import Path
from typing import Iterable


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")


def random_filename(min_length: int = 4, max_length: int = 7) -> str:
    length = random.randint(min_length, max_length)
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def mutate_case(value: str) -> str:
    return "".join(random.choice((str.upper, str.lower))(char) for char in value)


def parse_key_value_csv(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    items: dict[str, str] = {}
    for pair in value.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "," not in pair:
            raise ValueError(f"Expected name,value pair, got: {pair}")
        name, item_value = pair.split(",", 1)
        items[name.strip()] = item_value.strip()
    return items


def parse_headers(values: Iterable[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if not values:
        return headers
    for value in values:
        if ":" not in value:
            raise ValueError(f"Expected header as 'Name: value', got: {value}")
        name, header_value = value.split(":", 1)
        headers[name.strip()] = header_value.strip()
    return headers


def write_json(path: str | Path, data: object) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def snippet(text: str, max_length: int = 240) -> str:
    clean = " ".join(text.split())
    if len(clean) <= max_length:
        return clean
    return f"{clean[:max_length - 3]}..."
