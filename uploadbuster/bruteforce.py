"""Brute-force payload generation techniques."""

from __future__ import annotations

from collections.abc import Iterable

from .config import UploadBusterConfig
from .models import Payload
from .payloads import PayloadFactory


def brute_extension(config: UploadBusterConfig, factory: PayloadFactory, backend: str) -> Iterable[Payload]:
    for extension in config.extensions.get(backend, []):
        yield factory.create(extension)


def brute_null_byte(config: UploadBusterConfig, factory: PayloadFactory, backend: str) -> Iterable[Payload]:
    executable = backend if backend.startswith(".") else f".{backend}"
    for suffix in config.null_extensions:
        yield factory.create(f"{executable}{suffix}")


def brute_multi_extension(
    config: UploadBusterConfig,
    factory: PayloadFactory,
    backend: str,
    allowed_extension: str,
    count: int,
) -> Iterable[Payload]:
    selected_count = count if count > 0 else 1
    for executable_extension in config.extensions.get(backend, []):
        yield factory.multi_extension(executable_extension, allowed_extension, selected_count)


def brute_reverse_multi_extension(
    config: UploadBusterConfig,
    factory: PayloadFactory,
    backend: str,
    allowed_extension: str,
    count: int,
) -> Iterable[Payload]:
    selected_count = count if count > 0 else 1
    for executable_extension in config.extensions.get(backend, []):
        yield factory.multi_extension(executable_extension, allowed_extension, selected_count, reverse=True)


def brute_content_type(config: UploadBusterConfig, factory: PayloadFactory, backend: str) -> Iterable[Payload]:
    executable = backend if backend.startswith(".") else f".{backend}"
    for content_type in config.content_types:
        yield factory.create(executable, content_type=content_type)


def brute_magic_bytes(config: UploadBusterConfig, factory: PayloadFactory, backend: str) -> Iterable[Payload]:
    executable = backend if backend.startswith(".") else f".{backend}"
    for values in config.magic_bytes.values():
        for magic_hex in values:
            yield factory.with_magic_bytes(executable, magic_hex)


def brute_filename_limit(factory: PayloadFactory, payload_name: str, backend: str, limit: int = 999) -> Iterable[Payload]:
    executable = backend if backend.startswith(".") else f".{backend}"
    for index in range(limit):
        yield factory.create(executable, filename=f"{payload_name}{'A' * index}", content_type="application/x-php")
