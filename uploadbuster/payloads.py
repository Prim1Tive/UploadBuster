"""Payload construction helpers."""

from __future__ import annotations

from pathlib import Path

from .constants import DEFAULT_CONTENT_TYPE, PHP_HELLO_PAYLOAD, PHP_SHORT_PAYLOAD
from .models import Payload
from .utils import mutate_case, random_filename


class PayloadFactory:
    def __init__(
        self,
        upload_field_name: str,
        base_data: bytes | None = None,
        content_type: str = DEFAULT_CONTENT_TYPE,
    ) -> None:
        self.upload_field_name = upload_field_name
        self.base_data = base_data or PHP_HELLO_PAYLOAD
        self.content_type = content_type

    @classmethod
    def from_file(cls, upload_field_name: str, payload_path: str, content_type: str = DEFAULT_CONTENT_TYPE) -> "PayloadFactory":
        data = Path(payload_path).read_bytes()
        return cls(upload_field_name=upload_field_name, base_data=data, content_type=content_type)

    def create(
        self,
        extension: str,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        data: bytes | None = None,
        mutate_extension_case: bool = True,
    ) -> Payload:
        selected_extension = mutate_case(extension) if mutate_extension_case else extension
        return Payload(
            filename=filename or random_filename(),
            extension=selected_extension,
            content_type=content_type if content_type is not None else self.content_type,
            data=data if data is not None else self.base_data,
            upload_field_name=self.upload_field_name,
        )

    def multi_extension(self, executable_extension: str, allowed_extension: str, count: int, *, reverse: bool = False) -> Payload:
        executable = executable_extension if executable_extension.startswith(".") else f".{executable_extension}"
        allowed = allowed_extension if allowed_extension.startswith(".") else f".{allowed_extension}"
        extension = allowed + (executable * count) if not reverse else (executable * count) + allowed
        return self.create(extension)

    def with_magic_bytes(self, extension: str, magic_hex: str) -> Payload:
        data = bytes.fromhex(magic_hex) + b"\n" + self.base_data
        return self.create(extension, data=data)

    def short_php_payload(self) -> Payload:
        return self.create(".php", content_type="application/x-php", data=PHP_SHORT_PAYLOAD)
