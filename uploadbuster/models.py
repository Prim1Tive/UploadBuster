"""Structured objects shared between modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Payload:
    filename: str
    extension: str
    content_type: str
    data: bytes
    upload_field_name: str

    @property
    def full_filename(self) -> str:
        return f"{self.filename}{self.extension}"

    def as_requests_file(self) -> tuple[str, bytes, str]:
        return (self.full_filename, self.data, self.content_type)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["full_filename"] = self.full_filename
        result["data_size"] = len(self.data)
        result.pop("data", None)
        return result


@dataclass(frozen=True)
class RequestData:
    url: str
    form_data: dict[str, str]
    headers: dict[str, str]
    cookies: dict[str, str]
    timeout: float
    allow_redirects: bool
    delay: float
    proxy: str | None = None


@dataclass(frozen=True)
class ResponseResult:
    request_id: int
    payload: Payload
    status_code: int | None
    text: str
    error: str | None = None


@dataclass(frozen=True)
class PayloadResult:
    request_id: int
    payload: Payload
    success: bool
    response_snippet: str
    extracted_url: str | None
    status_code: int | None
    accessible: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["payload"] = self.payload.to_dict()
        return result
