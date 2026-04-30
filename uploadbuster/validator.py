"""Response success detection and uploaded-file validation."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

from .models import PayloadResult, ResponseResult
from .requester import Requester
from .utils import snippet


class _HrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)


def extract_first_href(html: str) -> str | None:
    parser = _HrefParser()
    parser.feed(html)
    return parser.links[0] if parser.links else None


def detect_success(response: ResponseResult, success_string: str, base_url: str, requester: Requester) -> PayloadResult:
    if response.error:
        return PayloadResult(
            request_id=response.request_id,
            payload=response.payload,
            success=False,
            response_snippet="",
            extracted_url=None,
            status_code=response.status_code,
            error=response.error,
        )

    matched_line = ""
    success_needle = success_string.lower()
    for line in response.text.splitlines() or [response.text]:
        if success_needle in line.lower():
            matched_line = line.strip()
            break

    if not matched_line:
        return PayloadResult(
            request_id=response.request_id,
            payload=response.payload,
            success=False,
            response_snippet=snippet(response.text),
            extracted_url=None,
            status_code=response.status_code,
        )

    href = extract_first_href(matched_line) or extract_first_href(response.text)
    extracted_url = urljoin(base_url, href) if href else None
    accessible = False
    validation_error = None
    validation_status = response.status_code

    if extracted_url:
        validation_status, _, validation_error = requester.get(extracted_url)
        accessible = validation_status == 200

    return PayloadResult(
        request_id=response.request_id,
        payload=response.payload,
        success=True,
        response_snippet=snippet(matched_line),
        extracted_url=extracted_url,
        status_code=validation_status,
        accessible=accessible,
        error=validation_error,
    )
