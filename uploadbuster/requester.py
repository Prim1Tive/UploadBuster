"""HTTP request wrapper for UploadBuster."""

from __future__ import annotations

import logging
from time import sleep

import requests

from .constants import DEFAULT_RETRIES
from .models import Payload, RequestData, ResponseResult

logger = logging.getLogger(__name__)


class Requester:
    def __init__(self, request_data: RequestData, max_retries: int = DEFAULT_RETRIES) -> None:
        self.request_data = request_data
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update(request_data.headers)
        self.session.cookies.update(request_data.cookies)
        self._request_id = 0

    @property
    def request_count(self) -> int:
        return self._request_id

    def send_upload(self, payload: Payload) -> ResponseResult:
        self._request_id += 1
        files = {payload.upload_field_name: payload.as_requests_file()}
        proxies = {"http": self.request_data.proxy, "https": self.request_data.proxy} if self.request_data.proxy else None

        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.post(
                    self.request_data.url,
                    files=files,
                    data=self.request_data.form_data,
                    timeout=self.request_data.timeout,
                    allow_redirects=self.request_data.allow_redirects,
                    proxies=proxies,
                )
                if self.request_data.delay > 0:
                    sleep(self.request_data.delay)
                return ResponseResult(
                    request_id=self._request_id,
                    payload=payload,
                    status_code=response.status_code,
                    text=response.text,
                )
            except (requests.Timeout, requests.ConnectionError) as exc:
                logger.debug("Request attempt %s failed: %s", attempt + 1, exc)
                if attempt >= self.max_retries:
                    return ResponseResult(
                        request_id=self._request_id,
                        payload=payload,
                        status_code=None,
                        text="",
                        error=str(exc),
                    )
            except requests.RequestException as exc:
                return ResponseResult(
                    request_id=self._request_id,
                    payload=payload,
                    status_code=None,
                    text="",
                    error=str(exc),
                )

        return ResponseResult(self._request_id, payload, None, "", "Unexpected request failure")

    def get(self, url: str) -> tuple[int | None, str, str | None]:
        proxies = {"http": self.request_data.proxy, "https": self.request_data.proxy} if self.request_data.proxy else None
        try:
            response = self.session.get(
                url,
                timeout=self.request_data.timeout,
                allow_redirects=self.request_data.allow_redirects,
                proxies=proxies,
            )
            return response.status_code, response.text, None
        except requests.RequestException as exc:
            return None, "", str(exc)
