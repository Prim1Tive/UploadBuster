"""CLI entrypoint and run orchestration."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Iterable

from . import __version__
from .bruteforce import (
    brute_content_type,
    brute_extension,
    brute_filename_limit,
    brute_magic_bytes,
    brute_multi_extension,
    brute_null_byte,
    brute_reverse_multi_extension,
)
from .config import load_config
from .constants import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_DELAY,
    DEFAULT_FORM_DATA,
    DEFAULT_MAX_REQUESTS,
    DEFAULT_PAYLOAD_PATH,
    DEFAULT_SUCCESS_MESSAGE,
    DEFAULT_TIMEOUT,
    DEFAULT_UPLOAD_FIELD,
)
from .models import Payload, PayloadResult, RequestData
from .payloads import PayloadFactory
from .requester import Requester
from .techniques import technique_htaccess_bypass, technique_short_php_payload
from .utils import parse_headers, parse_key_value_csv, setup_logging, write_json
from .validator import detect_success

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="UploadBuster",
        description="Detect unrestricted file upload vulnerabilities with common bypass techniques.",
        epilog="Use only on systems you own or have explicit permission to test.",
    )
    parser.add_argument("-u", "--url", required=True, help="Full URL to the upload handler")
    parser.add_argument("-b", "--backend", required=True, help="Backend language/extension family, e.g. php, jsp, asp")
    parser.add_argument("-e", "--extensions", required=True, help="Allowed extension used by the upload form, e.g. jpg")
    parser.add_argument("-p", "--payload", default=DEFAULT_PAYLOAD_PATH, help="Payload file path")
    parser.add_argument("-s", "--success-message", default=DEFAULT_SUCCESS_MESSAGE, help="Success string to find in responses")
    parser.add_argument("-d", "--data", default=DEFAULT_FORM_DATA, help="Form data as name,value;name,value")
    parser.add_argument("-uv", "--upload-variable", default=DEFAULT_UPLOAD_FIELD, help="Upload form field name")
    parser.add_argument("-c", "--headers", action="append", help="Custom header as 'Name: value'. Repeatable")
    parser.add_argument("--cookies", help="Cookies as name,value;name,value")
    parser.add_argument("-i", "--intervals", type=float, default=DEFAULT_DELAY, help="Delay between requests in seconds")
    parser.add_argument("-to", "--request-time-out", type=float, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("-re", "--request-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--proxy", help="Proxy URL for HTTP and HTTPS requests")
    parser.add_argument("--threads", type=int, default=1, help="Future support stub; currently only 1 is used")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS, help="Maximum requests before stopping")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--output-file", help="Write JSON results to this file")
    parser.add_argument("--dry-run", action="store_true", help="Print planned payloads without sending requests")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Config JSON path")
    parser.add_argument("--version", action="version", version=f"UploadBuster {__version__}")

    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("-a", "--all-tests", action="store_true", help="Run all available tests")
    modes.add_argument("-be", "--bruteforce-extension", action="store_true", help="Brute-force executable extensions")
    modes.add_argument("-bn", "--bruteforce-null-extension", action="store_true", help="Brute-force null-byte/suffix extensions")
    modes.add_argument("-bc", "--bruteforce-content-type", action="store_true", help="Brute-force Content-Type values")
    modes.add_argument("-by", "--bruteforce-magic-bytes", action="store_true", help="Brute-force magic-byte prefixes")
    modes.add_argument("-bm", "--bruteforce-multi-extension", type=int, nargs="?", const=1, help="Use allowed.ext + executable extension")
    modes.add_argument("-br", "--bruteforce-reverse-multi-extension", type=int, nargs="?", const=1, help="Use executable extension + allowed.ext")
    modes.add_argument("-bl", "--bruteforce-filename-limit", action="store_true", help="Try long filenames")

    parser.add_argument("-ts", "--tech-short-payload", action="store_true", help="Add a short PHP payload attempt")
    parser.add_argument("-te", "--tech-execution-extension", action="store_true", help="Try .htaccess extension execution bypass")
    parser.add_argument("-db", "--dont-brute", action="store_true", help="Stop after first successful result")
    parser.add_argument("-vi", "--print-i", action="store_true", help="Verbose request detail")
    parser.add_argument("-vo", "--print-o", action="store_true", help="Verbose response detail")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-vs", "--verbal-success", action="store_false", help="Suppress success console lines")
    return parser


def _selected_payloads(args: argparse.Namespace, config, factory: PayloadFactory) -> Iterable[Payload]:
    if args.tech_short_payload:
        yield from technique_short_php_payload(factory)

    if args.tech_execution_extension:
        yield from technique_htaccess_bypass(factory)

    if args.all_tests:
        logger.warning("[WARNING] all-tests can send many requests. Use --max-requests and --dry-run when scoping.")
        yield from technique_htaccess_bypass(factory)
        yield from brute_extension(config, factory, args.backend)
        yield from brute_null_byte(config, factory, args.backend)
        yield from brute_multi_extension(config, factory, args.backend, args.extensions, 1)
        yield from brute_reverse_multi_extension(config, factory, args.backend, args.extensions, 1)
        yield from brute_magic_bytes(config, factory, args.backend)
        yield from brute_content_type(config, factory, args.backend)
        yield from brute_filename_limit(factory, args.payload, args.backend)
        return

    if args.bruteforce_extension:
        yield from brute_extension(config, factory, args.backend)
    elif args.bruteforce_null_extension:
        yield from brute_null_byte(config, factory, args.backend)
    elif args.bruteforce_multi_extension:
        yield from brute_multi_extension(config, factory, args.backend, args.extensions, args.bruteforce_multi_extension)
    elif args.bruteforce_reverse_multi_extension:
        yield from brute_reverse_multi_extension(
            config,
            factory,
            args.backend,
            args.extensions,
            args.bruteforce_reverse_multi_extension,
        )
    elif args.bruteforce_magic_bytes:
        yield from brute_magic_bytes(config, factory, args.backend)
    elif args.bruteforce_content_type:
        yield from brute_content_type(config, factory, args.backend)
    elif args.bruteforce_filename_limit:
        yield from brute_filename_limit(factory, args.payload, args.backend)


def _print_result(result: PayloadResult, verbose: bool = False) -> None:
    if result.success:
        location = result.extracted_url or "no extracted URL"
        status = "accessible" if result.accessible else "uploaded"
        print(f"[SUCCESS] payload: {result.payload.full_filename} -> {status} at {location}")
    elif verbose and result.error:
        print(f"[ERROR] payload: {result.payload.full_filename} -> {result.error}")
    elif verbose:
        print(f"[MISS] payload: {result.payload.full_filename} -> status {result.status_code}")


def _print_dry_run(payload: Payload) -> None:
    print(f"[DRY-RUN] {payload.full_filename} content-type={payload.content_type} size={len(payload.data)}")


def run(args: argparse.Namespace) -> int:
    setup_logging(args.verbose)
    if args.threads != 1:
        logger.warning("[INFO] --threads is reserved for future support; running sequentially.")

    config = load_config(args.config)
    headers = parse_headers(args.headers)
    if not headers and config.user_agents:
        headers["user-agent"] = config.user_agents[0]

    request_data = RequestData(
        url=args.url,
        form_data=parse_key_value_csv(args.data),
        headers=headers,
        cookies=parse_key_value_csv(args.cookies),
        timeout=args.request_time_out,
        allow_redirects=args.request_redirects,
        delay=args.intervals,
        proxy=args.proxy,
    )
    factory = PayloadFactory.from_file(args.upload_variable, args.payload)
    requester = Requester(request_data)
    results: list[PayloadResult] = []

    for index, payload in enumerate(_selected_payloads(args, config, factory), start=1):
        if index > args.max_requests:
            logger.warning("[WARNING] max request cap reached: %s", args.max_requests)
            break
        if args.dry_run:
            _print_dry_run(payload)
            continue

        response = requester.send_upload(payload)
        result = detect_success(response, args.success_message, args.url, requester)
        results.append(result)

        if args.print_i:
            logger.info("[REQUEST] #%s %s", result.request_id, payload.to_dict())
        if args.print_o:
            logger.info("[RESPONSE] #%s status=%s snippet=%s", result.request_id, result.status_code, result.response_snippet)
        if args.output == "text" and args.verbal_success:
            _print_result(result, verbose=args.verbose)
        if args.dont_brute and result.success:
            break

    if args.output == "json":
        print(json.dumps([result.to_dict() for result in results], indent=2))
    if args.output_file:
        write_json(args.output_file, [result.to_dict() for result in results])

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        return run(parser.parse_args(argv))
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
        return 2
