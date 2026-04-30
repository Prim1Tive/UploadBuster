# UploadBuster

UploadBuster is a lightweight Python CLI tool for authorized penetration tests of file upload controls. It helps identify unrestricted upload weaknesses by trying common bypass techniques such as executable extensions, multi-extension filenames, content-type spoofing, magic bytes, and `.htaccess` execution mapping.

Use UploadBuster only against systems you own or have explicit permission to test.

## Features

- Modular Python package with isolated payload, request, validation, and technique logic
- Centralized HTTP handling with `requests.Session`, timeout, redirects, cookies, headers, proxy support, retries, and rate limiting
- Structured result objects with clean text output or JSON export
- Dry-run mode for scoping tests before sending traffic
- Request cap to keep runs predictable
- Extensible technique functions for future auto-detection and advanced bypasses

## Installation

```bash
git clone https://github.com/Prim1Tive/UploadBuster.git
cd UploadBuster
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

Run a dry run first to see the payloads that would be attempted:

```bash
python3 main.py \
  -u http://localhost:9001/upload1/index.php \
  -b php \
  -e jpg \
  -uv fileToUpload \
  -d submit,Upload \
  -s "The file has been uploaded here" \
  -be \
  --dry-run
```

Run the extension brute-force test:

```bash
python3 main.py \
  -u http://localhost:9001/upload1/index.php \
  -b php \
  -e jpg \
  -uv fileToUpload \
  -d submit,Upload \
  -s "The file has been uploaded here" \
  -be
```

Sample output:

```text
[SUCCESS] payload: 8k2p.Php -> accessible at http://localhost:9001/upload1/uploads/8k2p.Php
```

Export results as JSON:

```bash
python3 main.py -u http://target/upload.php -b php -e jpg -uv file -a --output json --output-file results.json
```

## Techniques

| Flag | Technique | Description |
| --- | --- | --- |
| `-be`, `--bruteforce-extension` | Extension brute force | Tries executable extensions for the selected backend, such as `.php`, `.phtml`, `.jsp`, or `.aspx`. |
| `-bn`, `--bruteforce-null-extension` | Null/suffix extension bypass | Appends encoded null bytes, path suffixes, and separator tricks to executable extensions. |
| `-bm`, `--bruteforce-multi-extension` | Multi-extension bypass | Builds names like `file.jpg.php`; accepts an optional repeat count. |
| `-br`, `--bruteforce-reverse-multi-extension` | Reverse multi-extension bypass | Builds names like `file.php.jpg`; accepts an optional repeat count. |
| `-bc`, `--bruteforce-content-type` | Content-Type spoofing | Keeps an executable extension while cycling MIME types from `data/config.json`. |
| `-by`, `--bruteforce-magic-bytes` | Magic bytes | Prefixes payload content with image/archive signatures. |
| `-bl`, `--bruteforce-filename-limit` | Filename length | Sends progressively longer filenames. |
| `-te`, `--tech-execution-extension` | `.htaccess` bypass | Attempts to upload an `.htaccess` file mapping `.wtf` to PHP, then uploads a `.wtf` payload. |
| `-ts`, `--tech-short-payload` | Short PHP payload | Adds a compact PHP execution payload attempt. |
| `-a`, `--all-tests` | All tests | Runs the bundled tests sequentially. Use with `--dry-run` first. |

## CLI Reference

Required:

```text
-u, --url                 Upload endpoint URL
-b, --backend             Backend family, e.g. php, jsp, asp
-e, --extensions          Allowed extension observed in the form, e.g. jpg
```

Common options:

```text
-p, --payload             Payload file path, default PAYLOAD.php
-s, --success-message     Case-insensitive success string
-d, --data                Form data as name,value;name,value
-uv, --upload-variable    File upload field name
-c, --headers             Header as "Name: value", repeatable
--cookies                 Cookies as name,value;name,value
-i, --intervals           Delay between requests, default 0.5 seconds
-to, --request-time-out   Request timeout, default 3 seconds
-re, --request-redirects  Follow redirects
--proxy                   Proxy URL for HTTP and HTTPS
--max-requests            Stop after this many requests, default 1000
--output text|json        Console output format
--output-file             Write JSON results to a file
--dry-run                 Print payloads without sending requests
-v, --verbose             Verbose logging
-db, --dont-brute         Stop after first successful result
```

`--threads` is accepted as a future support stub; runs are currently sequential to keep behavior predictable.

## Configuration

Technique data lives in `data/config.json`:

- user agents
- backend executable extensions
- null-byte/path suffixes
- magic bytes
- content types

Add new backends or content types there without changing code.

## Architecture

```text
uploadbuster/
├── cli.py          argument parsing and orchestration
├── config.py       config loading and validation
├── requester.py    all network traffic through Requester
├── payloads.py     PayloadFactory and payload mutation helpers
├── bruteforce.py   brute-force technique generators
├── techniques.py   advanced technique generators
├── validator.py    success matching and uploaded-file validation
├── models.py       Payload, RequestData, ResponseResult, PayloadResult
├── utils.py        small helpers
└── constants.py    defaults
```

Each technique returns payloads or structured results rather than printing directly, which keeps future features like auto-detection, threading, and richer reporting straightforward.

## Development

Run syntax checks:

```bash
python3 -m compileall uploadbuster main.py
```

Run tests:

```bash
python3 -m unittest discover
```
