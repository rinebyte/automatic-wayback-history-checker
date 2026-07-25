#!/usr/bin/env python3
"""Standalone Internet Archive history and content-risk checker."""

from __future__ import annotations

import argparse
import base64
import codecs
from dataclasses import dataclass
import json
import math
import os
import random
import re
import ssl
import sys
import threading
import time
import traceback
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import Message
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from http.client import HTTPException
from typing import Any, Callable, Mapping
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
import zlib


class InputError(ValueError):
    """Raised when user-supplied CLI input is invalid."""


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise InputError("domain must be text")
    domain = value.strip().lower()
    domain = re.sub(r"^https?://", "", domain, count=1, flags=re.IGNORECASE)
    if domain.startswith("www."):
        domain = domain[4:]
    domain = re.split(r"[/#?]", domain, maxsplit=1)[0].rstrip(".")
    if not domain or "." not in domain:
        raise InputError("enter a valid domain such as example.com")
    if any(ch.isspace() for ch in domain) or ":" in domain or "@" in domain:
        raise InputError("domain must not contain whitespace, credentials, or a port")
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InputError("domain could not be converted to IDNA") from exc
    if len(ascii_domain) > 253:
        raise InputError("domain exceeds 253 characters")
    labels = ascii_domain.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
        ):
            raise InputError(f"invalid DNS label in {ascii_domain!r}")
    return ascii_domain


def validate_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InputError("timeout must be a number from 1 through 120")
    timeout = float(value)
    if not math.isfinite(timeout) or not 1 <= timeout <= 120:
        raise InputError("timeout must be a number from 1 through 120")
    return timeout


def validate_workers(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 8:
        raise InputError("workers must be an integer from 1 through 8")
    return value


def _contains_control(value: str) -> bool:
    return any(unicodedata.category(ch) in {"Cc", "Cf"} for ch in value)


def sanitize_terminal(value: object) -> str:
    chars: list[str] = []
    for ch in str(value):
        if ch.isspace():
            chars.append(" ")
        elif unicodedata.category(ch) not in {"Cc", "Cf"}:
            chars.append(ch)
    return " ".join("".join(chars).split())


def normalize_keywords(values: Iterable[str]) -> list[str]:
    raw_values = list(values)
    if len(raw_values) > 50:
        raise InputError("at most 50 custom keywords are allowed")
    result: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        if not isinstance(raw, str) or _contains_control(raw):
            raise InputError("custom keywords must be control-character-free text")
        term = " ".join(raw.split())
        if not 1 <= len(term) <= 80:
            raise InputError("custom keywords must contain 1 through 80 characters")
        key = term.casefold()
        if key not in seen:
            seen.add(key)
            result.append(term)
    return result


def normalize_proxy_url(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    raw = value.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        raw = raw[1:-1].strip()
    if "://" not in raw:
        pieces = raw.split(":")
        if len(pieces) >= 4:
            host, port, user = pieces[:3]
            password = ":".join(pieces[3:])
            raw = (
                f"http://{quote(user, safe='')}:{quote(password, safe='')}"
                f"@{host}:{port}"
            )
        elif len(pieces) == 2:
            raw = f"http://{raw}"
        else:
            raise InputError("proxy must include host and port")
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "http":
        raise InputError("only http:// proxies are supported")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputError("proxy port is invalid") from exc
    if not parsed.hostname or port is None or not 1 <= port <= 65535:
        raise InputError("proxy must include a valid host and port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise InputError("proxy URL must not contain a path, query, or fragment")
    auth = ""
    if parsed.username is not None:
        user = quote(unquote(parsed.username), safe="")
        password = quote(unquote(parsed.password or ""), safe="")
        auth = f"{user}:{password}@"
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"http://{auth}{host}:{port}"


def redact_proxy_secrets(
    message: object,
    raw_proxy: str | None,
    normalized_proxy: str | None,
) -> str:
    text = str(message)
    for secret in (raw_proxy, normalized_proxy):
        if secret:
            text = text.replace(secret, "[configured proxy]")
    text = re.sub(
        r"https?://[^/@\s]+@",
        "http://[redacted]@",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"(?<![\w.-])[^:\s]+:\d+:[^:\s]+:[^\s]+",
        "[configured proxy]",
        text,
    )
    return sanitize_terminal(text)


def _argument_has_proxy_credentials(argument: str) -> bool:
    candidate = argument
    if candidate.casefold().startswith("--proxy="):
        candidate = candidate.split("=", 1)[1]
    candidate = candidate.strip()
    if (
        len(candidate) >= 2
        and candidate[0] == candidate[-1]
        and candidate[0] in {"'", '"'}
    ):
        candidate = candidate[1:-1].strip()
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        parsed = None
    if (
        parsed is not None
        and parsed.scheme.casefold() in {"http", "https"}
        and parsed.username is not None
    ):
        return True
    pieces = candidate.split(":", 3)
    return (
        len(pieces) == 4
        and bool(pieces[0])
        and pieces[1].isdigit()
        and bool(pieces[2])
    )


def _redact_cli_error(
    message: object,
    argv: list[str],
    raw_proxy: str | None,
    normalized_proxy: str | None,
) -> str:
    text = str(message)
    for argument in argv:
        if _argument_has_proxy_credentials(argument):
            text = text.replace(argument, "[configured proxy]")
    return redact_proxy_secrets(
        text,
        raw_proxy,
        normalized_proxy,
    )


# Statuses where the server is explicitly asking us to slow down, as opposed
# to a one-off failure worth retrying immediately.
BUSY_STATUSES = {429, 503}
BUSY_COOLDOWN_SECONDS = 10.0
# Retry-After is honoured, but bounded so an absurd header cannot stall a scan.
MAX_RETRY_AFTER_SECONDS = 60.0


def retry_after_seconds(
    value: str | None,
    now: datetime | None = None,
) -> float | None:
    if not value:
        return None
    stripped = value.strip()
    if stripped.isdigit():
        return min(MAX_RETRY_AFTER_SECONDS, max(0.0, float(stripped)))
    try:
        parsed = parsedate_to_datetime(stripped)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return min(
        MAX_RETRY_AFTER_SECONDS,
        max(0.0, (parsed - current).total_seconds()),
    )


def backoff_seconds(retry_index: int, random_value: float) -> float:
    return min(8.0, 0.7 * (2**retry_index) + 0.4 * random_value)


ARCHIVE_VIEW_BASE = "https://web.archive.org/web"
ARCHIVE_REPLAY_BASE = "https://web.archive.org/web"
CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
REQUIRED_CDX_FIELDS = ("timestamp", "statuscode", "redirect", "original")
RETRYABLE_STATUSES = {403, 408, 429, 500, 502, 503, 504}
USER_AGENT = "standalone-wayback-checker/1.0"
MAX_BODY_BYTES = 600_000
ANALYZABLE_APPLICATION_TYPES = {
    "application/html",
    "application/javascript",
    "application/xhtml+xml",
    "application/xml",
    "application/x-javascript",
}
EXCLUDED_TEXT_TAGS = {"script", "style", "noscript"}
BUILTIN_KEYWORDS = {
    "gambling": [
        "judi",
        "slot",
        "togel",
        "casino",
        "kasino",
        "poker",
        "bandar",
        "sbobet",
        "maxwin",
        "gacor",
        "jackpot",
        "taruhan",
        "pragmatic",
        "rtp",
        "pkv",
        "dominoqq",
        "bandarq",
    ],
    "pharma": [
        "viagra",
        "cialis",
        "kamagra",
        "tadalafil",
        "pharmacy",
    ],
    "adult": ["porn", "xxx", "bokep", "hentai", "escort"],
    "loan_scam": ["payday", "pinjol"],
}
WAYBACK_WRAPPER_RE = re.compile(
    r"^https?://web\.archive\.org/web/\d+[a-z_]*/(.*)$",
    flags=re.IGNORECASE,
)
JS_REDIRECT_PATTERNS = (
    re.compile(
        r"(?<![\w$.])(?:window\.)?"
        r"location(?:\.href)?\s*=\s*(['\"])(.*?)\1",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"(?<![\w$.])(?:window\.)?"
        r"location\.(?:replace|assign)"
        r"\(\s*(['\"])(.*?)\1",
        flags=re.IGNORECASE,
    ),
)
PUBLIC_SCAN_RESULT_KEYS = (
    "timestamp",
    "year",
    "month",
    "original",
    "archiveUrl",
    "httpStatus",
    "contentType",
    "title",
    "analyzed",
    "truncated",
    "unsupportedEncoding",
    "redirectType",
    "redirectTarget",
    "crossHost",
    "riskMatches",
    "error",
)


class CdxError(RuntimeError):
    """Raised when the CDX lookup cannot produce a usable result."""


def _cdx_warning(row_number: int, reason: str) -> dict[str, object]:
    return {
        "code": "cdx_row_invalid",
        "message": f"CDX data row {row_number} was ignored: {reason}",
        "timestamp": None,
    }


def parse_cdx_data(
    data: Any,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if data == []:
        return [], []
    if not isinstance(data, list) or not data or not isinstance(data[0], list):
        raise CdxError("Wayback CDX returned an invalid JSON table")
    header = data[0]
    indexes: dict[str, int] = {}
    for required in REQUIRED_CDX_FIELDS:
        try:
            indexes[required] = header.index(required)
        except ValueError as exc:
            raise CdxError(f"Wayback CDX header is missing {required!r}") from exc
    snapshots: list[dict[str, object]] = []
    warnings: list[dict[str, object]] = []
    for row_number, row in enumerate(data[1:], start=1):
        if not isinstance(row, list):
            warnings.append(_cdx_warning(row_number, "row is not an array"))
            continue
        try:
            timestamp = row[indexes["timestamp"]]
            original = row[indexes["original"]]
        except IndexError:
            warnings.append(_cdx_warning(row_number, "row is missing fields"))
            continue
        if not isinstance(timestamp, str) or re.fullmatch(r"\d{14}", timestamp) is None:
            warnings.append(_cdx_warning(row_number, "invalid timestamp"))
            continue
        try:
            datetime.strptime(timestamp, "%Y%m%d%H%M%S")
        except ValueError:
            warnings.append(_cdx_warning(row_number, "invalid timestamp"))
            continue
        if not isinstance(original, str) or not sanitize_terminal(original):
            warnings.append(_cdx_warning(row_number, "original URL is empty"))
            continue
        status_value = (
            row[indexes["statuscode"]] if indexes["statuscode"] < len(row) else ""
        )
        redirect_value = (
            row[indexes["redirect"]] if indexes["redirect"] < len(row) else ""
        )
        status = sanitize_terminal(
            status_value if isinstance(status_value, str) else str(status_value or "")
        )
        redirect = sanitize_terminal(
            redirect_value
            if isinstance(redirect_value, str)
            else str(redirect_value or "")
        )
        safe_original = sanitize_terminal(original)
        snapshots.append(
            {
                "timestamp": timestamp,
                "year": timestamp[:4],
                "month": timestamp[4:6],
                "statuscode": "—" if status in {"", "-"} else status,
                "redirect": None if redirect in {"", "-"} else redirect,
                "original": safe_original,
                "archiveUrl": f"{ARCHIVE_VIEW_BASE}/{timestamp}/{safe_original}",
            }
        )
    if len(data) > 1 and not snapshots:
        raise CdxError("Wayback CDX returned rows but none were usable")
    snapshots.sort(key=lambda row: str(row["timestamp"]))
    return snapshots, warnings


def summarize_snapshots(
    snapshots: list[dict[str, object]],
    warnings: list[dict[str, object]],
) -> dict[str, object]:
    years = {str(row["year"]) for row in snapshots}
    targets = sorted(
        {
            str(row["redirect"])
            for row in snapshots
            if row["redirect"] is not None
        }
    )
    has_redirect = any(
        str(row["statuscode"]).startswith("3") or row["redirect"] is not None
        for row in snapshots
    )
    return {
        "activeYears": len(years),
        "hasRedirect": has_redirect,
        "redirectTargets": targets,
        "firstCapture": (
            f"{snapshots[0]['year']}-{snapshots[0]['month']}" if snapshots else ""
        ),
        "lastCapture": (
            f"{snapshots[-1]['year']}-{snapshots[-1]['month']}" if snapshots else ""
        ),
        "lastStatus": str(snapshots[-1]["statuscode"]) if snapshots else "",
        "captureCount": len(snapshots),
        "parseWarningCount": sum(
            warning["code"] == "cdx_row_invalid" for warning in warnings
        ),
    }


class NetworkError(RuntimeError):
    """Raised after every network attempt fails."""


CERTIFICATE_HINT = (
    " (no usable CA bundle: on macOS run 'Install Certificates.command' "
    "from your Python installation, or point SSL_CERT_FILE at a bundle)"
)


def certificate_hint(error: object) -> str:
    """Explains a TLS trust failure, which is a local setup problem."""
    seen: set[int] = set()
    while isinstance(error, BaseException) and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, ssl.SSLCertVerificationError):
            return CERTIFICATE_HINT
        error = getattr(error, "reason", None) or error.__cause__
    return ""


@dataclass(frozen=True)
class RawResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    wire_truncated: bool


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ExplicitProxyHandler(ProxyHandler):
    """Proxy handler that does not consult ambient NO_PROXY rules."""

    def proxy_open(self, req, proxy, proxy_scheme):
        original_scheme = req.type
        parsed = urlsplit(proxy)
        selected_scheme = parsed.scheme.lower() or proxy_scheme
        if not parsed.hostname:
            raise OSError("configured proxy has no hostname")
        try:
            port = parsed.port
        except ValueError as exc:
            raise OSError("configured proxy has an invalid port") from exc
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        hostport = f"{host}:{port}" if port is not None else host
        if parsed.username is not None:
            user_pass = (
                f"{unquote(parsed.username)}:"
                f"{unquote(parsed.password or '')}"
            )
            credentials = base64.b64encode(
                user_pass.encode()
            ).decode("ascii")
            req.add_header(
                "Proxy-authorization",
                f"Basic {credentials}",
            )
        req.set_proxy(hostport, selected_scheme)
        if (
            original_scheme == selected_scheme
            or original_scheme == "https"
        ):
            return None
        return self.parent.open(req, timeout=req.timeout)


def urllib_attempt(
    url: str,
    *,
    proxy: str | None,
    timeout: float,
    headers: Mapping[str, str],
    max_wire_bytes: int,
    ssl_context: ssl.SSLContext | None = None,
) -> RawResponse:
    proxy_handler = (
        ExplicitProxyHandler(
            {"http": proxy, "https": proxy}
        )
        if proxy
        else ProxyHandler({})
    )
    handlers = [proxy_handler, NoRedirect()]
    if ssl_context is not None:
        handlers.append(HTTPSHandler(context=ssl_context))
    opener = build_opener(*handlers)
    request = Request(url, method="GET", headers=dict(headers))
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    try:
        body = response.read(max_wire_bytes + 1)
        return RawResponse(
            status=int(response.getcode()),
            headers={
                key.lower(): value for key, value in response.headers.items()
            },
            body=body[:max_wire_bytes],
            wire_truncated=len(body) > max_wire_bytes,
        )
    finally:
        response.close()


class NetworkClient:
    def __init__(
        self,
        *,
        proxy: str | None = None,
        raw_proxy: str | None = None,
        attempt_fn: Callable[..., RawResponse] = urllib_attempt,
        sleep_fn: Callable[[float], None] | None = None,
        random_fn: Callable[[], float] = random.random,
        clock_fn: Callable[[], float] = time.monotonic,
        verbose_fn: Callable[[str], None] | None = None,
    ):
        self.proxy = proxy
        self.raw_proxy = raw_proxy
        self.attempt_fn = attempt_fn
        self.cancelled = threading.Event()
        self.sleep_fn = sleep_fn or self._interruptible_sleep
        self.random_fn = random_fn
        self.clock_fn = clock_fn
        self.verbose_fn = verbose_fn
        self._proxy_preferred_until = 0.0
        self._busy_until = 0.0
        self._lock = threading.Lock()

    def _interruptible_sleep(self, seconds: float) -> None:
        """Sleeps, but wakes immediately once the scan is cancelled.

        Worker threads never receive SIGINT, so without this a Ctrl-C would
        block until the longest backoff or cooldown had run its course.
        """
        self.cancelled.wait(seconds)

    def cancel(self) -> None:
        """Abandons in-flight retries; safe to call from any thread."""
        self.cancelled.set()

    def _log(self, message: str) -> None:
        if self.verbose_fn:
            self.verbose_fn(
                redact_proxy_secrets(message, self.raw_proxy, self.proxy)
            )

    def _await_busy_window(self) -> None:
        """Blocks while a shared 429/503 cooldown is still running.

        Archive.org throttles the caller, not one request, so every worker
        waits it out instead of spending its attempts on a closed door.
        """
        with self._lock:
            remaining = self._busy_until - self.clock_fn()
        if remaining > 0:
            self._log(f"archive.org cooldown: waiting {remaining:.1f}s")
            self.sleep_fn(remaining)

    def _begin_busy_cooldown(self, delay: float) -> None:
        with self._lock:
            self._busy_until = max(
                self._busy_until,
                self.clock_fn() + delay,
            )

    def get(
        self,
        url: str,
        *,
        attempts: int,
        timeout: float,
        headers: Mapping[str, str] | None = None,
        max_wire_bytes: int = 5_000_000,
    ) -> RawResponse:
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
        }
        request_headers.update(headers or {})
        last_error: BaseException | None = None
        direct_failed = False
        for attempt_index in range(attempts):
            if self.cancelled.is_set():
                raise NetworkError("Wayback fetch cancelled")
            self._await_busy_window()
            with self._lock:
                prefer_proxy = self.clock_fn() < self._proxy_preferred_until
            use_proxy = bool(
                self.proxy and (prefer_proxy or attempt_index > 0)
            )
            selected_proxy = self.proxy if use_proxy else None
            try:
                response = self.attempt_fn(
                    url,
                    proxy=selected_proxy,
                    timeout=timeout,
                    headers=request_headers,
                    max_wire_bytes=max_wire_bytes,
                )
                if (
                    response.status in RETRYABLE_STATUSES
                    and attempt_index + 1 < attempts
                ):
                    direct_failed = direct_failed or not use_proxy
                    delay = retry_after_seconds(
                        response.headers.get("retry-after")
                    )
                    if response.status in BUSY_STATUSES:
                        # Park every worker; the next loop does the waiting.
                        cooldown = (
                            delay
                            if delay is not None
                            else BUSY_COOLDOWN_SECONDS
                        )
                        self._begin_busy_cooldown(cooldown)
                        self._log(
                            f"status {response.status}: "
                            f"cooling down {cooldown:.1f}s"
                        )
                        continue
                    if delay is None:
                        delay = backoff_seconds(
                            attempt_index, self.random_fn()
                        )
                    self._log(
                        f"retrying status {response.status} in {delay:.1f}s"
                    )
                    self.sleep_fn(delay)
                    continue
                if (
                    use_proxy
                    and direct_failed
                    and response.status not in RETRYABLE_STATUSES
                ):
                    with self._lock:
                        self._proxy_preferred_until = self.clock_fn() + 60.0
                return response
            except (
                OSError,
                URLError,
                TimeoutError,
                HTTPException,
            ) as exc:
                last_error = exc
                direct_failed = direct_failed or not use_proxy
                if attempt_index + 1 >= attempts:
                    break
                delay = backoff_seconds(attempt_index, self.random_fn())
                self._log(f"network retry in {delay:.1f}s: {exc}")
                self.sleep_fn(delay)
        safe = redact_proxy_secrets(
            last_error or "request failed", self.raw_proxy, self.proxy
        )
        route = "configured proxy" if self.proxy else "direct connection"
        raise NetworkError(
            f"Wayback fetch failed via {route}: {safe}"
            f"{certificate_hint(last_error)}"
        )


def build_cdx_url(domain: str, endpoint: str = CDX_ENDPOINT) -> str:
    query = urlencode(
        {
            "url": domain,
            "output": "json",
            "fl": "timestamp,statuscode,redirect,original",
            "collapse": "timestamp:6",
            "limit": "500",
        }
    )
    return f"{endpoint}?{query}"


def fetch_cdx(
    client: NetworkClient,
    domain: str,
    *,
    endpoint: str = CDX_ENDPOINT,
    timeout: float = 25.0,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    try:
        response = client.get(
            build_cdx_url(domain, endpoint),
            attempts=3,
            timeout=timeout,
            headers={"User-Agent": f"{USER_AGENT} (+cdx)"},
        )
    except NetworkError as exc:
        raise CdxError(str(exc)) from exc
    if response.status in {429, 503, 504}:
        raise CdxError("Wayback CDX is busy; try again in a moment")
    if not 200 <= response.status < 300:
        raise CdxError(f"Wayback CDX returned HTTP {response.status}")
    try:
        data = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CdxError("Wayback CDX did not return valid JSON") from exc
    return parse_cdx_data(data)


class ContentDecodeError(RuntimeError):
    """Raised when a supported content encoding cannot be decoded."""


@dataclass(frozen=True)
class DecodedBody:
    text: str | None
    content_type: str | None
    analyzable: bool
    html_like: bool
    truncated: bool
    unsupported_encoding: str | None


def _inflate_limited(
    data: bytes,
    wbits: int,
    *,
    concatenated: bool = False,
) -> tuple[bytes, bool]:
    output = bytearray()
    pending = data
    while True:
        decoder = zlib.decompressobj(wbits)
        try:
            budget = MAX_BODY_BYTES + 1 - len(output)
            output.extend(decoder.decompress(pending, budget))
            remaining = MAX_BODY_BYTES + 1 - len(output)
            if remaining > 0:
                output.extend(decoder.flush(remaining))
        except zlib.error as exc:
            raise ContentDecodeError(
                f"compressed body could not be decoded: {exc}"
            ) from exc
        if (
            len(output) > MAX_BODY_BYTES
            or bool(decoder.unconsumed_tail)
        ):
            return bytes(output[:MAX_BODY_BYTES]), True
        if not decoder.eof:
            return bytes(output[:MAX_BODY_BYTES]), True
        if not concatenated or not decoder.unused_data:
            return bytes(output), False
        pending = decoder.unused_data


def _decode_wire_body(
    response: RawResponse,
) -> tuple[bytes | None, bool, str | None]:
    encoding = response.headers.get("content-encoding", "").strip().lower()
    wire = response.body
    if encoding in {"", "identity"}:
        return (
            wire[:MAX_BODY_BYTES],
            response.wire_truncated or len(wire) > MAX_BODY_BYTES,
            None,
        )
    if encoding in {"gzip", "x-gzip"}:
        body, truncated = _inflate_limited(
            wire,
            16 + zlib.MAX_WBITS,
            concatenated=True,
        )
        return body, response.wire_truncated or truncated, None
    if encoding == "deflate":
        try:
            body, truncated = _inflate_limited(wire, zlib.MAX_WBITS)
        except ContentDecodeError:
            body, truncated = _inflate_limited(wire, -zlib.MAX_WBITS)
        return body, response.wire_truncated or truncated, None
    return None, response.wire_truncated, encoding


def _content_metadata(header: str | None) -> tuple[str | None, str]:
    if not header:
        return None, "utf-8"
    message = Message()
    message["content-type"] = header
    content_type = message.get_content_type().lower()
    charset = message.get_content_charset() or "utf-8"
    try:
        codecs.lookup(charset)
    except LookupError:
        charset = "utf-8"
    return content_type, charset


def decode_body(response: RawResponse) -> DecodedBody:
    body, truncated, unsupported = _decode_wire_body(response)
    content_type, charset = _content_metadata(
        response.headers.get("content-type")
    )
    if body is None:
        return DecodedBody(
            None,
            content_type,
            False,
            False,
            truncated,
            unsupported,
        )
    text = body.decode(charset, errors="replace")
    sniff = text[:4096].lstrip("\ufeff \t\r\n").lower()
    html_like = any(
        marker in sniff
        for marker in ("<!doctype html", "<html", "<head", "<title")
    )
    analyzable = (
        bool(content_type and content_type.startswith("text/"))
        or content_type in ANALYZABLE_APPLICATION_TYPES
        or html_like
    )
    return DecodedBody(
        text=text if analyzable else None,
        content_type=content_type,
        analyzable=analyzable,
        html_like=html_like
        or bool(
            content_type
            and ("html" in content_type or "xml" in content_type)
        ),
        truncated=truncated,
        unsupported_encoding=unsupported,
    )


@dataclass(frozen=True)
class ParsedContent:
    title: str | None
    normalized_title: str | None
    visible_text: str
    raw_text: str
    meta_redirect: str | None


def _meta_refresh_target(content: str) -> str | None:
    match = re.search(
        r"(?:^|;)\s*url\s*=\s*(?:['\"]([^'\"]+)['\"]|([^;]+))",
        content,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    return sanitize_terminal(match.group(1) or match.group(2)).strip()


class ArchiveHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.visible_parts: list[str] = []
        self.title_depth = 0
        self.title_complete = False
        self.excluded_depth = 0
        self.meta_redirect: str | None = None

    def handle_starttag(self, tag: str, attrs):
        name = tag.lower()
        if name in EXCLUDED_TEXT_TAGS:
            self.excluded_depth += 1
        if name == "title" and not self.title_complete:
            self.title_depth += 1
        if name == "meta" and self.meta_redirect is None:
            values = {
                str(key).lower(): str(value or "")
                for key, value in attrs
                if key is not None
            }
            if values.get("http-equiv", "").casefold() == "refresh":
                self.meta_redirect = _meta_refresh_target(
                    values.get("content", "")
                )

    def handle_startendtag(self, tag: str, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str):
        name = tag.lower()
        if name == "title" and self.title_depth:
            self.title_depth -= 1
            if self.title_depth == 0:
                self.title_complete = True
        if name in EXCLUDED_TEXT_TAGS and self.excluded_depth:
            self.excluded_depth -= 1

    def handle_data(self, data: str):
        if self.title_depth and not self.title_complete:
            self.title_parts.append(data)
        if self.excluded_depth == 0:
            self.visible_parts.append(data)


def parse_content(decoded: DecodedBody) -> ParsedContent:
    raw = decoded.text or ""
    if decoded.html_like:
        parser = ArchiveHtmlParser()
        parser.feed(raw)
        parser.close()
        title = sanitize_terminal("".join(parser.title_parts)) or None
        visible = sanitize_terminal(" ".join(parser.visible_parts))
        meta_redirect = parser.meta_redirect
    else:
        title = None
        visible = sanitize_terminal(raw)
        meta_redirect = None
    return ParsedContent(
        title=title,
        normalized_title=title.casefold() if title else None,
        visible_text=visible,
        raw_text=sanitize_terminal(raw),
        meta_redirect=meta_redirect,
    )


def _fold_with_index(value: str) -> tuple[str, list[int]]:
    pieces: list[str] = []
    indexes: list[int] = []
    for index, char in enumerate(value):
        folded = char.casefold()
        pieces.append(folded)
        indexes.extend([index] * len(folded))
    return "".join(pieces), indexes


def _word_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _find_token_in_folded(
    folded: str,
    index_map: list[int],
    term: str,
) -> tuple[int, int] | None:
    needle = term.casefold()
    offset = 0
    while True:
        position = folded.find(needle, offset)
        if position < 0:
            return None
        end = position + len(needle)
        left_ok = not (
            needle
            and _word_char(needle[0])
            and position > 0
            and _word_char(folded[position - 1])
        )
        right_ok = not (
            needle
            and _word_char(needle[-1])
            and end < len(folded)
            and _word_char(folded[end])
        )
        if left_ok and right_ok:
            start_index = index_map[position]
            end_index = index_map[end - 1] + 1
            return start_index, end_index
        offset = position + 1


def find_token(value: str, term: str) -> tuple[int, int] | None:
    folded, index_map = _fold_with_index(value)
    return _find_token_in_folded(folded, index_map, term)


def make_snippet(value: str, start: int, end: int) -> str:
    left = max(0, start - 79)
    right = min(len(value), end + 79)
    snippet = value[left:right]
    if left:
        snippet = "…" + snippet[1:]
    if right < len(value):
        snippet = snippet[:-1] + "…"
    return sanitize_terminal(snippet)[:160]


def find_risk_matches(
    title: str | None,
    visible_text: str,
    custom_keywords: list[str],
) -> list[dict[str, object]]:
    groups = {**BUILTIN_KEYWORDS, "custom": custom_keywords}
    matches: list[dict[str, object]] = []
    seen_terms: set[str] = set()
    title_text = title or ""
    folded_title, title_indexes = _fold_with_index(title_text)
    folded_body, body_indexes = _fold_with_index(visible_text)
    for category, terms in groups.items():
        for term in terms:
            term_key = term.casefold()
            if term_key in seen_terms:
                continue
            title_match = _find_token_in_folded(
                folded_title,
                title_indexes,
                term,
            )
            body_match = _find_token_in_folded(
                folded_body,
                body_indexes,
                term,
            )
            selected_text = title_text if title_match else visible_text
            selected_match = title_match or body_match
            if selected_match is None:
                continue
            seen_terms.add(term_key)
            matches.append(
                {
                    "category": category,
                    "term": term,
                    "inTitle": title_match is not None,
                    "snippet": make_snippet(
                        selected_text,
                        selected_match[0],
                        selected_match[1],
                    ),
                }
            )
    matches.sort(
        key=lambda item: (
            str(item["category"]),
            str(item["term"]).casefold(),
        )
    )
    return matches


def detect_javascript_redirect(raw_text: str) -> str | None:
    candidates = []
    for pattern in JS_REDIRECT_PATTERNS:
        match = pattern.search(raw_text)
        if match:
            candidates.append((match.start(), match.group(2)))
    if not candidates:
        return None
    return sanitize_terminal(min(candidates, key=lambda item: item[0])[1])


def resolve_redirect(
    target: str | None,
    original: str,
    domain: str,
) -> tuple[str | None, bool | None]:
    if not target:
        return None, None
    cleaned = sanitize_terminal(unescape(target))
    wrapped = WAYBACK_WRAPPER_RE.match(cleaned)
    if wrapped:
        cleaned = wrapped.group(1)
    resolved = sanitize_terminal(urljoin(original, cleaned))
    hostname = urlsplit(resolved).hostname
    if hostname is None:
        return resolved, None
    try:
        normalized_host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return resolved, None
    return resolved, normalized_host != domain


@dataclass(frozen=True)
class ContentAnalysis:
    title: str | None
    normalized_title: str | None
    risk_matches: list[dict[str, object]]
    redirect_type: str | None
    redirect_target: str | None
    cross_host: bool | None


def analyze_content(
    decoded: DecodedBody,
    *,
    original: str,
    domain: str,
    custom_keywords: list[str],
) -> ContentAnalysis:
    parsed = parse_content(decoded)
    redirect_type = None
    redirect_target = None
    cross_host = None
    if parsed.meta_redirect:
        redirect_type = "meta"
        redirect_target, cross_host = resolve_redirect(
            parsed.meta_redirect,
            original,
            domain,
        )
    else:
        javascript_target = detect_javascript_redirect(parsed.raw_text)
        if javascript_target:
            redirect_type = "js"
            redirect_target, cross_host = resolve_redirect(
                javascript_target,
                original,
                domain,
            )
    return ContentAnalysis(
        title=parsed.title,
        normalized_title=parsed.normalized_title,
        risk_matches=find_risk_matches(
            parsed.title,
            parsed.visible_text,
            custom_keywords,
        ),
        redirect_type=redirect_type,
        redirect_target=redirect_target,
        cross_host=cross_host,
    )


def failed_scan_result(
    snapshot: dict[str, object],
    message: str,
    *,
    status: int | None = None,
) -> dict[str, object]:
    return {
        "timestamp": snapshot["timestamp"],
        "year": snapshot["year"],
        "month": snapshot["month"],
        "original": snapshot["original"],
        "archiveUrl": snapshot["archiveUrl"],
        "httpStatus": status,
        "contentType": None,
        "title": None,
        "_normalizedTitle": None,
        "analyzed": False,
        "truncated": False,
        "unsupportedEncoding": None,
        "redirectType": None,
        "redirectTarget": None,
        "crossHost": None,
        "riskMatches": [],
        "error": sanitize_terminal(message),
    }


def scan_snapshot(
    snapshot: dict[str, object],
    client: NetworkClient,
    *,
    domain: str,
    custom_keywords: list[str],
    timeout: float = 18.0,
    replay_base: str = ARCHIVE_REPLAY_BASE,
) -> dict[str, object]:
    replay_url = (
        f"{replay_base}/{snapshot['timestamp']}id_/"
        f"{snapshot['original']}"
    )
    try:
        response = client.get(
            replay_url,
            attempts=3,
            timeout=timeout,
            headers={"User-Agent": f"{USER_AGENT} (+archive-scan)"},
            max_wire_bytes=MAX_BODY_BYTES,
        )
    except NetworkError as exc:
        return failed_scan_result(snapshot, str(exc))
    if response.status in RETRYABLE_STATUSES:
        return failed_scan_result(
            snapshot,
            (
                "Wayback replay returned "
                f"HTTP {response.status} after retries"
            ),
            status=response.status,
        )
    base = failed_scan_result(snapshot, "", status=response.status)
    base["error"] = None
    if 300 <= response.status < 400:
        target, cross_host = resolve_redirect(
            response.headers.get("location"),
            str(snapshot["original"]),
            domain,
        )
        base.update(
            {
                "redirectType": "http",
                "redirectTarget": target,
                "crossHost": cross_host,
            }
        )
        return base
    try:
        decoded = decode_body(response)
    except ContentDecodeError as exc:
        return failed_scan_result(
            snapshot,
            str(exc),
            status=response.status,
        )
    base.update(
        {
            "contentType": decoded.content_type,
            "truncated": decoded.truncated,
            "unsupportedEncoding": decoded.unsupported_encoding,
        }
    )
    if not decoded.analyzable:
        return base
    try:
        analysis = analyze_content(
            decoded,
            original=str(snapshot["original"]),
            domain=domain,
            custom_keywords=custom_keywords,
        )
    except Exception as exc:
        return failed_scan_result(
            snapshot,
            f"content analysis failed: {exc}",
            status=response.status,
        )
    base.update(
        {
            "title": analysis.title,
            "_normalizedTitle": analysis.normalized_title,
            "analyzed": True,
            "redirectType": analysis.redirect_type,
            "redirectTarget": analysis.redirect_target,
            "crossHost": analysis.cross_host,
            "riskMatches": analysis.risk_matches,
        }
    )
    return base


def initial_sample_indices(
    count: int,
    maximum: int = 20,
) -> list[int]:
    selected = min(count, maximum)
    if selected == 0:
        return []
    if selected == 1:
        return [0]
    return [
        (index * (count - 1)) // (selected - 1)
        for index in range(selected)
    ]


def adaptive_candidates(
    results_by_index: dict[int, dict[str, object]],
    submitted: set[int],
    count: int,
) -> list[tuple[int, int]]:
    priorities: dict[int, int] = {}

    def offer(index: int, priority: int) -> None:
        if 0 <= index < count and index not in submitted:
            priorities[index] = min(
                priority,
                priorities.get(index, priority),
            )

    for index, result in results_by_index.items():
        if result["riskMatches"]:
            offer(index - 1, 0)
            offer(index + 1, 0)
        if result["redirectType"]:
            offer(index - 1, 1)
            offer(index + 1, 1)
    titled = sorted(
        (index, result)
        for index, result in results_by_index.items()
        if result["error"] is None and result["_normalizedTitle"]
    )
    for (lower_index, lower), (upper_index, upper) in zip(
        titled,
        titled[1:],
    ):
        if (
            lower["_normalizedTitle"] != upper["_normalizedTitle"]
            and upper_index - lower_index > 1
        ):
            offer((lower_index + upper_index) // 2, 2)
    return sorted(
        (
            (priority, index)
            for index, priority in priorities.items()
        ),
        key=lambda item: (item[0], item[1]),
    )


def _scan_wave(
    snapshots: list[dict[str, object]],
    indexes: list[int],
    scan_fn: Callable[[dict[str, object]], dict[str, object]],
    workers: int,
    on_interrupt: Callable[[], None] | None = None,
) -> dict[int, dict[str, object]]:
    completed: dict[int, dict[str, object]] = {}
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = {
        executor.submit(scan_fn, snapshots[index]): index
        for index in indexes
    }
    try:
        for future in as_completed(futures):
            index = futures[future]
            try:
                completed[index] = future.result()
            except Exception as exc:
                completed[index] = failed_scan_result(
                    snapshots[index],
                    f"snapshot scan failed: {exc}",
                )
    except KeyboardInterrupt:
        # Tell running workers to stop retrying before we wait on them;
        # shutdown() joins them, so a pending backoff would hold up Ctrl-C.
        if on_interrupt is not None:
            on_interrupt()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    executor.shutdown(wait=True)
    return completed


def scan_history(
    snapshots: list[dict[str, object]],
    scan_fn: Callable[[dict[str, object]], dict[str, object]],
    *,
    full: bool,
    workers: int,
    on_interrupt: Callable[[], None] | None = None,
) -> dict[str, object]:
    count = len(snapshots)
    if count == 0:
        return {
            "mode": "full" if full else "adaptive",
            "validCaptures": 0,
            "selected": 0,
            "completed": 0,
            "failed": 0,
            "coveragePercent": 0.0,
            "adaptiveCapReached": False,
            "partial": False,
            "results": [],
        }
    cap = count if full else min(count, 40)
    submitted: set[int] = set()
    results_by_index: dict[int, dict[str, object]] = {}
    next_indexes = (
        list(range(count))
        if full
        else initial_sample_indices(count)
    )
    cap_reached = False
    while next_indexes:
        remaining = cap - len(submitted)
        if remaining <= 0:
            cap_reached = not full
            break
        wave = next_indexes[:remaining]
        submitted.update(wave)
        results_by_index.update(
            _scan_wave(
                snapshots,
                wave,
                scan_fn,
                workers,
                on_interrupt,
            )
        )
        if full:
            break
        candidates = adaptive_candidates(
            results_by_index,
            submitted,
            count,
        )
        if len(next_indexes) > remaining:
            cap_reached = True
        next_indexes = [index for _, index in candidates]
        if len(submitted) == cap and next_indexes:
            cap_reached = True
            break
    results = [
        results_by_index[index]
        for index in sorted(results_by_index)
    ]
    failed = sum(result["error"] is not None for result in results)
    selected = len(results)
    return {
        "mode": "full" if full else "adaptive",
        "validCaptures": count,
        "selected": selected,
        "completed": selected - failed,
        "failed": failed,
        "coveragePercent": round((selected / count) * 100, 2),
        "adaptiveCapReached": cap_reached,
        "partial": failed > 0,
        "results": results,
    }


def derive_title_changes(
    snapshots: list[dict[str, object]],
    results: list[dict[str, object]],
) -> list[dict[str, object]]:
    index_by_timestamp = {
        str(snapshot["timestamp"]): index
        for index, snapshot in enumerate(snapshots)
    }
    titled = [
        result
        for result in results
        if (
            result["error"] is None
            and result["title"]
            and result["_normalizedTitle"]
        )
    ]
    titled.sort(key=lambda result: str(result["timestamp"]))
    changes = []
    for previous, current in zip(titled, titled[1:]):
        if (
            previous["_normalizedTitle"]
            == current["_normalizedTitle"]
        ):
            continue
        previous_index = index_by_timestamp[str(previous["timestamp"])]
        current_index = index_by_timestamp[str(current["timestamp"])]
        changes.append(
            {
                "fromTimestamp": previous["timestamp"],
                "toTimestamp": current["timestamp"],
                "fromTitle": previous["title"],
                "toTitle": current["title"],
                "adjacent": current_index - previous_index == 1,
            }
        )
    return changes


def derive_risk_findings(
    results: list[dict[str, object]],
) -> list[dict[str, object]]:
    findings = []
    for result in sorted(
        results,
        key=lambda row: str(row["timestamp"]),
    ):
        matches = list(result["riskMatches"])
        if not matches:
            continue
        findings.append(
            {
                "timestamp": result["timestamp"],
                "archiveUrl": result["archiveUrl"],
                "title": result["title"],
                "categories": sorted(
                    {
                        str(match["category"])
                        for match in matches
                    }
                ),
                "matches": matches,
            }
        )
    return findings


def derive_redirects(
    snapshots: list[dict[str, object]],
    results: list[dict[str, object]],
    domain: str,
) -> list[dict[str, object]]:
    redirects: list[dict[str, object]] = []
    for snapshot in snapshots:
        status = str(snapshot["statuscode"])
        if (
            not status.startswith("3")
            and snapshot["redirect"] is None
        ):
            continue
        target, cross_host = resolve_redirect(
            snapshot["redirect"],
            str(snapshot["original"]),
            domain,
        )
        redirects.append(
            {
                "timestamp": snapshot["timestamp"],
                "archiveUrl": snapshot["archiveUrl"],
                "source": "cdx",
                "type": "cdx",
                "statuscode": status,
                "target": target,
                "crossHost": cross_host,
            }
        )
    for result in results:
        if result["redirectType"] is None:
            continue
        redirects.append(
            {
                "timestamp": result["timestamp"],
                "archiveUrl": result["archiveUrl"],
                "source": "replay",
                "type": result["redirectType"],
                "statuscode": (
                    str(result["httpStatus"])
                    if result["httpStatus"] is not None
                    else None
                ),
                "target": result["redirectTarget"],
                "crossHost": result["crossHost"],
            }
        )
    unique = {}
    for redirect in redirects:
        key = (
            redirect["timestamp"],
            redirect["source"],
            redirect["type"],
            redirect["target"],
        )
        unique[key] = redirect
    return sorted(
        unique.values(),
        key=lambda row: (
            str(row["timestamp"]),
            str(row["source"]),
            str(row["type"]),
            str(row["target"] or ""),
        ),
    )


def _warning(
    code: str,
    message: str,
    timestamp: str | None,
) -> dict[str, object]:
    return {
        "code": code,
        "message": sanitize_terminal(message),
        "timestamp": timestamp,
    }


def derive_scan_warnings(
    scan: dict[str, object],
) -> list[dict[str, object]]:
    warnings = []
    for result in scan["results"]:
        timestamp = str(result["timestamp"])
        if result["truncated"]:
            warnings.append(
                _warning(
                    "body_truncated",
                    "Archived response was truncated",
                    timestamp,
                )
            )
        if result["unsupportedEncoding"]:
            warnings.append(
                _warning(
                    "content_encoding_unsupported",
                    (
                        "Unsupported content encoding: "
                        f"{result['unsupportedEncoding']}"
                    ),
                    timestamp,
                )
            )
        elif (
            result["error"] is None
            and not result["analyzed"]
            and result["redirectType"] is None
            and result["contentType"] is not None
        ):
            warnings.append(
                _warning(
                    "content_type_unsupported",
                    (
                        "Unsupported content type: "
                        f"{result['contentType']}"
                    ),
                    timestamp,
                )
            )
        if result["error"] is not None:
            warnings.append(
                _warning(
                    "snapshot_failed",
                    str(result["error"]),
                    timestamp,
                )
            )
    if scan["adaptiveCapReached"]:
        warnings.append(
            _warning(
                "adaptive_cap_reached",
                (
                    "Adaptive scan stopped at 40 captures "
                    "while candidates remained"
                ),
                None,
            )
        )
    return warnings


def build_success_document(
    domain: str,
    snapshots: list[dict[str, object]],
    parse_warnings: list[dict[str, object]],
    scan: dict[str, object],
) -> dict[str, object]:
    public_results = [
        {
            key: result[key]
            for key in PUBLIC_SCAN_RESULT_KEYS
        }
        for result in scan["results"]
    ]
    public_scan = {
        key: scan[key]
        for key in (
            "mode",
            "validCaptures",
            "selected",
            "completed",
            "failed",
            "coveragePercent",
            "adaptiveCapReached",
            "partial",
        )
    }
    public_scan.update(
        {
            "results": public_results,
            "titleChanges": derive_title_changes(
                snapshots,
                scan["results"],
            ),
            "riskFindings": derive_risk_findings(scan["results"]),
            "redirects": derive_redirects(
                snapshots,
                scan["results"],
                domain,
            ),
        }
    )
    return {
        "domain": domain,
        "snapshots": snapshots,
        "summary": summarize_snapshots(
            snapshots,
            parse_warnings,
        ),
        "scan": public_scan,
        "warnings": [
            *parse_warnings,
            *derive_scan_warnings(scan),
        ],
    }


def error_document(
    code: str,
    message: object,
) -> dict[str, object]:
    return {
        "error": {
            "code": code,
            "message": sanitize_terminal(message),
        }
    }


class RaisingArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = RaisingArgumentParser(
        prog="wayback_checker.py",
        description=(
            "Inspect a domain's Wayback history and archived content."
        ),
    )
    parser.add_argument("domain")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--proxy")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--keyword", action="append", default=[])
    parser.add_argument("--verbose", action="store_true")
    return parser


def render_json(document: dict[str, object]) -> str:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


def render_human(document: dict[str, object]) -> str:
    summary = document["summary"]
    scan = document["scan"]
    lines = [
        f"Wayback Checker: {document['domain']}",
        "",
        "History",
        f"  Captures: {summary['captureCount']}",
        f"  Active years: {summary['activeYears']}",
        (
            "  First / last: "
            f"{summary['firstCapture'] or '—'} / "
            f"{summary['lastCapture'] or '—'}"
        ),
        f"  Last status: {summary['lastStatus'] or '—'}",
        "",
        "Scan coverage",
        f"  Mode: {scan['mode']}",
        (
            "  Completed / selected: "
            f"{scan['completed']} / {scan['selected']}"
        ),
        f"  Coverage: {scan['coveragePercent']:.2f}%",
    ]
    if scan["partial"]:
        lines.append(
            f"  Status: PARTIAL — {scan['failed']} of "
            f"{scan['selected']} selected captures failed"
        )
    lines.extend(["", "Risk findings"])
    if scan["riskFindings"]:
        for finding in scan["riskFindings"]:
            lines.append(
                f"  {finding['timestamp']}: "
                f"{', '.join(finding['categories'])}"
            )
            lines.append(f"    {finding['archiveUrl']}")
    elif scan["partial"]:
        lines.append(
            "  None in scanned captures "
            "(scan incomplete — absence is not proof)"
        )
    else:
        lines.append("  None in scanned captures")
    lines.extend(["", "Title changes"])
    if scan["titleChanges"]:
        for change in scan["titleChanges"]:
            lines.append(
                f"  {change['fromTimestamp']}–"
                f"{change['toTimestamp']}: "
                f"{change['fromTitle']} -> {change['toTitle']}"
            )
    else:
        lines.append(
            "  No change observed in successful scanned captures"
        )
    lines.extend(["", "Redirects"])
    if scan["redirects"]:
        # A 3xx CDX row without a recorded target carries no information, and
        # long domain histories produce dozens of them. Collapse to a count;
        # the JSON document still lists every row.
        targetless_cdx = 0
        for redirect in scan["redirects"]:
            if redirect["source"] == "cdx" and not redirect["target"]:
                targetless_cdx += 1
                continue
            lines.append(
                f"  {redirect['timestamp']} "
                f"[{redirect['source']}]: "
                f"{redirect['target'] or 'target unavailable'}"
            )
        if targetless_cdx:
            noun = "capture" if targetless_cdx == 1 else "captures"
            lines.append(
                f"  {targetless_cdx} CDX {noun} reported a redirect "
                "with no recorded target"
            )
    else:
        lines.append("  None observed")
    if document["warnings"]:
        lines.extend(["", "Warnings"])
        for warning in document["warnings"]:
            prefix = (
                f"{warning['timestamp']}: "
                if warning["timestamp"]
                else ""
            )
            lines.append(f"  {prefix}{warning['message']}")
    lines.extend(
        [
            "",
            "Findings are heuristic indications, not legal conclusions.",
        ]
    )
    if scan["mode"] == "adaptive" and scan["coveragePercent"] < 100:
        lines.append(
            "Use --full-scan when complete monthly coverage is required."
        )
    return "\n".join(lines) + "\n"


def _write_error(
    code: str,
    message: object,
    *,
    json_requested: bool,
    stdout,
    stderr,
) -> None:
    if json_requested:
        stdout.write(render_json(error_document(code, message)))
    else:
        stderr.write(f"Error: {sanitize_terminal(message)}\n")


def run_cli(
    argv: list[str],
    *,
    stdout=sys.stdout,
    stderr=sys.stderr,
    environ: Mapping[str, str] = os.environ,
    client_factory=NetworkClient,
    cdx_endpoint: str = CDX_ENDPOINT,
    replay_base: str = ARCHIVE_REPLAY_BASE,
) -> int:
    json_requested = "--json" in argv
    raw_proxy = None
    proxy = None
    try:
        args = build_parser().parse_args(argv)
        json_requested = bool(args.json_output)
        domain = normalize_domain(args.domain)
        workers = validate_workers(args.workers)
        custom_keywords = normalize_keywords(args.keyword)
        timeout_override = (
            validate_timeout(args.timeout)
            if args.timeout is not None
            else None
        )
        raw_proxy = (
            args.proxy
            if args.proxy is not None
            else environ.get("WAYBACK_PROXY_URL")
        )
        proxy = normalize_proxy_url(raw_proxy)

        def verbose(message: str) -> None:
            if args.verbose:
                stderr.write(
                    redact_proxy_secrets(
                        message,
                        raw_proxy,
                        proxy,
                    )
                    + "\n"
                )

        client = client_factory(
            proxy=proxy,
            raw_proxy=raw_proxy,
            verbose_fn=verbose,
        )
        verbose(f"checking CDX history for {domain}")
        snapshots, parse_warnings = fetch_cdx(
            client,
            domain,
            endpoint=cdx_endpoint,
            timeout=timeout_override or 25.0,
        )
        scan = scan_history(
            snapshots,
            lambda snapshot: scan_snapshot(
                snapshot,
                client,
                domain=domain,
                custom_keywords=custom_keywords,
                timeout=timeout_override or 18.0,
                replay_base=replay_base,
            ),
            full=args.full_scan,
            workers=workers,
            on_interrupt=client.cancel,
        )
        document = build_success_document(
            domain,
            snapshots,
            parse_warnings,
            scan,
        )
        stdout.write(
            render_json(document)
            if args.json_output
            else render_human(document)
        )
        return 0
    except InputError as exc:
        safe_error = _redact_cli_error(
            exc,
            argv,
            raw_proxy,
            proxy,
        )
        _write_error(
            "invalid_input",
            safe_error,
            json_requested=json_requested,
            stdout=stdout,
            stderr=stderr,
        )
        return 2
    except CdxError as exc:
        safe_error = _redact_cli_error(
            exc,
            argv,
            raw_proxy,
            proxy,
        )
        _write_error(
            "cdx_failed",
            safe_error,
            json_requested=json_requested,
            stdout=stdout,
            stderr=stderr,
        )
        return 3
    except KeyboardInterrupt:
        _write_error(
            "interrupted",
            "scan interrupted",
            json_requested=json_requested,
            stdout=stdout,
            stderr=stderr,
        )
        return 130
    except Exception as exc:
        safe_error = _redact_cli_error(
            exc,
            argv,
            raw_proxy,
            proxy,
        )
        _write_error(
            "internal_error",
            safe_error,
            json_requested=json_requested,
            stdout=stdout,
            stderr=stderr,
        )
        if "--verbose" in argv:
            safe_trace = _redact_cli_error(
                traceback.format_exc(),
                argv,
                raw_proxy,
                proxy,
            )
            stderr.write(safe_trace + "\n")
        return 4


def main() -> int:
    return run_cli(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
