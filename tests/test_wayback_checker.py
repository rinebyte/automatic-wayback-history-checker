from __future__ import annotations

import importlib.util
import gzip
from http.client import IncompleteRead
from io import StringIO
import json
import math
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
import ssl
import sys
import unittest
from unittest.mock import patch
from urllib.error import URLError
import zlib


SCRIPT = Path(__file__).resolve().parents[1] / "wayback_checker.py"
SPEC = importlib.util.spec_from_file_location("wayback_checker", SCRIPT)
assert SPEC and SPEC.loader
wb = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wb
SPEC.loader.exec_module(wb)


class InputValidationTests(unittest.TestCase):
    def test_normalizes_url_www_path_trailing_dot_and_idna(self):
        self.assertEqual(
            wb.normalize_domain(" HTTPS://WWW.BÜCHER.DE./path?q=1#x "),
            "xn--bcher-kva.de",
        )

    def test_rejects_invalid_hosts(self):
        for value in (
            "",
            "localhost",
            "example.com:443",
            "user@example.com",
            "-bad.example",
            "bad-.example",
            "two..dots.example",
            "has space.example",
        ):
            with self.subTest(value=value):
                with self.assertRaises(wb.InputError):
                    wb.normalize_domain(value)

    def test_validates_timeout_and_worker_bounds(self):
        self.assertEqual(wb.validate_timeout(18), 18.0)
        self.assertEqual(wb.validate_workers(3), 3)
        for value in (0, 121, math.inf, math.nan, True):
            with self.subTest(timeout=value):
                with self.assertRaises(wb.InputError):
                    wb.validate_timeout(value)
        for value in (0, 9, 1.5, True):
            with self.subTest(workers=value):
                with self.assertRaises(wb.InputError):
                    wb.validate_workers(value)

    def test_normalizes_and_deduplicates_custom_keywords(self):
        self.assertEqual(
            wb.normalize_keywords(["  Slot   Gacor ", "slot gacor", "Pinjol"]),
            ["Slot Gacor", "Pinjol"],
        )
        self.assertEqual(
            wb.sanitize_terminal("safe\x1b]8;;bad\x07text\u202ebidi"),
            "safe]8;;badtextbidi",
        )
        with self.assertRaises(wb.InputError):
            wb.normalize_keywords(["bad\x1bterm"])
        with self.assertRaises(wb.InputError):
            wb.normalize_keywords(["x" * 81])
        with self.assertRaises(wb.InputError):
            wb.normalize_keywords(["x"] * 51)


class ProxyAndRetryTests(unittest.TestCase):
    def test_normalizes_supported_proxy_forms(self):
        self.assertEqual(
            wb.normalize_proxy_url("host:8080"),
            "http://host:8080",
        )
        self.assertEqual(
            wb.normalize_proxy_url("'host:8080:user:p:a'"),
            "http://user:p%3Aa@host:8080",
        )
        self.assertEqual(
            wb.normalize_proxy_url("http://u:p@proxy.example:3128"),
            "http://u:p@proxy.example:3128",
        )

    def test_rejects_unsupported_or_incomplete_proxy(self):
        for value in ("https://proxy.example:443", "proxy-only", "host:notaport"):
            with self.subTest(value=value):
                with self.assertRaises(wb.InputError):
                    wb.normalize_proxy_url(value)

    def test_redacts_proxy_credentials(self):
        raw = "host:8080:user:secret"
        normalized = wb.normalize_proxy_url(raw)
        message = f"failed via {raw} and {normalized}"
        redacted = wb.redact_proxy_secrets(message, raw, normalized)
        self.assertNotIn("user", redacted)
        self.assertNotIn("secret", redacted)
        self.assertIn("[configured proxy]", redacted)

    def test_retry_after_supports_seconds_and_http_date(self):
        now = datetime(2026, 7, 25, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(wb.retry_after_seconds("3", now), 3.0)
        future = format_datetime(now.replace(second=8), usegmt=True)
        self.assertEqual(wb.retry_after_seconds(future, now), 8.0)
        self.assertEqual(wb.retry_after_seconds("45", now), 45.0)
        # Still bounded, so a hostile or absurd header cannot stall a scan.
        self.assertEqual(wb.retry_after_seconds("3600", now), 60.0)
        self.assertIsNone(wb.retry_after_seconds("not-a-date", now))

    def test_backoff_is_exponential_jittered_and_capped(self):
        self.assertAlmostEqual(wb.backoff_seconds(0, 0.5), 0.9)
        self.assertEqual(wb.backoff_seconds(10, 1.0), 8.0)


class CdxParsingTests(unittest.TestCase):
    def test_empty_cdx_is_successful(self):
        snapshots, warnings = wb.parse_cdx_data([])
        self.assertEqual(snapshots, [])
        self.assertEqual(warnings, [])
        self.assertEqual(
            wb.summarize_snapshots(snapshots, warnings),
            {
                "activeYears": 0,
                "hasRedirect": False,
                "redirectTargets": [],
                "firstCapture": "",
                "lastCapture": "",
                "lastStatus": "",
                "captureCount": 0,
                "parseWarningCount": 0,
            },
        )

    def test_maps_reordered_header_sorts_and_defaults_fields(self):
        data = [
            ["original", "redirect", "timestamp", "statuscode", "redirect"],
            ["http://example.com/", "-", "20210203000000", "-", "ignored"],
            [
                "https://example.com/",
                "https://other.test/",
                "20200102000000",
                "301",
                "ignored",
            ],
        ]
        snapshots, warnings = wb.parse_cdx_data(data)
        self.assertEqual(warnings, [])
        self.assertEqual(
            [row["timestamp"] for row in snapshots],
            ["20200102000000", "20210203000000"],
        )
        self.assertEqual(snapshots[0]["redirect"], "https://other.test/")
        self.assertIsNone(snapshots[1]["redirect"])
        self.assertEqual(snapshots[1]["statuscode"], "—")
        self.assertEqual(
            snapshots[0]["archiveUrl"],
            "https://web.archive.org/web/20200102000000/https://example.com/",
        )

    def test_excludes_malformed_rows_with_structured_warning(self):
        data = [
            ["timestamp", "statuscode", "redirect", "original"],
            ["bad", "200", "", "http://example.com/"],
            ["20191201000000", "200", "", ""],
            ["20200102030405", "200", "", "http://example.com/"],
        ]
        snapshots, warnings = wb.parse_cdx_data(data)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(
            warnings,
            [
                {
                    "code": "cdx_row_invalid",
                    "message": "CDX data row 1 was ignored: invalid timestamp",
                    "timestamp": None,
                },
                {
                    "code": "cdx_row_invalid",
                    "message": "CDX data row 2 was ignored: original URL is empty",
                    "timestamp": None,
                },
            ],
        )
        self.assertEqual(
            wb.summarize_snapshots(snapshots, warnings)["parseWarningCount"],
            2,
        )

    def test_rejects_missing_header_and_all_invalid_rows(self):
        with self.assertRaises(wb.CdxError):
            wb.parse_cdx_data([["timestamp", "statuscode"]])
        with self.assertRaises(wb.CdxError):
            wb.parse_cdx_data(
                [
                    ["timestamp", "statuscode", "redirect", "original"],
                    ["not-a-time", "200", "", "http://example.com/"],
                ]
            )

    def test_summary_matches_legacy_fields_and_added_counts(self):
        snapshots, warnings = wb.parse_cdx_data(
            [
                ["timestamp", "statuscode", "redirect", "original"],
                ["20190101000000", "200", "", "http://example.com/"],
                [
                    "20200301000000",
                    "302",
                    "https://target.test/",
                    "http://example.com/",
                ],
                ["20210101000000", "404", "", "http://example.com/"],
            ]
        )
        self.assertEqual(
            wb.summarize_snapshots(snapshots, warnings),
            {
                "activeYears": 3,
                "hasRedirect": True,
                "redirectTargets": ["https://target.test/"],
                "firstCapture": "2019-01",
                "lastCapture": "2021-01",
                "lastStatus": "404",
                "captureCount": 3,
                "parseWarningCount": 0,
            },
        )


class NetworkClientTests(unittest.TestCase):
    def test_retries_status_through_proxy_and_prefers_rescuing_proxy(self):
        calls = []
        sleeps = []
        responses = [
            wb.RawResponse(503, {"retry-after": "1"}, b"busy", False),
            wb.RawResponse(200, {}, b"ok", False),
            wb.RawResponse(200, {}, b"again", False),
        ]

        clock = [100.0]

        def attempt(url, *, proxy, timeout, headers, max_wire_bytes):
            calls.append(proxy)
            return responses.pop(0)

        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds

        client = wb.NetworkClient(
            proxy="http://proxy:8080",
            attempt_fn=attempt,
            sleep_fn=sleep,
            random_fn=lambda: 0.0,
            clock_fn=lambda: clock[0],
        )
        first = client.get("https://example.test/", attempts=3, timeout=5)
        second = client.get("https://example.test/next", attempts=1, timeout=5)
        self.assertEqual(first.status, 200)
        self.assertEqual(second.body, b"again")
        self.assertEqual(calls, [None, "http://proxy:8080", "http://proxy:8080"])
        self.assertEqual(sleeps, [1.0])

    def test_retries_network_error_and_raises_redacted_final_error(self):
        calls = 0

        def attempt(url, **kwargs):
            nonlocal calls
            calls += 1
            raise OSError("failed via http://user:secret@proxy:8080")

        client = wb.NetworkClient(
            proxy="http://user:secret@proxy:8080",
            raw_proxy="proxy:8080:user:secret",
            attempt_fn=attempt,
            sleep_fn=lambda seconds: None,
            random_fn=lambda: 0.0,
        )
        with self.assertRaises(wb.NetworkError) as caught:
            client.get("https://example.test/", attempts=2, timeout=5)
        self.assertEqual(calls, 2)
        self.assertIn("configured proxy", str(caught.exception))
        self.assertNotIn("user", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))

    def test_fetch_cdx_builds_expected_query_and_parses_json(self):
        requested = []

        class FakeClient:
            def get(self, url, **kwargs):
                requested.append((url, kwargs))
                return wb.RawResponse(
                    200,
                    {"content-type": "application/json"},
                    b'[["timestamp","statuscode","redirect","original"]]',
                    False,
                )

        snapshots, warnings = wb.fetch_cdx(FakeClient(), "example.com")
        self.assertEqual(snapshots, [])
        self.assertEqual(warnings, [])
        self.assertIn("url=example.com", requested[0][0])
        self.assertIn("collapse=timestamp%3A6", requested[0][0])
        self.assertEqual(requested[0][1]["attempts"], 3)

    def test_fetch_cdx_decodes_a_compressed_response(self):
        payload = (
            b'[["timestamp","statuscode","redirect","original"],'
            b'["20200101000000","200","","http://example.com/"]]'
        )

        class GzipClient:
            def get(self, url, **kwargs):
                return wb.RawResponse(
                    200,
                    {
                        "content-type": "application/json",
                        "content-encoding": "gzip",
                    },
                    gzip.compress(payload),
                    False,
                )

        snapshots, warnings = wb.fetch_cdx(GzipClient(), "example.com")
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(warnings, [])

    def test_fetch_cdx_maps_busy_and_invalid_json_to_cdx_error(self):
        class BusyClient:
            def get(self, url, **kwargs):
                return wb.RawResponse(503, {}, b"busy", False)

        class BrokenClient:
            def get(self, url, **kwargs):
                return wb.RawResponse(200, {}, b"<html>not json", False)

        with self.assertRaisesRegex(wb.CdxError, "busy"):
            wb.fetch_cdx(BusyClient(), "example.com")
        with self.assertRaisesRegex(wb.CdxError, "valid JSON"):
            wb.fetch_cdx(BrokenClient(), "example.com")

    def test_requests_compressed_bodies_rather_than_identity(self):
        seen = {}

        def attempt(url, *, proxy, timeout, headers, max_wire_bytes):
            seen.update(headers)
            return wb.RawResponse(200, {}, b"ok", False)

        client = wb.NetworkClient(
            attempt_fn=attempt,
            sleep_fn=lambda seconds: None,
            random_fn=lambda: 0.0,
        )
        client.get("https://example.test/", attempts=1, timeout=5)
        # Asking for identity made ordinary pages overflow the wire budget
        # and cost a connection, since a truncated body cannot be reused.
        self.assertIn("gzip", seen["Accept-Encoding"])

    def test_cancel_abandons_the_remaining_attempts(self):
        calls = []

        def attempt(url, **kwargs):
            calls.append(url)
            client.cancel()
            raise OSError("boom")

        client = wb.NetworkClient(
            attempt_fn=attempt,
            sleep_fn=lambda seconds: None,
            random_fn=lambda: 0.0,
        )
        with self.assertRaises(wb.NetworkError):
            client.get("https://example.test/", attempts=3, timeout=5)
        self.assertEqual(len(calls), 1)

    def test_busy_status_waits_the_cooldown_not_the_fast_backoff(self):
        responses = [
            wb.RawResponse(503, {}, b"busy", False),
            wb.RawResponse(200, {}, b"ok", False),
        ]
        sleeps = []
        client = wb.NetworkClient(
            attempt_fn=lambda url, **kwargs: responses.pop(0),
            sleep_fn=sleeps.append,
            random_fn=lambda: 0.0,
            clock_fn=lambda: 100.0,
        )
        response = client.get(
            "https://example.test/",
            attempts=2,
            timeout=5,
        )
        self.assertEqual(response.body, b"ok")
        self.assertEqual(sleeps, [10.0])

    def test_busy_cooldown_also_holds_back_a_later_request(self):
        responses = [
            wb.RawResponse(503, {}, b"busy", False),
            wb.RawResponse(200, {}, b"ok", False),
            wb.RawResponse(200, {}, b"later", False),
        ]
        sleeps = []
        client = wb.NetworkClient(
            attempt_fn=lambda url, **kwargs: responses.pop(0),
            sleep_fn=sleeps.append,
            random_fn=lambda: 0.0,
            clock_fn=lambda: 100.0,
        )
        client.get("https://example.test/a", attempts=2, timeout=5)
        sleeps.clear()
        # A single-attempt request that never saw a 503 still waits out the
        # shared cooldown before its first attempt.
        later = client.get("https://example.test/b", attempts=1, timeout=5)
        self.assertEqual(later.body, b"later")
        self.assertEqual(sleeps, [10.0])

    def test_transient_server_error_keeps_the_fast_backoff(self):
        responses = [
            wb.RawResponse(500, {}, b"boom", False),
            wb.RawResponse(200, {}, b"ok", False),
        ]
        sleeps = []
        client = wb.NetworkClient(
            attempt_fn=lambda url, **kwargs: responses.pop(0),
            sleep_fn=sleeps.append,
            random_fn=lambda: 0.0,
            clock_fn=lambda: 100.0,
        )
        client.get("https://example.test/", attempts=2, timeout=5)
        self.assertEqual(sleeps, [0.7])

    def test_certificate_failure_points_at_the_missing_ca_bundle(self):
        def attempt(url, **kwargs):
            raise URLError(
                ssl.SSLCertVerificationError(
                    1,
                    "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify "
                    "failed: unable to get local issuer certificate",
                )
            )

        client = wb.NetworkClient(
            attempt_fn=attempt,
            sleep_fn=lambda seconds: None,
            random_fn=lambda: 0.0,
        )
        with self.assertRaises(wb.NetworkError) as caught:
            client.get("https://example.test/", attempts=1, timeout=5)
        message = str(caught.exception)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", message)
        self.assertIn("Install Certificates.command", message)
        self.assertIn("SSL_CERT_FILE", message)

    def test_ordinary_network_failure_carries_no_certificate_hint(self):
        def attempt(url, **kwargs):
            raise OSError("connection refused")

        client = wb.NetworkClient(
            attempt_fn=attempt,
            sleep_fn=lambda seconds: None,
            random_fn=lambda: 0.0,
        )
        with self.assertRaises(wb.NetworkError) as caught:
            client.get("https://example.test/", attempts=1, timeout=5)
        self.assertNotIn(
            "Install Certificates.command",
            str(caught.exception),
        )

    def test_retries_protocol_errors_and_maps_final_cdx_failure(self):
        calls = 0

        def attempt(url, **kwargs):
            nonlocal calls
            calls += 1
            raise IncompleteRead(b"partial", 10)

        client = wb.NetworkClient(
            attempt_fn=attempt,
            sleep_fn=lambda seconds: None,
            random_fn=lambda: 0.0,
        )
        with self.assertRaises(wb.CdxError):
            wb.fetch_cdx(client, "example.com")
        self.assertEqual(calls, 3)


class BodyDecodingTests(unittest.TestCase):
    def test_decodes_gzip_with_declared_charset(self):
        source = "<title>Café</title>".encode("iso-8859-1")
        response = wb.RawResponse(
            200,
            {
                "content-encoding": "gzip",
                "content-type": "text/html; charset=iso-8859-1",
            },
            gzip.compress(source),
            False,
        )
        decoded = wb.decode_body(response)
        self.assertEqual(decoded.text, "<title>Café</title>")
        self.assertTrue(decoded.analyzable)
        self.assertTrue(decoded.html_like)
        self.assertFalse(decoded.truncated)

    def test_decodes_wrapped_and_raw_deflate(self):
        payload = b"plain text"
        raw_encoder = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw = raw_encoder.compress(payload) + raw_encoder.flush()
        for body in (zlib.compress(payload), raw):
            with self.subTest(body=body):
                decoded = wb.decode_body(
                    wb.RawResponse(
                        200,
                        {
                            "content-encoding": "deflate",
                            "content-type": "text/plain",
                        },
                        body,
                        False,
                    )
                )
                self.assertEqual(decoded.text, "plain text")

    def test_decodes_all_concatenated_gzip_members(self):
        response = wb.RawResponse(
            200,
            {
                "content-encoding": "gzip",
                "content-type": "text/html",
            },
            (
                gzip.compress(b"<title>Safe</title>")
                + gzip.compress(b" slot")
            ),
            False,
        )
        decoded = wb.decode_body(response)
        self.assertEqual(
            decoded.text,
            "<title>Safe</title> slot",
        )
        self.assertFalse(decoded.truncated)
        analysis = wb.analyze_content(
            decoded,
            original="https://example.com/",
            domain="example.com",
            custom_keywords=[],
        )
        self.assertEqual(
            [match["term"] for match in analysis.risk_matches],
            ["slot"],
        )
        capped = wb.decode_body(
            wb.RawResponse(
                200,
                {
                    "content-encoding": "gzip",
                    "content-type": "text/plain",
                },
                (
                    gzip.compress(b"a" * wb.MAX_DECODED_BYTES)
                    + gzip.compress(b"b" * wb.MAX_DECODED_BYTES)
                ),
                False,
            )
        )
        self.assertEqual(len(capped.text), wb.MAX_DECODED_BYTES)
        self.assertTrue(capped.truncated)

    def test_caps_decompressed_output_and_marks_truncation(self):
        response = wb.RawResponse(
            200,
            {
                "content-encoding": "gzip",
                "content-type": "text/plain",
            },
            gzip.compress(b"x" * (wb.MAX_DECODED_BYTES + 1)),
            False,
        )
        decoded = wb.decode_body(response)
        self.assertEqual(len(decoded.text), wb.MAX_DECODED_BYTES)
        self.assertTrue(decoded.truncated)
        exact = wb.decode_body(
            wb.RawResponse(
                200,
                {"content-type": "text/plain"},
                b"x" * wb.MAX_WIRE_BYTES,
                False,
            )
        )
        wire_overflow = wb.decode_body(
            wb.RawResponse(
                200,
                {"content-type": "text/plain"},
                b"x" * wb.MAX_WIRE_BYTES,
                True,
            )
        )
        self.assertFalse(exact.truncated)
        self.assertTrue(wire_overflow.truncated)

    def test_page_over_the_wire_budget_survives_when_compressed(self):
        # Shaped after a real capture: ~820 KB of HTML, ~196 KB gzipped.
        html = b"<title>Big</title>" + b"a" * 820_000
        packed = gzip.compress(html)
        self.assertLess(len(packed), wb.MAX_WIRE_BYTES)
        decoded = wb.decode_body(
            wb.RawResponse(
                200,
                {
                    "content-encoding": "gzip",
                    "content-type": "text/html",
                },
                packed,
                False,
            )
        )
        self.assertFalse(decoded.truncated)
        self.assertEqual(len(decoded.text), len(html))

    def test_decompression_bomb_is_still_bounded(self):
        packed = gzip.compress(b"\0" * (wb.MAX_DECODED_BYTES * 2))
        self.assertLess(len(packed), wb.MAX_WIRE_BYTES)
        decoded = wb.decode_body(
            wb.RawResponse(
                200,
                {
                    "content-encoding": "gzip",
                    "content-type": "text/plain",
                },
                packed,
                False,
            )
        )
        self.assertTrue(decoded.truncated)
        self.assertEqual(len(decoded.text), wb.MAX_DECODED_BYTES)

    def test_records_unsupported_encoding_without_failure(self):
        for encoding in ("br", "zstd"):
            with self.subTest(encoding=encoding):
                decoded = wb.decode_body(
                    wb.RawResponse(
                        200,
                        {
                            "content-encoding": encoding,
                            "content-type": "text/html",
                        },
                        b"encoded bytes",
                        False,
                    )
                )
                self.assertEqual(decoded.unsupported_encoding, encoding)
                self.assertFalse(decoded.analyzable)
                self.assertIsNone(decoded.text)

    def test_classifies_binary_and_html_sniffed_content(self):
        binary = wb.decode_body(
            wb.RawResponse(
                200,
                {"content-type": "application/octet-stream"},
                b"\x00\x01\x02",
                False,
            )
        )
        sniffed = wb.decode_body(
            wb.RawResponse(
                200,
                {"content-type": "application/octet-stream"},
                b" <!doctype html><title>Sniffed</title>",
                False,
            )
        )
        self.assertFalse(binary.analyzable)
        self.assertTrue(sniffed.analyzable)
        self.assertTrue(sniffed.html_like)
        invalid_charset = wb.decode_body(
            wb.RawResponse(
                200,
                {
                    "content-type": "text/plain; charset=does-not-exist"
                },
                "fallback ✓".encode(),
                False,
            )
        )
        self.assertEqual(invalid_charset.text, "fallback ✓")

    def test_invalid_compression_is_an_analysis_error(self):
        with self.assertRaises(wb.ContentDecodeError):
            wb.decode_body(
                wb.RawResponse(
                    200,
                    {
                        "content-encoding": "gzip",
                        "content-type": "text/plain",
                    },
                    b"not gzip",
                    False,
                )
            )


class HtmlParsingTests(unittest.TestCase):
    def test_extracts_first_clean_title_and_visible_text(self):
        decoded = wb.DecodedBody(
            text=(
                "<html><head><title> First &amp;\nTitle </title>"
                "<title>Second</title><style>slot</style></head>"
                "<body>Hello <script>viagra</script>"
                "<noscript>porn</noscript>World</body></html>"
            ),
            content_type="text/html",
            analyzable=True,
            html_like=True,
            truncated=False,
            unsupported_encoding=None,
        )
        parsed = wb.parse_content(decoded)
        self.assertEqual(parsed.title, "First & Title")
        self.assertEqual(parsed.normalized_title, "first & title")
        self.assertIn("Hello", parsed.visible_text)
        self.assertIn("World", parsed.visible_text)
        self.assertNotIn("viagra", parsed.visible_text)
        self.assertNotIn("slot", parsed.visible_text)
        self.assertEqual(parsed.raw_text.count("viagra"), 1)

    def test_meta_refresh_attributes_can_be_in_any_order(self):
        for markup in (
            '<meta http-equiv="refresh" content="0; url=/next">',
            (
                '<meta content="5; URL=https://other.test/" '
                "HTTP-EQUIV=refresh>"
            ),
        ):
            parsed = wb.parse_content(
                wb.DecodedBody(
                    markup,
                    "text/html",
                    True,
                    True,
                    False,
                    None,
                )
            )
            self.assertIsNotNone(parsed.meta_redirect)

    def test_plain_text_has_no_title_and_remains_analyzable(self):
        parsed = wb.parse_content(
            wb.DecodedBody(
                "hello\nworld",
                "text/plain",
                True,
                False,
                False,
                None,
            )
        )
        self.assertIsNone(parsed.title)
        self.assertEqual(parsed.visible_text, "hello world")

    def test_terminal_controls_and_format_controls_are_removed(self):
        safe = wb.sanitize_terminal("safe\x1b]8;;bad\x07text\u202ebidi")
        self.assertNotIn("\x1b", safe)
        self.assertNotIn("\x07", safe)
        self.assertNotIn("\u202e", safe)
        self.assertEqual(safe, "safe]8;;badtextbidi")


class ContentAnalysisTests(unittest.TestCase):
    def test_categorizes_terms_with_boundaries_and_title_evidence(self):
        matches = wb.find_risk_matches(
            "Slot Gacor",
            "timeslot viagra porn pinjol and C++ service",
            ["C++"],
        )
        compact = [
            (match["category"], match["term"], match["inTitle"])
            for match in matches
        ]
        self.assertEqual(
            compact,
            [
                ("adult", "porn", False),
                ("custom", "C++", False),
                ("gambling", "gacor", True),
                ("gambling", "slot", True),
                ("loan_scam", "pinjol", False),
                ("pharma", "viagra", False),
            ],
        )
        self.assertNotIn("timeslot", [match["term"] for match in matches])
        self.assertTrue(all(len(match["snippet"]) <= 160 for match in matches))

    def test_folds_title_and_body_once_per_analysis(self):
        with patch.object(
            wb,
            "_fold_with_index",
            wraps=wb._fold_with_index,
        ) as folded:
            matches = wb.find_risk_matches(
                "Slot",
                "viagra and custom-term",
                ["custom-term"],
            )
        self.assertTrue(matches)
        self.assertEqual(folded.call_count, 2)

    def test_detects_static_js_but_not_dynamic_expression(self):
        for script in (
            'location = "https://other.test/path"',
            'location.href = "https://other.test/path"',
            'window.location = "https://other.test/path"',
            'window.location.href = "https://other.test/path"',
            'location.replace("https://other.test/path")',
            'window.location.assign("https://other.test/path")',
        ):
            with self.subTest(script=script):
                self.assertEqual(
                    wb.detect_javascript_redirect(script),
                    "https://other.test/path",
                )
        self.assertIsNone(
            wb.detect_javascript_redirect(
                "window.location = buildTarget()"
            )
        )
        for script in (
            'allocation = "https://false.test/"',
            'geolocation.href = "https://false.test/"',
            'object.location = "https://false.test/"',
            '$location = "https://false.test/"',
        ):
            with self.subTest(non_redirect=script):
                self.assertIsNone(
                    wb.detect_javascript_redirect(script)
                )

    def test_resolves_relative_and_unwraps_wayback_targets(self):
        target, cross_host = wb.resolve_redirect(
            (
                "https://web.archive.org/web/"
                "20200101id_/https://other.test/x"
            ),
            "http://example.com/start",
            "example.com",
        )
        self.assertEqual(target, "https://other.test/x")
        self.assertTrue(cross_host)
        same, same_cross = wb.resolve_redirect(
            "/next",
            "https://example.com/start",
            "example.com",
        )
        self.assertEqual(same, "https://example.com/next")
        self.assertFalse(same_cross)
        protocol_relative, protocol_cross = wb.resolve_redirect(
            "//cdn.example.net/landing",
            "https://example.com/start",
            "example.com",
        )
        self.assertEqual(
            protocol_relative,
            "https://cdn.example.net/landing",
        )
        self.assertTrue(protocol_cross)
        unresolved, unresolved_cross = wb.resolve_redirect(
            "mailto:test@example.com",
            "https://example.com/start",
            "example.com",
        )
        self.assertEqual(unresolved, "mailto:test@example.com")
        self.assertIsNone(unresolved_cross)

    def test_meta_precedes_javascript_redirect(self):
        decoded = wb.DecodedBody(
            '<meta http-equiv=refresh content="0; url=/meta">'
            '<script>location.replace("https://js.test/")</script>',
            "text/html",
            True,
            True,
            False,
            None,
        )
        analysis = wb.analyze_content(
            decoded,
            original="https://example.com/",
            domain="example.com",
            custom_keywords=[],
        )
        self.assertEqual(analysis.redirect_type, "meta")
        self.assertEqual(
            analysis.redirect_target,
            "https://example.com/meta",
        )
        self.assertFalse(analysis.cross_host)


class SnapshotScanTests(unittest.TestCase):
    SNAPSHOT = {
        "timestamp": "20200102030405",
        "year": "2020",
        "month": "01",
        "statuscode": "200",
        "redirect": None,
        "original": "http://example.com/",
        "archiveUrl": (
            "https://web.archive.org/web/"
            "20200102030405/http://example.com/"
        ),
    }

    def client_returning(self, response):
        class FakeClient:
            def get(self, url, **kwargs):
                self.url = url
                self.kwargs = kwargs
                return response

        return FakeClient()

    def test_replay_fetch_gets_three_attempts(self):
        client = self.client_returning(
            wb.RawResponse(
                200,
                {"content-type": "text/html"},
                b"<title>ok</title>",
                False,
            )
        )
        wb.scan_snapshot(
            self.SNAPSHOT,
            client,
            domain="example.com",
            custom_keywords=[],
        )
        self.assertEqual(client.kwargs["attempts"], 3)

    def test_http_redirect_does_not_analyze_body(self):
        result = wb.scan_snapshot(
            self.SNAPSHOT,
            self.client_returning(
                wb.RawResponse(
                    302,
                    {"location": "https://other.test/"},
                    b"<title>ignored</title>",
                    False,
                )
            ),
            domain="example.com",
            custom_keywords=[],
        )
        self.assertEqual(result["redirectType"], "http")
        self.assertEqual(
            result["redirectTarget"],
            "https://other.test/",
        )
        self.assertTrue(result["crossHost"])
        self.assertFalse(result["analyzed"])
        self.assertIsNone(result["title"])

    def test_success_and_nonretryable_error_bodies_are_analyzed(self):
        for status in (200, 404):
            with self.subTest(status=status):
                result = wb.scan_snapshot(
                    self.SNAPSHOT,
                    self.client_returning(
                        wb.RawResponse(
                            status,
                            {"content-type": "text/html"},
                            b"<title>Slot Gacor</title>",
                            False,
                        )
                    ),
                    domain="example.com",
                    custom_keywords=[],
                )
                self.assertIsNone(result["error"])
                self.assertTrue(result["analyzed"])
                self.assertEqual(result["title"], "Slot Gacor")
                self.assertTrue(result["riskMatches"])

    def test_final_retryable_status_is_failed_without_body_analysis(self):
        result = wb.scan_snapshot(
            self.SNAPSHOT,
            self.client_returning(
                wb.RawResponse(
                    503,
                    {"content-type": "text/html"},
                    b"<title>Archive error</title>",
                    False,
                )
            ),
            domain="example.com",
            custom_keywords=[],
        )
        self.assertIn("HTTP 503", result["error"])
        self.assertFalse(result["analyzed"])

    def test_unsupported_encoding_is_completed_but_not_analyzed(self):
        result = wb.scan_snapshot(
            self.SNAPSHOT,
            self.client_returning(
                wb.RawResponse(
                    200,
                    {
                        "content-encoding": "br",
                        "content-type": "text/html",
                    },
                    b"bytes",
                    False,
                )
            ),
            domain="example.com",
            custom_keywords=[],
        )
        self.assertIsNone(result["error"])
        self.assertEqual(result["unsupportedEncoding"], "br")
        self.assertFalse(result["analyzed"])


class AdaptiveScanTests(unittest.TestCase):
    def snapshots(self, count):
        return [
            {
                "timestamp": (
                    f"2020{(index // 28) + 1:02d}"
                    f"{(index % 28) + 1:02d}000000"
                ),
                "year": "2020",
                "month": f"{(index // 28) + 1:02d}",
                "statuscode": "200",
                "redirect": None,
                "original": "http://example.com/",
                "archiveUrl": f"https://archive/{index}",
            }
            for index in range(count)
        ]

    def result(
        self,
        snapshot,
        *,
        title="Same",
        risk=False,
        redirect=False,
        error=None,
    ):
        value = wb.failed_scan_result(snapshot, error or "")
        value.update(
            {
                "error": error,
                "title": title,
                "_normalizedTitle": (
                    title.casefold() if title else None
                ),
                "analyzed": error is None,
                "riskMatches": (
                    [
                        {
                            "category": "gambling",
                            "term": "slot",
                            "inTitle": True,
                            "snippet": "slot",
                        }
                    ]
                    if risk
                    else []
                ),
                "redirectType": "meta" if redirect else None,
            }
        )
        return value

    def test_initial_sample_is_unique_and_includes_endpoints(self):
        indexes = wb.initial_sample_indices(100, 20)
        self.assertEqual(len(indexes), 20)
        self.assertEqual(indexes[0], 0)
        self.assertEqual(indexes[-1], 99)
        self.assertEqual(len(set(indexes)), 20)
        snapshots = self.snapshots(12)
        lower = self.result(
            snapshots[5],
            title="Old",
            risk=True,
            redirect=True,
        )
        upper = self.result(snapshots[10], title="New")
        candidates = wb.adaptive_candidates(
            {5: lower, 10: upper},
            submitted={5, 10},
            count=12,
        )
        self.assertEqual(
            candidates[:3],
            [(0, 4), (0, 6), (2, 7)],
        )

    def test_adaptive_scan_recursively_expands_risk_and_title_boundary(
        self,
    ):
        snapshots = self.snapshots(100)
        index_by_timestamp = {
            row["timestamp"]: index
            for index, row in enumerate(snapshots)
        }

        def scan(snapshot):
            index = index_by_timestamp[snapshot["timestamp"]]
            return self.result(
                snapshot,
                title="Old" if index <= 60 else "New",
                risk=51 <= index <= 53,
            )

        outcome = wb.scan_history(
            snapshots,
            scan,
            full=False,
            workers=1,
        )
        scanned = {
            index_by_timestamp[row["timestamp"]]
            for row in outcome["results"]
        }
        self.assertTrue({50, 51, 52, 53, 54}.issubset(scanned))
        self.assertTrue({60, 61, 62}.issubset(scanned))
        self.assertLessEqual(outcome["selected"], 40)
        self.assertEqual(
            outcome["selected"],
            outcome["completed"] + outcome["failed"],
        )

    def test_cap_flag_requires_a_blocked_candidate(self):
        snapshots = self.snapshots(100)

        def risky(snapshot):
            return self.result(snapshot, risk=True)

        outcome = wb.scan_history(
            snapshots,
            risky,
            full=False,
            workers=1,
        )
        self.assertEqual(outcome["selected"], 40)
        self.assertTrue(outcome["adaptiveCapReached"])
        exhausted = wb.scan_history(
            self.snapshots(40),
            risky,
            full=False,
            workers=1,
        )
        self.assertEqual(exhausted["selected"], 40)
        self.assertFalse(exhausted["adaptiveCapReached"])

    def test_full_mode_attempts_every_snapshot_and_preserves_order(self):
        snapshots = self.snapshots(25)
        for snapshot in snapshots:
            snapshot["statuscode"] = "301"
            snapshot["redirect"] = "https://metadata-only.test/"
        adaptive = wb.scan_history(
            snapshots,
            lambda snapshot: self.result(snapshot),
            full=False,
            workers=1,
        )
        self.assertEqual(adaptive["selected"], 20)
        outcome = wb.scan_history(
            snapshots,
            lambda snapshot: self.result(snapshot),
            full=True,
            workers=4,
        )
        self.assertEqual(outcome["selected"], 25)
        self.assertEqual(
            [row["timestamp"] for row in outcome["results"]],
            [row["timestamp"] for row in snapshots],
        )
        self.assertEqual(outcome["coveragePercent"], 100.0)


class ResultDocumentTests(unittest.TestCase):
    def fixtures(self):
        snapshots, parse_warnings = wb.parse_cdx_data(
            [
                [
                    "timestamp",
                    "statuscode",
                    "redirect",
                    "original",
                ],
                [
                    "20200101000000",
                    "200",
                    "",
                    "http://example.com/",
                ],
                [
                    "20200201000000",
                    "301",
                    "https://target.test/",
                    "http://example.com/",
                ],
                [
                    "20200301000000",
                    "200",
                    "",
                    "http://example.com/",
                ],
            ]
        )
        results = []
        for snapshot, title in zip(
            snapshots,
            ("Old", "Old", "New"),
        ):
            result = wb.failed_scan_result(snapshot, "")
            result.update(
                {
                    "error": None,
                    "httpStatus": 200,
                    "title": title,
                    "_normalizedTitle": title.casefold(),
                    "analyzed": True,
                }
            )
            results.append(result)
        results[1]["riskMatches"] = [
            {
                "category": "gambling",
                "term": "slot",
                "inTitle": False,
                "snippet": "found slot content",
            }
        ]
        results[2].update(
            {
                "redirectType": "meta",
                "redirectTarget": "https://other.test/",
                "crossHost": True,
            }
        )
        scan = {
            "mode": "adaptive",
            "validCaptures": 3,
            "selected": 3,
            "completed": 3,
            "failed": 0,
            "coveragePercent": 100.0,
            "adaptiveCapReached": False,
            "partial": False,
            "results": results,
        }
        return snapshots, parse_warnings, scan

    def test_derives_title_risk_and_both_redirect_sources(self):
        snapshots, _, scan = self.fixtures()
        changes = wb.derive_title_changes(
            snapshots,
            scan["results"],
        )
        risks = wb.derive_risk_findings(scan["results"])
        redirects = wb.derive_redirects(
            snapshots,
            scan["results"],
            "example.com",
        )
        self.assertEqual(
            changes,
            [
                {
                    "fromTimestamp": "20200201000000",
                    "toTimestamp": "20200301000000",
                    "fromTitle": "Old",
                    "toTitle": "New",
                    "adjacent": True,
                }
            ],
        )
        self.assertEqual(risks[0]["categories"], ["gambling"])
        self.assertEqual(
            [
                (row["source"], row["type"])
                for row in redirects
            ],
            [("cdx", "cdx"), ("replay", "meta")],
        )

    def test_success_document_has_exact_public_keys_and_no_internal_fields(
        self,
    ):
        snapshots, parse_warnings, scan = self.fixtures()
        document = wb.build_success_document(
            "example.com",
            snapshots,
            parse_warnings,
            scan,
        )
        self.assertEqual(
            set(document),
            {
                "domain",
                "snapshots",
                "summary",
                "scan",
                "warnings",
            },
        )
        self.assertEqual(
            set(document["summary"]),
            {
                "activeYears",
                "hasRedirect",
                "redirectTargets",
                "firstCapture",
                "lastCapture",
                "lastStatus",
                "captureCount",
                "parseWarningCount",
            },
        )
        self.assertEqual(
            set(document["scan"]),
            {
                "mode",
                "validCaptures",
                "selected",
                "completed",
                "failed",
                "coveragePercent",
                "adaptiveCapReached",
                "partial",
                "results",
                "titleChanges",
                "riskFindings",
                "redirects",
            },
        )
        self.assertNotIn(
            "_normalizedTitle",
            document["scan"]["results"][0],
        )
        self.assertEqual(
            set(document["scan"]["results"][0]),
            {
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
            },
        )

    def test_builds_deterministic_warning_objects(self):
        snapshots, parse_warnings, scan = self.fixtures()
        scan["results"][0]["truncated"] = True
        scan["results"][1]["unsupportedEncoding"] = "br"
        scan["results"][1]["analyzed"] = False
        scan["results"][2]["error"] = "timeout"
        scan["failed"] = 1
        scan["completed"] = 2
        scan["partial"] = True
        scan["adaptiveCapReached"] = True
        codes = [
            warning["code"]
            for warning in wb.build_success_document(
                "example.com",
                snapshots,
                parse_warnings,
                scan,
            )["warnings"]
        ]
        self.assertEqual(
            codes,
            [
                "body_truncated",
                "content_encoding_unsupported",
                "snapshot_failed",
                "adaptive_cap_reached",
            ],
        )

    def test_error_document_is_stable(self):
        self.assertEqual(
            wb.error_document("invalid_input", "bad domain"),
            {
                "error": {
                    "code": "invalid_input",
                    "message": "bad domain",
                }
            },
        )


class HumanRenderingTests(unittest.TestCase):
    def build(self, cdx_rows, failed_indexes=()):
        snapshots, parse_warnings = wb.parse_cdx_data(
            [
                ["timestamp", "statuscode", "redirect", "original"],
                *cdx_rows,
            ]
        )
        results = []
        for index, snapshot in enumerate(snapshots):
            if index in failed_indexes:
                results.append(
                    wb.failed_scan_result(snapshot, "replay timed out")
                )
                continue
            result = wb.failed_scan_result(snapshot, "")
            result.update(
                {
                    "error": None,
                    "httpStatus": 200,
                    "analyzed": True,
                }
            )
            results.append(result)
        failed = len(failed_indexes)
        scan = {
            "mode": "adaptive",
            "validCaptures": len(snapshots),
            "selected": len(results),
            "completed": len(results) - failed,
            "failed": failed,
            "coveragePercent": 100.0,
            "adaptiveCapReached": False,
            "partial": failed > 0,
            "results": results,
        }
        return wb.build_success_document(
            "example.com",
            snapshots,
            parse_warnings,
            scan,
        )

    def test_targetless_redirects_collapse_into_one_line(self):
        document = self.build(
            [
                ["20200101000000", "301", "", "http://example.com/"],
                ["20200201000000", "301", "", "http://example.com/"],
                ["20200301000000", "302", "", "http://example.com/"],
                [
                    "20200401000000",
                    "301",
                    "https://target.test/",
                    "http://example.com/",
                ],
            ]
        )
        rendered = wb.render_human(document)
        self.assertNotIn("target unavailable", rendered)
        self.assertIn("https://target.test/", rendered)
        self.assertIn(
            "3 CDX captures reported a redirect with no recorded target",
            rendered,
        )
        # The JSON contract stays complete; only the human view collapses.
        self.assertEqual(len(document["scan"]["redirects"]), 4)

    def test_single_targetless_redirect_is_reported_in_singular(self):
        document = self.build(
            [["20200101000000", "301", "", "http://example.com/"]]
        )
        rendered = wb.render_human(document)
        self.assertIn(
            "1 CDX capture reported a redirect with no recorded target",
            rendered,
        )

    def test_partial_scan_is_flagged_beside_coverage_and_risk(self):
        document = self.build(
            [
                ["20200101000000", "200", "", "http://example.com/"],
                ["20200201000000", "200", "", "http://example.com/"],
            ],
            failed_indexes={1},
        )
        rendered = wb.render_human(document)
        self.assertIn("Status: PARTIAL", rendered)
        self.assertIn("1 of 2 selected captures failed", rendered)
        self.assertIn("scan incomplete", rendered)

    def test_complete_scan_is_never_flagged_as_partial(self):
        document = self.build(
            [["20200101000000", "200", "", "http://example.com/"]]
        )
        rendered = wb.render_human(document)
        self.assertNotIn("PARTIAL", rendered)
        self.assertNotIn("scan incomplete", rendered)
        self.assertIn("None in scanned captures", rendered)


class CliTests(unittest.TestCase):
    def fake_client_factory(self, **client_options):
        class FakeClient:
            def get(self, url, **kwargs):
                if "cdx/search/cdx" in url:
                    return wb.RawResponse(
                        200,
                        {"content-type": "application/json"},
                        (
                            b'[["timestamp","statuscode",'
                            b'"redirect","original"],'
                            b'["20200102030405","200","",'
                            b'"http://example.com/"]]'
                        ),
                        False,
                    )
                return wb.RawResponse(
                    200,
                    {"content-type": "text/html"},
                    b"<title>Example Domain</title>",
                    False,
                )

            def cancel(self):
                pass

            def close(self):
                pass

        return FakeClient()

    def test_json_success_is_parseable_and_quiet(self):
        stdout, stderr = StringIO(), StringIO()
        code = wb.run_cli(
            ["example.com", "--json"],
            stdout=stdout,
            stderr=stderr,
            environ={},
            client_factory=self.fake_client_factory,
        )
        document = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(document["domain"], "example.com")
        self.assertEqual(stderr.getvalue(), "")

    def test_json_invalid_input_is_only_error_document(self):
        stdout, stderr = StringIO(), StringIO()
        code = wb.run_cli(
            ["localhost", "--json"],
            stdout=stdout,
            stderr=stderr,
            environ={},
        )
        self.assertEqual(code, 2)
        self.assertEqual(
            json.loads(stdout.getvalue())["error"]["code"],
            "invalid_input",
        )
        self.assertEqual(stderr.getvalue(), "")

        class BusyClient:
            def get(self, url, **kwargs):
                return wb.RawResponse(503, {}, b"busy", False)

            def close(self):
                pass

        busy_out, busy_err = StringIO(), StringIO()
        busy_code = wb.run_cli(
            ["example.com", "--json"],
            stdout=busy_out,
            stderr=busy_err,
            environ={},
            client_factory=lambda **options: BusyClient(),
        )
        self.assertEqual(busy_code, 3)
        self.assertEqual(
            json.loads(busy_out.getvalue())["error"]["code"],
            "cdx_failed",
        )
        self.assertEqual(busy_err.getvalue(), "")

    def test_parse_errors_redact_proxy_like_credentials(self):
        for proxy_like in (
            "http://user:secret@proxy.example:8080",
            "HTTP://user:secret@proxy.example:8080",
            "HTTP://user name:secret phrase@proxy.example:8080",
            "proxy.example:8080:user:secret",
            "proxy.example:8080:user:secret phrase",
        ):
            for json_output in (False, True):
                with self.subTest(
                    proxy_like=proxy_like,
                    json_output=json_output,
                ):
                    stdout, stderr = StringIO(), StringIO()
                    argv = ["example.com", proxy_like]
                    if json_output:
                        argv.append("--json")
                    code = wb.run_cli(
                        argv,
                        stdout=stdout,
                        stderr=stderr,
                        environ={},
                    )
                    combined = (
                        stdout.getvalue() + stderr.getvalue()
                    )
                    self.assertEqual(code, 2)
                    self.assertNotIn("user", combined)
                    self.assertNotIn("secret", combined)
                    if json_output:
                        self.assertEqual(
                            json.loads(stdout.getvalue())[
                                "error"
                            ]["code"],
                            "invalid_input",
                        )

    def test_human_output_contains_summary_and_heuristic_notice(self):
        stdout, stderr = StringIO(), StringIO()
        code = wb.run_cli(
            ["example.com"],
            stdout=stdout,
            stderr=stderr,
            environ={},
            client_factory=self.fake_client_factory,
        )
        self.assertEqual(code, 0)
        self.assertIn(
            "Wayback Checker: example.com",
            stdout.getvalue(),
        )
        self.assertIn("Title changes", stdout.getvalue())
        self.assertIn("heuristic", stdout.getvalue().lower())

    def test_verbose_progress_uses_stderr_and_proxy_env_precedence(self):
        captured_options = {}

        def factory(**options):
            captured_options.update(options)
            return self.fake_client_factory()

        stdout, stderr = StringIO(), StringIO()
        code = wb.run_cli(
            [
                "example.com",
                "--json",
                "--verbose",
                "--proxy",
                "cli:80",
            ],
            stdout=stdout,
            stderr=stderr,
            environ={"WAYBACK_PROXY_URL": "env:81"},
            client_factory=factory,
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            captured_options["proxy"],
            "http://cli:80",
        )
        self.assertTrue(stderr.getvalue())
        json.loads(stdout.getvalue())

        def broken_factory(**options):
            raise RuntimeError(
                "boom via http://user:secret@proxy.example:80"
            )

        failed_out, failed_err = StringIO(), StringIO()
        failed_code = wb.run_cli(
            [
                "example.com",
                "--json",
                "--verbose",
                "--proxy",
                "proxy.example:80:user:secret",
            ],
            stdout=failed_out,
            stderr=failed_err,
            environ={},
            client_factory=broken_factory,
        )
        self.assertEqual(failed_code, 4)
        combined = failed_out.getvalue() + failed_err.getvalue()
        self.assertNotIn("user", combined)
        self.assertNotIn("secret", combined)


if __name__ == "__main__":
    unittest.main()
