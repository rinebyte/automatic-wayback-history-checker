from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import select
import signal
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit


SCRIPT = Path(__file__).resolve().parents[1] / "wayback_checker.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SPEC = importlib.util.spec_from_file_location(
    "wayback_checker_integration",
    SCRIPT,
)
assert SPEC and SPEC.loader
wb = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wb
SPEC.loader.exec_module(wb)


class ScenarioHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = urlsplit(self.path).path
        responses = self.server.routes[path]
        status, headers, body, delay = (
            responses.pop(0)
            if len(responses) > 1
            else responses[0]
        )
        if delay:
            self.server.delay_fn(delay)
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format, *args):
        return


class ScenarioServer(ThreadingHTTPServer):
    daemon_threads = True

    def process_request(self, request, client_address):
        # One call per accepted TCP connection, so this counts connections
        # rather than requests.
        self.connections_accepted = (
            getattr(self, "connections_accepted", 0) + 1
        )
        super().process_request(request, client_address)


@contextmanager
def scenario_server(routes, delay_fn=lambda seconds: None, handle=None):
    server = ScenarioServer(
        ("127.0.0.1", 0),
        ScenarioHandler,
    )
    server.routes = routes
    server.delay_fn = delay_fn
    server.connections_accepted = 0
    if handle is not None:
        handle.append(server)
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class RetryTlsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.requests_seen += 1
        status = 503 if self.server.requests_seen == 1 else 200
        body = b"busy" if status == 503 else b"ok"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@contextmanager
def tls_origin():
    server = ScenarioServer(
        ("127.0.0.1", 0),
        RetryTlsHandler,
    )
    server.requests_seen = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        FIXTURES / "localhost-cert.pem",
        FIXTURES / "localhost-key.pem",
    )
    server.socket = context.wrap_socket(
        server.socket,
        server_side=True,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class ConnectRelayHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline().decode("ascii").strip()
        method, target, _ = request_line.split(" ", 2)
        headers = {}
        while True:
            line = self.rfile.readline()
            if line in {b"\r\n", b"\n", b""}:
                break
            name, value = line.decode("iso-8859-1").split(":", 1)
            headers[name.lower()] = value.strip()
        if method != "CONNECT":
            self.wfile.write(
                b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"
            )
            return
        host, port_text = target.rsplit(":", 1)
        upstream = socket.create_connection(
            (host, int(port_text)),
            timeout=2,
        )
        self.server.targets.append(target)
        self.server.proxy_authorization.append(
            headers.get("proxy-authorization")
        )
        self.wfile.write(
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        self.wfile.flush()
        sockets = [self.connection, upstream]
        try:
            while True:
                readable, _, _ = select.select(
                    sockets,
                    [],
                    [],
                    0.5,
                )
                for source in readable:
                    data = source.recv(65_536)
                    if not data:
                        return
                    destination = (
                        upstream
                        if source is self.connection
                        else self.connection
                    )
                    destination.sendall(data)
        finally:
            upstream.close()


class ConnectServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextmanager
def connect_proxy():
    server = ConnectServer(
        ("127.0.0.1", 0),
        ConnectRelayHandler,
    )
    server.targets = []
    server.proxy_authorization = []
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def slow_routes():
    cdx_rows = [
        ["timestamp", "statuscode", "redirect", "original"],
        *[
            [
                f"2020{month:02d}01000000",
                "200",
                "",
                "http://example.com/",
            ]
            for month in range(1, 13)
        ],
    ]
    routes = {
        "/cdx": [
            (
                200,
                {"Content-Type": "application/json"},
                json.dumps(cdx_rows).encode(),
                0,
            )
        ],
    }
    for row in cdx_rows[1:]:
        routes[
            f"/web/{row[0]}id_/http://example.com/"
        ] = [
            (
                200,
                {"Content-Type": "text/html"},
                b"<title>Slow</title>",
                3,
            )
        ]
    return routes


class ConnectionReuseIntegrationTests(unittest.TestCase):
    def test_repeated_requests_share_one_tcp_connection(self):
        routes = {
            "/page": [
                (200, {"Content-Type": "text/html"}, b"<title>ok</title>", 0)
            ]
        }
        handle = []
        with scenario_server(routes, handle=handle) as base:
            client = wb.NetworkClient(sleep_fn=lambda seconds: None)
            self.addCleanup(client.close)
            for _ in range(12):
                self.assertEqual(
                    client.get(
                        f"{base}/page",
                        attempts=1,
                        timeout=5,
                    ).status,
                    200,
                )
        # Archive.org budgets new TCP connections, not requests, so a scan
        # must not open one per capture.
        self.assertEqual(handle[0].connections_accepted, 1)

    def test_truncated_response_does_not_poison_the_pool(self):
        routes = {
            "/big": [(200, {"Content-Type": "text/html"}, b"x" * 500, 0)]
        }
        handle = []
        with scenario_server(routes, handle=handle) as base:
            client = wb.NetworkClient(sleep_fn=lambda seconds: None)
            self.addCleanup(client.close)
            first = client.get(
                f"{base}/big",
                attempts=1,
                timeout=5,
                max_wire_bytes=10,
            )
            self.assertTrue(first.wire_truncated)
            self.assertEqual(len(first.body), 10)
            # An undrained connection cannot be reused; the next request must
            # still succeed rather than read the previous body's leftovers.
            second = client.get(f"{base}/big", attempts=1, timeout=5)
            self.assertEqual(second.status, 200)
            self.assertEqual(len(second.body), 500)

    def test_server_closing_the_connection_is_handled(self):
        routes = {
            "/once": [
                (
                    200,
                    {"Content-Type": "text/html", "Connection": "close"},
                    b"bye",
                    0,
                )
            ]
        }
        handle = []
        with scenario_server(routes, handle=handle) as base:
            client = wb.NetworkClient(sleep_fn=lambda seconds: None)
            self.addCleanup(client.close)
            for _ in range(3):
                self.assertEqual(
                    client.get(
                        f"{base}/once",
                        attempts=1,
                        timeout=5,
                    ).body,
                    b"bye",
                )
        self.assertEqual(handle[0].connections_accepted, 3)


class LocalHttpIntegrationTests(unittest.TestCase):
    def test_real_urllib_retry_after_and_no_redirect_follow(self):
        future = format_datetime(
            datetime.now(timezone.utc) + timedelta(seconds=2),
            usegmt=True,
        )
        routes = {
            "/seconds": [
                (503, {"Retry-After": "0"}, b"busy", 0),
                (200, {}, b"ok", 0),
            ],
            "/date": [
                (503, {"Retry-After": future}, b"busy", 0),
                (200, {}, b"ok", 0),
            ],
            "/redirect": [
                (302, {"Location": "/target"}, b"", 0),
            ],
        }
        sleeps = []

        def sleep(seconds):
            # Really sleep: the busy cooldown is wall-clock based, so a fake
            # sleep would leave it pending and stall the next request.
            sleeps.append(seconds)
            time.sleep(seconds)

        with scenario_server(routes) as base:
            client = wb.NetworkClient(sleep_fn=sleep)
            self.addCleanup(client.close)
            self.assertEqual(
                client.get(
                    f"{base}/seconds",
                    attempts=2,
                    timeout=2,
                ).status,
                200,
            )
            self.assertEqual(
                client.get(
                    f"{base}/date",
                    attempts=2,
                    timeout=2,
                ).status,
                200,
            )
            redirect = client.get(
                f"{base}/redirect",
                attempts=1,
                timeout=2,
            )
        self.assertEqual(redirect.status, 302)
        self.assertEqual(
            redirect.headers["location"],
            "/target",
        )
        # "Retry-After: 0" means retry now, so it no longer books a sleep;
        # only the future-dated header makes the client wait.
        self.assertEqual(len(sleeps), 1)
        self.assertGreaterEqual(sleeps[0], 0.0)
        self.assertLessEqual(sleeps[0], 3.0)

    def test_end_to_end_json_keeps_partial_replay_result(self):
        cdx = (
            b'[["timestamp","statuscode","redirect","original"],'
            b'["20200101000000","200","","http://example.com/"],'
            b'["20200201000000","404","","http://example.com/"],'
            b'["20200301000000","200","","http://example.com/"]]'
        )
        # Served gzipped, so it compresses to a few KB on the wire and only
        # the decoded budget can cut it.
        risky_html = (
            b"<title>Slot Gacor</title>" + b"x" * (wb.MAX_DECODED_BYTES + 1)
        )
        routes = {
            "/cdx": [
                (
                    200,
                    {"Content-Type": "application/json"},
                    cdx,
                    0,
                )
            ],
            "/web/20200101000000id_/http://example.com/": [
                (
                    200,
                    {
                        "Content-Type": (
                            "text/html; charset=utf-8"
                        ),
                        "Content-Encoding": "gzip",
                    },
                    gzip.compress(risky_html),
                    0,
                )
            ],
            "/web/20200201000000id_/http://example.com/": [
                (
                    404,
                    {"Content-Type": "text/html"},
                    b"<title>Gone</title>",
                    0,
                )
            ],
            "/web/20200301000000id_/http://example.com/": [
                (
                    503,
                    {"Retry-After": "0"},
                    b"busy",
                    0,
                ),
                (
                    503,
                    {"Retry-After": "0"},
                    b"busy",
                    0,
                ),
            ],
        }

        def factory(**options):
            return wb.NetworkClient(
                **options,
                sleep_fn=lambda seconds: None,
                random_fn=lambda: 0.0,
            )

        stdout, stderr = StringIO(), StringIO()
        with scenario_server(routes) as base:
            code = wb.run_cli(
                [
                    "example.com",
                    "--json",
                    "--full-scan",
                ],
                stdout=stdout,
                stderr=stderr,
                environ={},
                client_factory=factory,
                cdx_endpoint=f"{base}/cdx",
                replay_base=f"{base}/web",
            )
        document = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(document["scan"]["partial"])
        self.assertEqual(document["scan"]["failed"], 1)
        self.assertEqual(document["scan"]["completed"], 2)
        self.assertEqual(
            document["scan"]["results"][1]["httpStatus"],
            404,
        )
        self.assertEqual(
            document["scan"]["riskFindings"][0]["categories"],
            ["gambling"],
        )
        self.assertIn(
            "body_truncated",
            [
                warning["code"]
                for warning in document["warnings"]
            ],
        )

    def test_runtime_still_works_when_only_script_is_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "wayback_checker.py"
            shutil.copy2(SCRIPT, copied)
            help_run = subprocess.run(
                [sys.executable, str(copied), "--help"],
                text=True,
                capture_output=True,
                check=False,
            )
            invalid_run = subprocess.run(
                [
                    sys.executable,
                    str(copied),
                    "localhost",
                    "--json",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(help_run.returncode, 0)
        self.assertIn("Wayback", help_run.stdout)
        self.assertEqual(invalid_run.returncode, 2)
        self.assertEqual(
            json.loads(invalid_run.stdout)["error"]["code"],
            "invalid_input",
        )


class ConnectAndInterruptIntegrationTests(unittest.TestCase):
    def test_https_retry_really_traverses_authenticated_connect_proxy(
        self,
    ):
        logs = []
        client_context = ssl.create_default_context(
            cafile=str(FIXTURES / "localhost-cert.pem")
        )
        with tls_origin() as origin, connect_proxy() as proxy:
            raw_proxy = (
                f"127.0.0.1:{proxy.server_address[1]}:"
                "user:secret"
            )
            normalized = wb.normalize_proxy_url(raw_proxy)
            client = wb.NetworkClient(
                proxy=normalized,
                raw_proxy=raw_proxy,
                attempt_fn=wb.PooledTransport(
                    ssl_context=client_context,
                ),
                sleep_fn=lambda seconds: None,
                random_fn=lambda: 0.0,
                verbose_fn=logs.append,
            )
            self.addCleanup(client.close)
            with patch.dict(
                os.environ,
                {"NO_PROXY": "*", "no_proxy": "*"},
                clear=False,
            ):
                response = client.get(
                    origin,
                    attempts=2,
                    timeout=2,
                )
        self.assertEqual(response.status, 200)
        self.assertEqual(len(proxy.targets), 1)
        self.assertEqual(len(proxy.proxy_authorization), 1)
        self.assertTrue(
            proxy.proxy_authorization[0].startswith("Basic ")
        )
        combined = "\n".join(logs)
        self.assertNotIn("user", combined)
        self.assertNotIn("secret", combined)

    def test_interrupt_returns_130_without_partial_success_document(
        self,
    ):
        with scenario_server(
            slow_routes(),
            delay_fn=time.sleep,
        ) as base:
            program = (
                "import importlib.util,sys;"
                "s=importlib.util.spec_from_file_location("
                f"'wb',{str(SCRIPT)!r});"
                "m=importlib.util.module_from_spec(s);"
                "sys.modules[s.name]=m;"
                "s.loader.exec_module(m);"
                "raise SystemExit(m.run_cli("
                "['example.com','--json','--timeout','1',"
                "'--workers','2'],"
                f"cdx_endpoint={base + '/cdx'!r},"
                f"replay_base={base + '/web'!r}))"
            )
            started = time.monotonic()
            process = subprocess.Popen(
                [sys.executable, "-c", program],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.3)
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=5)
            elapsed = time.monotonic() - started
        self.assertEqual(process.returncode, 130)
        self.assertLess(elapsed, 4.0)
        self.assertEqual(
            json.loads(stdout),
            {
                "error": {
                    "code": "interrupted",
                    "message": "scan interrupted",
                }
            },
        )
        self.assertNotIn('"scan"', stdout)


if __name__ == "__main__":
    unittest.main()
