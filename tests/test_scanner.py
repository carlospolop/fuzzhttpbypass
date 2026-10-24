import asyncio
import importlib.util
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from typing import ClassVar

import fuzzhttpbypass as tool


class Handler(BaseHTTPRequestHandler):
    paths: ClassVar[list[str]] = []
    unstable_count = 0
    dynamic_count = 0

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.paths.append(self.path)
        if self.headers.get("X-Generic") == "yes":
            status, body = 200, b"generic page"
            self.send_response(status)
        elif self.path.startswith("/admin"):
            allowed = self.headers.get("X-Forwarded-For") == "127.0.0.1"
            allowed &= "sid=test" in self.headers.get("Cookie", "")
            status, body = (200, b"SECRET admin dashboard") if allowed else (403, b"denied")
            self.send_response(status)
            self.send_header("Set-Cookie", "sid=test")
        elif self.path.startswith("/redirect"):
            status, body = 302, b"redirect"
            self.send_response(status)
            self.send_header("Location", "/login")
        elif self.path.startswith("/fake"):
            status, body = ((200, b"missing")
                            if self.headers.get("X-Requested-With") == "XMLHttpRequest"
                            else (403, b"denied"))
            self.send_response(status)
        elif self.path.startswith("/candidate"):
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                status, body = 200, b"new content"
            else:
                status, body = 403, b"denied"
            self.send_response(status)
        elif self.path.startswith("/unstable"):
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                Handler.unstable_count += 1
                status, body = ((200, b"new content") if Handler.unstable_count % 2
                                else (403, b"denied"))
            else:
                status, body = 403, b"denied"
            self.send_response(status)
        elif self.path.startswith("/dynamic"):
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                Handler.dynamic_count += 1
                status, body = 200, f"SECRET nonce={Handler.dynamic_count}".encode()
            else:
                status, body = 403, b"denied"
            self.send_response(status)
        elif self.path.startswith("/redirprotected"):
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                status, body = 200, b"private page"
            else:
                status, body = 302, b"redirect"
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "/login")
        elif self.path.startswith("/head"):
            status, body = 302, b"redirect"
            self.send_response(status)
            self.send_header("Location", "/login")
        elif self.path.startswith("/cookie"):
            allowed = "role=admin" in self.headers.get("Cookie", "")
            status, body = (200, b"COOKIE_SECRET") if allowed else (403, b"denied")
            self.send_response(status)
            self.send_header("Set-Cookie", "role=user")
        elif self.path.startswith("/bearer"):
            allowed = self.headers.get("Authorization") == "Bearer good"
            status, body = (200, b"BEARER_SECRET") if allowed else (403, b"denied")
            self.send_response(status)
        elif self.path.startswith("/custom"):
            allowed = self.headers.get("X-Allow") == "yes"
            status, body = (200, b"CUSTOM_SECRET") if allowed else (403, b"denied")
            self.send_response(status)
        elif self.path.startswith("/target"):
            status, body = 403, b"denied"
            self.send_response(status)
        elif self.path.startswith("/alt"):
            status, body = 200, b"PATH_SECRET"
            self.send_response(status)
        elif self.path.startswith("/big"):
            status, body = 200, b"x" * 4096
            self.send_response(status)
        elif self.path.startswith("/late"):
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                status, body = 200, b"x" * 70000 + b"LATE_SECRET"
            else:
                status, body = 403, b"denied"
            self.send_response(status)
        elif self.path.startswith("/generic"):
            status, body = 403, b"denied"
            self.send_response(status)
        else:
            status, body = 404, b"missing"
            self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        if self.path == "/head":
            self.send_response(200)
            self.send_header("Set-Cookie", "adminSession=private; HttpOnly")
            self.end_headers()
            return
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/post":
            allowed = body == b'{"token":"abc"}'
            allowed &= self.headers.get("X-Forwarded-For") == "127.0.0.1"
            payload = b"POST_SECRET" if allowed else b"denied"
            self.send_response(200 if allowed else 403)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(405)
        self.end_headers()


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def args(self, path, *extra):
        return tool.parser().parse_args([
            "-u", self.base + path, "--rate", "0", "--concurrency", "3", *extra
        ])

    def test_header_bypass_requires_cookie_and_marker(self):
        result = asyncio.run(tool.run(self.args(
            "/admin", "--checks", "headers", "--success-regex", "SECRET admin"
        )))[0]
        self.assertEqual(result["baseline"]["status"], 403)
        self.assertEqual(result["control"]["status"], 404)
        self.assertTrue(any(
            finding["classification"] == "confirmed"
            and finding["name"] == "X-Forwarded-For: 127.0.0.1"
            for finding in result["findings"]
        ))
        self.assertEqual(result["errors"], [])

    def test_redirect_is_not_followed(self):
        result = asyncio.run(tool.run(self.args("/redirect", "--checks", "protocol")))[0]
        self.assertEqual(result["baseline"]["status"], 302)
        self.assertEqual(result["baseline"]["location"], "/login")

    def test_no_false_bypass_when_baseline_is_403(self):
        result = asyncio.run(tool.run(self.args("/fake", "--checks", "protocol")))[0]
        self.assertFalse(any(f["classification"] in ("confirmed", "candidate")
                             for f in result["findings"]))

    def test_literal_dot_paths_reach_server(self):
        Handler.paths.clear()
        asyncio.run(tool.run(self.args("/admin", "--checks", "paths")))
        self.assertIn("/./admin", Handler.paths)
        self.assertIn("/x/../admin", Handler.paths)

    def test_post_body_is_preserved_for_header_probes(self):
        result = asyncio.run(tool.run(self.args(
            "/post", "-X", "POST", "-d", '{"token":"abc"}',
            "--checks", "headers", "--success-regex", "POST_SECRET"
        )))[0]
        self.assertEqual(result["baseline"]["status"], 403)
        self.assertTrue(any(f["classification"] == "confirmed" for f in result["findings"]))

    def test_captured_post_request_file(self):
        body = b'{"token":"abc"}'
        host = f"127.0.0.1:{self.server.server_port}"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.txt"
            request_head = (
                f"POST /post HTTP/1.1\r\nHost: {host}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                "\r\n"
            )
            path.write_bytes(request_head.encode() + body)
            args = tool.parser().parse_args([
                "--request-file", str(path), "--request-proto", "http",
                "--checks", "headers", "--success-regex", "POST_SECRET", "--rate", "0",
            ])
            result = asyncio.run(tool.run(args))[0]
            self.assertEqual(result["baseline"]["status"], 403)
            self.assertTrue(any(f["classification"] == "confirmed" for f in result["findings"]))
            path.write_bytes(path.read_bytes().replace(b"Content-Length: 15", b"Content-Length: 14"))
            with self.assertRaisesRegex(ValueError, "Content-Length"):
                tool.load_request_file(path, "http")

    def test_repeatable_status_change_is_only_a_candidate(self):
        result = asyncio.run(tool.run(self.args(
            "/candidate", "--checks", "headers"
        )))[0]
        self.assertTrue(any(
            f["classification"] == "candidate"
            and f["name"] == "X-Forwarded-For: 127.0.0.1"
            for f in result["findings"]))
        self.assertFalse(any(f["classification"] == "confirmed" for f in result["findings"]))

    def test_unstable_response_is_not_reported_as_bypass(self):
        Handler.unstable_count = 0
        result = asyncio.run(tool.run(self.args(
            "/unstable", "--checks", "headers"
        )))[0]
        self.assertFalse(any(
            f["classification"] == "candidate"
            and f["name"] == "X-Forwarded-For: 127.0.0.1"
            for f in result["findings"]))

    def test_dynamic_confirmed_body_can_change(self):
        Handler.dynamic_count = 0
        result = asyncio.run(tool.run(self.args(
            "/dynamic", "--checks", "headers", "--success-regex", "SECRET"
        )))[0]
        self.assertTrue(any(
            f["classification"] == "confirmed" and not f["stable_body"]
            for f in result["findings"]))

    def test_redirect_to_login_can_be_candidate(self):
        result = asyncio.run(tool.run(self.args(
            "/redirprotected", "--checks", "headers"
        )))[0]
        self.assertTrue(any(
            f["classification"] == "candidate"
            and f["name"] == "X-Forwarded-For: 127.0.0.1"
            for f in result["findings"]))

    def test_head_can_grant_session_cookie_without_body(self):
        result = asyncio.run(tool.run(self.args(
            "/head", "--checks", "methods"
        )))[0]
        finding = next(f for f in result["findings"] if f["name"] == "HEAD")
        self.assertEqual(finding["classification"], "candidate")
        self.assertEqual(finding["response"]["length"], 0)
        self.assertIn("adminSession", finding["response"]["set_cookie_names"])
        self.assertNotIn("private", json.dumps(result))

    def test_custom_cookie_value(self):
        result = asyncio.run(tool.run(self.args(
            "/cookie", "--checks", "auth", "--cookie-value", "admin",
            "--success-regex", "COOKIE_SECRET"
        )))[0]
        self.assertTrue(any(f["classification"] == "confirmed" for f in result["findings"]))

    def test_bearer_token_is_redacted(self):
        result = asyncio.run(tool.run(self.args(
            "/bearer", "--checks", "auth", "--bearer", "good",
            "--success-regex", "BEARER_SECRET"
        )))[0]
        self.assertTrue(any(f["classification"] == "confirmed" for f in result["findings"]))
        self.assertNotIn("Bearer good", json.dumps(result))

    def test_custom_path_and_header(self):
        path = asyncio.run(tool.run(self.args(
            "/target", "--checks", "paths", "--path-variant", "/alt?x=1",
            "--success-regex", "PATH_SECRET"
        )))[0]
        header = asyncio.run(tool.run(self.args(
            "/custom", "--checks", "headers",
            "--header-variant", "X-Allow: no", "--header-variant", "X-Allow: yes",
            "--success-regex", "CUSTOM_SECRET"
        )))[0]
        self.assertTrue(any(f["classification"] == "confirmed" for f in path["findings"]))
        self.assertTrue(any(f["request"]["url"].endswith("/alt?x=1") for f in path["findings"]))
        self.assertTrue(any(f["classification"] == "confirmed" for f in header["findings"]))
        self.assertTrue(any(f["name"] == "custom X-Allow #2" for f in header["findings"]))

    @unittest.skipUnless(importlib.util.find_spec("requests_ntlm"), "NTLM extra unavailable")
    def test_ntlm_probe_uses_optional_client(self):
        result = asyncio.run(tool.run(self.args(
            "/fake", "--checks", "auth", "--ntlm", "EXAMPLE\\user:secret"
        )))[0]
        self.assertEqual(result["errors"], [])
        self.assertNotIn("secret", json.dumps(result))

    def test_url_query_and_ipv6_parsing(self):
        url = "https://[::1]:8443/admin?x=1"
        self.assertEqual(tool.validate_url(url), url)
        self.assertTrue(all("?x=1" in value for _, value in tool.path_variants(url)))
        self.assertEqual(tool.parse_ips(["::1", "127.0.0.1"]), ["::1", "127.0.0.1"])
        with self.assertRaises(ValueError):
            tool.validate_url("ftp://example.org/admin")

    def test_method_probe_requires_opt_in_for_mutating_verbs(self):
        url = self.base + "/admin"
        ordinary = tool.generate_probes(url, {"methods"}, [], [])
        unsafe = tool.generate_probes(url, {"methods"}, [], [], True)
        self.assertNotIn("DELETE", {p.method for p in ordinary})
        self.assertIn("DELETE", {p.method for p in unsafe})
        self.assertFalse(any(p.headers == (("X-HTTP-Method-Override", "PUT"),)
                             for p in ordinary))
        self.assertTrue(any(p.headers == (("X-HTTP-Method-Override", "PUT"),)
                            for p in unsafe))

    def test_secret_is_redacted_in_json(self):
        result = asyncio.run(tool.run(self.args(
            "/admin", "--checks", "auth", "--basic", "user:secret"
        )))[0]
        self.assertNotIn("user:secret", json.dumps(result))
        self.assertNotIn("dXNlcjpzZWNyZXQ=", json.dumps(result))

    def test_cli_url_list_json_and_request_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            urls = Path(directory) / "urls.txt"
            output = Path(directory) / "results.json"
            urls.write_text(self.base + "/admin\n" + self.base + "/fake\n")
            with redirect_stdout(StringIO()):
                exit_code = tool.main([
                    "-L", str(urls), "--checks", "headers", "--max-requests", "1",
                    "--rate", "0", "--json", str(output),
                ])
            results = json.loads(output.read_text())
            self.assertEqual(exit_code, 0)
            self.assertEqual(len(results), 2)
            self.assertTrue(all(result["probes"] == 1 for result in results))

    def test_response_size_is_bounded(self):
        args = self.args("/big", "--checks", "protocol", "--max-response-bytes", "64")
        result = asyncio.run(tool.run(args))[0]
        self.assertEqual(result["baseline"]["length"], 64)
        self.assertTrue(result["baseline"]["truncated"])
        raw = tool.send_raw_path(
            tool.Probe("paths", "raw", "GET", self.base + "/big", raw_path=True),
            {}, 2, True, 64,
        )
        self.assertEqual(raw.length, 64)
        self.assertTrue(raw.truncated)

    def test_success_marker_after_64k_is_seen(self):
        result = asyncio.run(tool.run(self.args(
            "/late", "--checks", "headers", "--success-regex", "LATE_SECRET"
        )))[0]
        self.assertTrue(any(f["classification"] == "confirmed" for f in result["findings"]))

    def test_generic_header_response_is_filtered_by_probe_control(self):
        result = asyncio.run(tool.run(self.args(
            "/generic", "--checks", "headers", "--header-variant", "X-Generic: yes"
        )))[0]
        self.assertFalse(any(f["name"] == "custom X-Generic #1" for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
