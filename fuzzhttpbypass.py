#!/usr/bin/env python3
"""Probe HTTP access controls with explainable request variations."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import http.client
import ipaddress
import json
import math
import re
import secrets
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

IP_HEADERS = (
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Client-IP",
    "True-Client-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-ProxyUser-Ip", "Forwarded-For", "X-Cluster-Client-IP",
)
PATH_HEADERS = ("X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Uri", "X-Original-URI")
PATH_HEADERS_LOWER = frozenset(header.lower() for header in PATH_HEADERS)
OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
CHECKS = ("paths", "methods", "headers", "auth", "protocol")


@dataclass(frozen=True)
class Probe:
    category: str
    name: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None
    raw_path: bool = False
    ntlm: tuple[str, str] | None = None


@dataclass
class Observation:
    status: int | None = None
    location: str | None = None
    length: int = 0
    digest: str = ""
    body: str = ""
    error: str | None = None
    elapsed_ms: int = 0
    truncated: bool = False
    cookies: dict[str, str] = field(default_factory=dict)

    def public(self) -> dict:
        return {key: value for key, value in asdict(self).items() if key not in ("body", "cookies")}


def validate_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"Expected an absolute HTTP(S) URL: {url}")
    if parts.username or parts.password:
        raise ValueError("Put credentials in --basic rather than the URL")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in URL: {url}") from exc
    return url


def with_path(url: str, path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def control_url(url: str, token: str) -> str:
    path = urlsplit(url).path or "/"
    parent = path.rsplit("/", 1)[0]
    return with_path(url, f"{parent}/fuzzhttpbypass-{token}")


def path_variants(url: str) -> list[tuple[str, str]]:
    path = urlsplit(url).path or "/"
    if path == "/":
        return []
    clean = path.rstrip("/")
    parent, _, leaf = clean.rpartition("/")
    variants = {
        "trailing slash": clean + "/",
        "double slash": parent + "//" + leaf,
        "dot segment": parent + "/./" + leaf,
        "parent segment": parent + "/x/../" + leaf,
        "encoded dot segment": parent + "/%2e/" + leaf,
        "encoded slash": parent + "/%2f" + leaf,
        "double encoded slash": parent + "/%252f" + leaf,
        "backslash": parent + "/%5c" + leaf,
        "semicolon parameter": clean + ";/",
        "semicolon suffix": clean + ";",
        "semicolon path segment": parent + "/..;/" + leaf,
        "dot suffix": clean + ".",
        "dot slash suffix": clean + "/.",
        "encoded dot suffix": clean + "%2e",
        "encoded slash suffix": clean + "%2f",
        "double encoded dot": parent + "/%252e/" + leaf,
        "unicode slash": parent + "/%ef%bc%8f" + leaf,
        "extension suffix": clean + ".json",
        "case change": parent + "/" + leaf.swapcase(),
    }
    if leaf:
        variants["encoded first character"] = parent + f"/%{ord(leaf[0]):02x}{leaf[1:]}"
    return [(name, with_path(url, value)) for name, value in variants.items() if value != path]


def parse_ips(values: list[str]) -> list[str]:
    try:
        return [str(ipaddress.ip_address(value)) for value in values]
    except ValueError as exc:
        raise ValueError(f"Invalid --ip value: {exc}") from exc


def parse_headers(values: list[str]) -> dict[str, str]:
    headers = {}
    for value in values:
        if ":" not in value or "\r" in value or "\n" in value:
            raise ValueError(f"Expected 'Name: Value' for --header: {value!r}")
        name, item = value.split(":", 1)
        if not name.strip():
            raise ValueError(f"Invalid --header: {value!r}")
        headers[name.strip()] = item.strip()
    return headers


def generate_probes(url: str, checks: set[str], ips: list[str], basic: list[str],
                    unsafe_methods: bool = False, base_method: str = "GET",
                    base_body: bytes | None = None,
                    ntlm: list[str] | None = None, bearer: list[str] | None = None,
                    custom_paths: list[str] | None = None,
                    custom_headers: list[tuple[str, str]] | None = None,
                    cookies: dict[str, str] | None = None,
                    cookie_values: list[str] | None = None) -> list[Probe]:
    parts = urlsplit(url)
    path = parts.path or "/"
    probes = []

    def add(category: str, name: str, method: str | None = None, probe_url: str | None = None,
            headers: tuple[tuple[str, str], ...] = (), body: bytes | None = None,
            raw_path: bool = False) -> None:
        probes.append(Probe(category, name, method or base_method, probe_url or url,
                            headers, base_body if body is None else body, raw_path))

    if "paths" in checks:
        for name, value in path_variants(url):
            add("paths", name, probe_url=value,
                raw_path=name in ("dot segment", "parent segment", "dot slash suffix"))
        for value in custom_paths or []:
            if not value.startswith("/") or "\r" in value or "\n" in value or "#" in value:
                raise ValueError("--path-variant must be a path beginning with /")
            candidate_path, separator, candidate_query = value.partition("?")
            candidate_url = urlunsplit((
                parts.scheme, parts.netloc, candidate_path,
                candidate_query if separator else parts.query, "",
            ))
            add("paths", f"custom path: {value}", probe_url=candidate_url,
                raw_path="/./" in candidate_path or "/../" in candidate_path)

    if "methods" in checks:
        methods = ["HEAD", "POST", "OPTIONS", "TRACE", "PROPFIND", "INVENTED"]
        if unsafe_methods:
            methods += ["PUT", "PATCH", "DELETE"]
        for method in methods:
            add("methods", method, method)
        for method in ("GET", "POST"):
            for header in OVERRIDE_HEADERS:
                overrides = ("GET", "POST", "PUT", "PATCH", "DELETE") if unsafe_methods else ("GET", "POST")
                for override in overrides:
                    add("methods", f"{method} with {header}: {override}", method,
                        headers=((header, override),))
            overrides = ("GET", "POST", "PUT", "DELETE") if unsafe_methods else ("GET", "POST")
            for override in overrides:
                delimiter = "&" if parts.query else "?"
                add("methods", f"{method} with _method={override}", method,
                    probe_url=url + delimiter + "_method=" + override)

    if "headers" in checks:
        for ip in dict.fromkeys(["127.0.0.1", "127.0.0.2", "::1"] + ips):
            for header in IP_HEADERS:
                add("headers", f"{header}: {ip}", headers=((header, ip),))
            forwarded_ip = f"[{ip}]" if ":" in ip else ip
            add("headers", f"Forwarded for={ip}",
                headers=(("Forwarded", f'for="{forwarded_ip}"'),))
            add("headers", f"X-Forwarded-For chain ending {ip}",
                headers=(("X-Forwarded-For", f"198.51.100.1, {ip}"),))
            add("headers", f"X-Forwarded-For chain starting {ip}",
                headers=(("X-Forwarded-For", f"{ip}, 198.51.100.1"),))
        for value in ("localhost", "127.0.0.1", parts.hostname or ""):
            for header in ("Host", "X-Forwarded-Host", "X-Forwarded-Server",
                           "X-HTTP-Host-Override", "X-Host"):
                add("headers", f"{header}: {value}", headers=((header, value),))
            add("headers", f"Forwarded host={value}",
                headers=(("Forwarded", f"host={value}"),))
        for value in ("http", "https"):
            for header in ("X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Url-Scheme"):
                add("headers", f"{header}: {value}", headers=((header, value),))
            add("headers", f"Forwarded proto={value}", headers=(("Forwarded", f"proto={value}"),))
        for value in ("80", "443", str(parts.port or (443 if parts.scheme == "https" else 80))):
            add("headers", f"X-Forwarded-Port: {value}",
                headers=(("X-Forwarded-Port", value),))
        for header in PATH_HEADERS:
            for value in (path, "/"):
                add("headers", f"{header}: {value}", probe_url=with_path(url, "/"),
                    headers=((header, value),))
        for value in (path, "/"):
            add("headers", f"X-Forwarded-Prefix: {value}",
                headers=(("X-Forwarded-Prefix", value),))
        for agent in ("Googlebot", "bingbot", "Mozilla/5.0"):
            add("headers", f"User-Agent: {agent}", headers=(("User-Agent", agent),))
        add("headers", "Referer: target", headers=(("Referer", url),))
        add("headers", "Origin: target",
            headers=(("Origin", f"{parts.scheme}://{parts.netloc}"),))
        for index, (name, value) in enumerate(custom_headers or [], 1):
            add("headers", f"custom {name} #{index}", headers=((name, value),))

    if "auth" in checks:
        for index, credential in enumerate(basic, 1):
            if ":" not in credential:
                raise ValueError("--basic must be USER:PASS")
            encoded = base64.b64encode(credential.encode()).decode()
            add("auth", f"Basic credential {index}",
                headers=(("Authorization", "Basic " + encoded),))
        for index, credential in enumerate(ntlm or [], 1):
            if ":" not in credential:
                raise ValueError("--ntlm must be DOMAIN\\USER:PASS")
            username, password = credential.split(":", 1)
            probes.append(Probe("auth", f"NTLM credential {index}", base_method, url,
                                body=base_body, ntlm=(username, password)))
        for index, token in enumerate(bearer or [], 1):
            if "\r" in token or "\n" in token:
                raise ValueError("Invalid --bearer token")
            add("auth", f"Bearer token {index}",
                headers=(("Authorization", "Bearer " + token),))
        for name in cookies or {}:
            for index, value in enumerate(cookie_values or [], 1):
                if "\r" in value or "\n" in value:
                    raise ValueError("Invalid --cookie-value")
                changed = dict(cookies or {})
                changed[name] = value
                add("auth", f"Cookie {name} value #{index}",
                    headers=(("Cookie", "; ".join(f"{k}={v}" for k, v in changed.items())),))

    if "protocol" in checks:
        for header, value in (("Accept", "*/*"), ("Content-Type", "application/json"),
                              ("Range", "bytes=0-0"), ("Cache-Control", "no-cache"),
                              ("X-Requested-With", "XMLHttpRequest")):
            add("protocol", f"{header}: {value}", headers=((header, value),))

    seen = set()
    unique = []
    for probe in probes:
        key = (probe.method, probe.url, probe.headers, probe.body, probe.raw_path, probe.ntlm)
        if key not in seen and key != (base_method, url, (), base_body, False, None):
            seen.add(key)
            unique.append(probe)
    return unique


def classify(observation: Observation, baseline: Observation, control: Observation,
             success: re.Pattern[str] | None) -> str | None:
    if observation.error or observation.status is None:
        return None
    if (success and 200 <= observation.status < 300 and success.search(observation.body)
            and not success.search(baseline.body)
            and not success.search(control.body)):
        return "confirmed"
    if (observation.status, observation.location, observation.digest) == (
            baseline.status, baseline.location, baseline.digest):
        return None
    if observation.status in (401, 403, 404) or observation.status >= 500:
        return None
    if observation.digest == control.digest and observation.location == control.location:
        return None
    if (baseline.status in (401, 403, 404) or 300 <= baseline.status < 400) \
            and 200 <= observation.status < 300 \
            and observation.length > 0:
        return "candidate"
    return "changed"


def send_raw_path(probe: Probe, headers: dict[str, str], timeout: float,
                  verify: bool, max_bytes: int) -> Observation:
    """Use http.client for literal /./ and /../ paths that HTTPX normalizes."""
    parts = urlsplit(probe.url)
    connection_class = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": timeout}
    if parts.scheme == "https":
        kwargs["context"] = ssl.create_default_context() if verify else ssl._create_unverified_context()
    connection = connection_class(parts.hostname, parts.port, **kwargs)
    started = time.monotonic()
    try:
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        connection.request(probe.method, target, body=probe.body, headers=headers)
        response = connection.getresponse()
        content = response.read(max_bytes + 1)
        truncated = len(content) > max_bytes
        content = content[:max_bytes]
        return Observation(
            status=response.status, location=response.getheader("Location"),
            length=len(content), digest=hashlib.sha256(content).hexdigest(),
            body=content.decode("utf-8", errors="replace"),
            elapsed_ms=round((time.monotonic() - started) * 1000),
            truncated=truncated,
        )
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return Observation(error=f"{type(exc).__name__}: {exc}",
                           elapsed_ms=round((time.monotonic() - started) * 1000))
    finally:
        connection.close()


def send_ntlm(probe: Probe, headers: dict[str, str], timeout: float, verify: bool,
              proxy: str | None, max_bytes: int) -> Observation:
    """Run one connection-bound NTLM handshake with requests-ntlm."""
    try:
        import requests
        from requests_ntlm import HttpNtlmAuth
    except ImportError:
        return Observation(error="NTLM requires: pip install 'fuzzhttpbypass[ntlm]'")
    started = time.monotonic()
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.auth = HttpNtlmAuth(*probe.ntlm)
            response = session.request(
                probe.method, probe.url, headers=headers, data=probe.body,
                timeout=timeout, verify=verify, allow_redirects=False,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                stream=True,
            )
            chunks = []
            size = 0
            truncated = False
            for chunk in response.iter_content(chunk_size=8192):
                if size + len(chunk) > max_bytes:
                    chunks.append(chunk[:max_bytes - size])
                    truncated = True
                    break
                chunks.append(chunk)
                size += len(chunk)
            content = b"".join(chunks)
            response.close()
            return Observation(
                status=response.status_code, location=response.headers.get("Location"),
                length=len(content), digest=hashlib.sha256(content).hexdigest(),
                body=content.decode(response.encoding or "utf-8", errors="replace"),
                elapsed_ms=round((time.monotonic() - started) * 1000),
                truncated=truncated,
                cookies=response.cookies.get_dict(),
            )
    except requests.RequestException as exc:
        return Observation(error=f"{type(exc).__name__}: {exc}",
                           elapsed_ms=round((time.monotonic() - started) * 1000))


class Scanner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.headers = {"Accept-Encoding": "identity"}
        self.headers.update(parse_headers(args.header))
        if args.cookie:
            self.headers["Cookie"] = "; ".join(args.cookie)
        self.success = re.compile(args.success_regex, re.IGNORECASE) if args.success_regex else None
        self.semaphore = asyncio.Semaphore(args.concurrency)
        self.rate_lock = asyncio.Lock()
        self.next_request = 0.0

    async def request(self, client: httpx.AsyncClient, probe: Probe,
                      cookies: dict[str, str] | None = None) -> Observation:
        async with self.semaphore:
            if self.args.rate:
                async with self.rate_lock:
                    delay = max(0, self.next_request - time.monotonic())
                    if delay:
                        await asyncio.sleep(delay)
                    self.next_request = time.monotonic() + 1 / self.args.rate
            headers = httpx.Headers(self.headers)
            if "cookie" not in headers:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())
            headers.update(dict(probe.headers))
            started = time.monotonic()
            if probe.ntlm:
                return await asyncio.to_thread(send_ntlm, probe, dict(headers), self.args.timeout,
                                               not self.args.bypass_verification, self.args.proxy,
                                               self.args.max_response_bytes)
            if probe.raw_path:
                if self.args.proxy:
                    return Observation(error="literal path probes require a direct connection")
                return await asyncio.to_thread(send_raw_path, probe, dict(headers), self.args.timeout,
                                               not self.args.bypass_verification,
                                               self.args.max_response_bytes)
            try:
                async with client.stream(probe.method, probe.url, headers=headers,
                                         content=probe.body, follow_redirects=False) as response:
                    chunks = []
                    size = 0
                    truncated = False
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        if size + len(chunk) > self.args.max_response_bytes:
                            chunks.append(chunk[:self.args.max_response_bytes - size])
                            truncated = True
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                    content = b"".join(chunks)
                    return Observation(
                        status=response.status_code, location=response.headers.get("location"),
                        length=len(content), digest=hashlib.sha256(content).hexdigest(),
                        body=content.decode(response.encoding or "utf-8", errors="replace"),
                        elapsed_ms=round((time.monotonic() - started) * 1000),
                        truncated=truncated, cookies=dict(response.cookies),
                    )
            except (httpx.HTTPError, ValueError) as exc:
                return Observation(error=f"{type(exc).__name__}: {exc}",
                                   elapsed_ms=round((time.monotonic() - started) * 1000))

    async def scan_url(self, client: httpx.AsyncClient, url: str) -> dict:
        baseline = await self.request(client, Probe("baseline", "baseline", self.args.method, url,
                                                   body=self.args.data))
        if baseline.error:
            return {"url": url, "error": baseline.error, "findings": []}
        control = await self.request(client, Probe("control", "missing sibling", self.args.method,
                                                   control_url(url, secrets.token_hex(6)),
                                                   body=self.args.data), baseline.cookies)
        if control.error:
            return {"url": url, "error": "control request: " + control.error, "findings": []}
        effective_cookies = dict(baseline.cookies)
        cookie_header = httpx.Headers(self.headers).get("cookie", "")
        for pair in cookie_header.split(";"):
            if "=" in pair:
                name, value = pair.strip().split("=", 1)
                effective_cookies[name] = value
        custom_headers = [
            next(iter(parse_headers([value]).items())) for value in self.args.header_variant
        ]
        probes = generate_probes(url, set(self.args.checks), parse_ips(self.args.ip),
                                 self.args.basic, self.args.unsafe_methods,
                                 self.args.method, self.args.data, self.args.ntlm,
                                 self.args.bearer, self.args.path_variant,
                                 custom_headers,
                                 effective_cookies, self.args.cookie_value)
        if self.args.max_requests:
            probes = probes[:self.args.max_requests]
        findings = []
        errors = []

        async def run_probe(probe: Probe) -> None:
            result = await self.request(client, probe, baseline.cookies)
            if result.error:
                errors.append({"probe": probe.name, "error": result.error})
                return
            kind = classify(result, baseline, control, self.success)
            if not kind:
                return
            repeat = await self.request(client, probe, baseline.cookies)
            if repeat.error or (repeat.status, repeat.location) != (
                    result.status, result.location):
                return
            if classify(repeat, baseline, control, self.success) != kind:
                return
            path_override = any(name.lower() in PATH_HEADERS_LOWER for name, _ in probe.headers)
            if probe.category in ("headers", "methods", "auth", "protocol") and not path_override:
                probe_control = Probe(
                    "control", "same variation on missing path", probe.method,
                    control_url(url, secrets.token_hex(6)), probe.headers, probe.body,
                    ntlm=probe.ntlm,
                )
                control_result = await self.request(client, probe_control, baseline.cookies)
                if control_result.error:
                    errors.append({"probe": probe.name, "error": "control: " + control_result.error})
                    return
                if self.success and self.success.search(control_result.body):
                    return
                if (control_result.status, control_result.digest, control_result.location) == (
                        result.status, result.digest, result.location):
                    return
            findings.append({
                "classification": kind, "category": probe.category, "name": probe.name,
                "stable_body": repeat.digest == result.digest,
                "request": {"method": probe.method, "url": probe.url,
                            "headers": {k: "<redacted>" if re.search(
                                r"auth|cookie|token|secret|api.key", k, re.IGNORECASE
                            ) else v for k, v in probe.headers}},
                "response": result.public(),
            })

        await asyncio.gather(*(run_probe(probe) for probe in probes))
        findings.sort(key=lambda item: ({"confirmed": 0, "candidate": 1, "changed": 2}[
            item["classification"]], item["category"], item["name"]))
        return {"url": url, "baseline": baseline.public(), "control": control.public(),
                "probes": len(probes), "findings": findings, "errors": errors}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", "--url", help="HTTP(S) URL to test")
    target.add_argument("-L", "--url-list", type=Path, help="one HTTP(S) URL per line")
    p.add_argument("-i", "--ip", action="append", default=[], help="additional forwarded IP; repeatable")
    p.add_argument("-b", "--bypass-verification", action="store_true", help="disable TLS verification")
    p.add_argument("--header", action="append", default=[], help="base request Name: Value; repeatable")
    p.add_argument("--cookie", action="append", default=[], help="base Cookie data; repeatable")
    p.add_argument("--basic", action="append", default=[], metavar="USER:PASS", help="Basic credential")
    p.add_argument("--bearer", action="append", default=[], metavar="TOKEN", help="Bearer token")
    p.add_argument("--ntlm", action="append", default=[], metavar="DOMAIN\\USER:PASS",
                   help="NTLM credential; requires the ntlm extra")
    p.add_argument("-X", "--method", default="GET", help="baseline HTTP method")
    data = p.add_mutually_exclusive_group()
    data.add_argument("-d", "--data", help="baseline request body")
    data.add_argument("--data-file", type=Path, help="read baseline request body from file")
    p.add_argument("--success-regex", help="protected content regex for confirmed findings")
    p.add_argument("--path-variant", action="append", default=[], help="extra path to try; repeatable")
    p.add_argument("--header-variant", action="append", default=[], metavar="NAME: VALUE",
                   help="extra header to try; repeatable")
    p.add_argument("--cookie-value", action="append", default=[], help="replace each response cookie with value")
    p.add_argument("--checks", nargs="+", choices=CHECKS, default=list(CHECKS))
    p.add_argument("--unsafe-methods", action="store_true", help="include PUT, PATCH and DELETE")
    p.add_argument("--concurrency", type=int, default=5)
    p.add_argument("--rate", type=float, default=5.0, help="maximum requests per second; 0 disables")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--max-response-bytes", type=int, default=1048576)
    p.add_argument("--max-requests", type=int, default=0, help="maximum probes per URL; 0 disables")
    p.add_argument("--proxy", help="HTTP or SOCKS proxy URL")
    p.add_argument("--http2", action="store_true")
    p.add_argument("--json", type=Path, help="write full results as JSON")
    p.add_argument("--show-changed", action="store_true")
    return p


async def run(args: argparse.Namespace) -> list[dict]:
    args.method = args.method.upper()
    if not re.fullmatch(r"[A-Z!#$%&'*+.^_`|~-]+", args.method):
        raise ValueError("Invalid HTTP method")
    args.data = args.data.encode() if isinstance(args.data, str) else (
        args.data if args.data is not None else
        args.data_file.read_bytes() if args.data_file else None)
    scanner = Scanner(args)
    urls = [args.url] if args.url else [
        line.strip() for line in args.url_list.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    urls = [validate_url(url) for url in urls]
    if not urls:
        raise ValueError("URL list is empty")
    results = []
    for url in urls:
        async with httpx.AsyncClient(verify=not args.bypass_verification, timeout=args.timeout,
                                     proxy=args.proxy, http2=args.http2, trust_env=False) as client:
            results.append(await scanner.scan_url(client, url))
    return results


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if (args.concurrency < 1 or not math.isfinite(args.rate) or args.rate < 0
            or not math.isfinite(args.timeout) or args.timeout <= 0
            or args.max_requests < 0 or args.max_response_bytes < 1):
        parser().error("invalid concurrency, rate, timeout, request cap, or response size cap")
    try:
        results = asyncio.run(run(args))
    except (ValueError, OSError, re.error, ImportError, httpx.HTTPError) as exc:
        parser().error(str(exc))
    for result in results:
        print(f"{result['url']}: {result.get('probes', 0)} probes")
        if "error" in result:
            print(f"  error: {result['error']}")
            continue
        print(f"  baseline {result['baseline']['status']}; control {result['control']['status']}")
        for finding in result["findings"]:
            if finding["classification"] == "changed" and not args.show_changed:
                continue
            print(f"  {finding['classification']:9} {finding['category']}: {finding['name']} "
                  f"=> {finding['response']['status']}")
        if result["errors"]:
            print(f"  {len(result['errors'])} request errors (see --json)")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2) + "\n")
    return 1 if any("error" in result or result.get("errors") for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
