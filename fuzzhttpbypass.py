#!/usr/bin/env python3
"""Probe HTTP access controls with explainable request variations."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import math
import re
import secrets
import sys
import time
from copy import copy
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
VOLATILE_FIELD = re.compile(
    r"(?i)(\b(?:nonce|timestamp|request[_-]?id|trace[_-]?id|csrf(?:token)?)"
    r"\b\s*[:=]\s*['\"]?)[A-Za-z0-9._:/+-]+"
)


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
        result = {key: value for key, value in asdict(self).items() if key not in ("body", "cookies")}
        result["set_cookie_names"] = sorted(self.cookies)
        return result


def validate_url(url: str) -> str:
    if any(character in url for character in "\r\n\t"):
        raise ValueError("URL contains a control character")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"Expected an absolute HTTP(S) URL: {url}")
    if parts.username or parts.password:
        raise ValueError("Put credentials in --basic rather than the URL")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in URL: {url}") from exc
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


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
    if "." not in leaf:
        variants.update({
            "index": clean + "/index",
            "index php": clean + "/index.php",
            "index html": clean + "/index.html",
        })
    if leaf:
        encoded = "".join(f"%{byte:02X}" for byte in leaf[0].encode("utf-8"))
        variants["encoded first character"] = parent + "/" + encoded + leaf[1:]
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


def load_request_file(path: Path, protocol: str) -> tuple[str, str, bytes, list[str]]:
    """Read an HTTP/1.x request template, letting the client frame its body."""
    content = path.read_bytes()
    if b"\r\n\r\n" in content:
        head, body = content.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
    elif b"\n\n" in content:
        head, body = content.split(b"\n\n", 1)
        lines = head.split(b"\n")
    else:
        raise ValueError("Request file needs a blank line after its headers")
    try:
        method, target, version = lines[0].decode("ascii").split()
    except (UnicodeError, ValueError, IndexError) as exc:
        raise ValueError("Invalid HTTP request line in request file") from exc
    if not re.fullmatch(r"HTTP/1\.[01]", version):
        raise ValueError("Request file must contain an HTTP/1.0 or HTTP/1.1 request")
    parsed = []
    seen = set()
    content_length = None
    host = None
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t") or b":" not in line:
            raise ValueError("Invalid or folded header in request file")
        name, value = line.split(b":", 1)
        try:
            header_name = name.decode("ascii").strip()
            header_value = value.decode("latin-1").strip()
        except UnicodeError as exc:
            raise ValueError("Invalid header in request file") from exc
        lowered = header_name.lower()
        if lowered in seen:
            raise ValueError(f"Duplicate {header_name} header in request file")
        seen.add(lowered)
        if lowered == "transfer-encoding":
            raise ValueError("Transfer-Encoding request templates are unsupported")
        if lowered == "content-length":
            try:
                content_length = int(header_value)
            except ValueError as exc:
                raise ValueError("Invalid Content-Length in request file") from exc
        else:
            parsed.append(f"{header_name}: {header_value}")
        if lowered == "host":
            host = header_value
    if content_length is not None and content_length != len(body):
        raise ValueError("Content-Length does not match request body")
    if target.startswith(("http://", "https://")):
        url = target
    elif target.startswith("/") and host:
        url = f"{protocol}://{host}{target}"
    else:
        raise ValueError("Request file needs an absolute URL or origin path with Host")
    return validate_url(url), method, body, parsed


def generate_probes(url: str, checks: set[str], ips: list[str], basic: list[str],
                    unsafe_methods: bool = False, base_method: str = "GET",
                    base_body: bytes | None = None,
                    ntlm: list[str] | None = None, bearer: list[str] | None = None,
                    custom_paths: list[str] | None = None,
                    custom_headers: list[tuple[str, str]] | None = None,
                    cookies: dict[str, str] | None = None,
                    cookie_values: list[str] | None = None,
                    form_body: bool = False) -> list[Probe]:
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
                query = (parts.query + "&" if parts.query else "") + "_method=" + override
                add("methods", f"{method} with _method={override}", method,
                    probe_url=urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))
                if method == "POST" and (base_body is None or form_body):
                    content = base_body or b""
                    separator = b"&" if content else b""
                    add("methods", f"POST form _method={override}", "POST",
                        headers=(("Content-Type", "application/x-www-form-urlencoded"),),
                        body=content + separator + f"_method={override}".encode())

    if "headers" in checks:
        for ip in dict.fromkeys([
            "127.0.0.1", "127.0.0.2", "127.1", "localhost",
            "::1", "::ffff:127.0.0.1",
        ] + ips):
            for header in IP_HEADERS:
                add("headers", f"{header}: {ip}", headers=((header, ip),))
            forwarded_ip = f"[{ip}]" if ":" in ip else ip
            add("headers", f"Forwarded for={ip}",
                headers=(("Forwarded", f'for="{forwarded_ip}"'),))
            add("headers", f"X-Forwarded-For chain ending {ip}",
                headers=(("X-Forwarded-For", f"198.51.100.1, {ip}"),))
            add("headers", f"X-Forwarded-For chain starting {ip}",
                headers=(("X-Forwarded-For", f"{ip}, 198.51.100.1"),))
        host_values = ["localhost", "127.0.0.1", parts.netloc]
        if parts.hostname and ":" not in parts.hostname:
            host_values.append(parts.hostname)
        for value in dict.fromkeys(host_values):
            for header in ("Host", "X-Forwarded-Host", "X-Forwarded-Server",
                           "X-HTTP-Host-Override", "X-Host"):
                add("headers", f"{header}: {value}", headers=((header, value),))
            forwarded_host = f'"{value}"' if ":" in value else value
            add("headers", f"Forwarded host={value}",
                headers=(("Forwarded", f"host={forwarded_host}"),))
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
    if (observation.status, observation.location, observation.digest, observation.cookies) == (
            baseline.status, baseline.location, baseline.digest, baseline.cookies):
        return None
    if observation.status in (401, 403, 404) or observation.status >= 500:
        return None
    if resembles_control(observation, control):
        return None
    new_cookie_names = set(observation.cookies) - set(baseline.cookies)
    if (baseline.status in (401, 403, 404) or 300 <= baseline.status < 400) \
            and 200 <= observation.status < 300 \
            and (observation.length > 0 or new_cookie_names):
        return "candidate"
    return "changed"


def resembles_control(observation: Observation, control: Observation) -> bool:
    """Suppress identical generic pages, allowing common volatile field values."""
    if observation.location != control.location or set(observation.cookies) != set(control.cookies):
        return False
    if observation.digest == control.digest:
        return True
    if not observation.body or not control.body:
        return False
    return (
        VOLATILE_FIELD.sub(r"\1<VALUE>", observation.body)
        == VOLATILE_FIELD.sub(r"\1<VALUE>", control.body)
    )


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
        self.headers = httpx.Headers({"Accept-Encoding": "identity"})
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
            try:
                extensions = {}
                if probe.raw_path:
                    parts = urlsplit(probe.url)
                    target = parts.path or "/"
                    if parts.query:
                        target += "?" + parts.query
                    if (self.args.proxy and urlsplit(self.args.proxy).scheme in ("http", "https")
                            and parts.scheme == "http"):
                        target = f"{parts.scheme}://{parts.netloc}{target}"
                    extensions["target"] = target.encode("ascii")
                request = client.build_request(
                    probe.method, probe.url, headers=headers, content=probe.body,
                    extensions=extensions,
                )
                response = await client.send(request, stream=True, follow_redirects=False)
                try:
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
                finally:
                    await response.aclose()
            except (httpx.HTTPError, ValueError, UnicodeError) as exc:
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
                                 effective_cookies, self.args.cookie_value,
                                 self.headers.get("content-type", "").lower().startswith(
                                     "application/x-www-form-urlencoded"
                                 ))
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
                if resembles_control(result, control_result):
                    return
            findings.append({
                "classification": kind, "category": probe.category, "name": probe.name,
                "stable_body": repeat.digest == result.digest,
                "cookie_changed": result.cookies != baseline.cookies,
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
    target.add_argument("--request-file", type=Path, help="HTTP/1.x request template")
    p.add_argument("--request-proto", choices=("http", "https"), default="https",
                   help="scheme for an origin-form request file (default: https)")
    p.add_argument("-i", "--ip", action="append", default=[], help="additional forwarded IP; repeatable")
    p.add_argument("-b", "--bypass-verification", action="store_true", help="disable TLS verification")
    p.add_argument("--header", action="append", default=[], help="base request Name: Value; repeatable")
    p.add_argument("--cookie", action="append", default=[], help="base Cookie data; repeatable")
    p.add_argument("--basic", action="append", default=[], metavar="USER:PASS", help="Basic credential")
    p.add_argument("--bearer", action="append", default=[], metavar="TOKEN", help="Bearer token")
    p.add_argument("--ntlm", action="append", default=[], metavar="DOMAIN\\USER:PASS",
                   help="NTLM credential; requires the ntlm extra")
    p.add_argument("-X", "--method", help="baseline HTTP method")
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
    args = copy(args)
    if args.request_file:
        if args.data is not None or args.data_file:
            raise ValueError("Use the request file body without -d or --data-file")
        url, file_method, body, file_headers = load_request_file(
            args.request_file, args.request_proto,
        )
        args.url = url
        args.method = args.method or file_method
        args.data = body
        args.header = file_headers + args.header
    args.method = args.method or "GET"
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
