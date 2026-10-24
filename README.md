# FuzzHTTPBypass

FuzzHTTPBypass checks whether small HTTP request changes alter access to a URL.
It is intended for authorized testing and CTFs. A response change is not proof
of access: use a protected-content marker to confirm a result.

## Install

```sh
python3 -m pip install .
```

Python 3.10 or later is required. Wfuzz is no longer required. Install
`.[http2]` for HTTP/2, `.[socks]` for SOCKS proxies, or `.[ntlm]` for NTLM.

## Examples

```sh
fuzzhttpbypass -u https://example.test/admin --success-regex 'Admin Dashboard'
fuzzhttpbypass -L urls.txt --rate 2 --concurrency 2 --json results.json
fuzzhttpbypass -u https://example.test/admin --header 'Authorization: Bearer TOKEN' --cookie 'session=VALUE'
fuzzhttpbypass -u https://example.test/admin --checks paths headers -i 10.0.0.1
fuzzhttpbypass -u https://example.test/api/admin -X POST -d '{"action":"read"}' --header 'Content-Type: application/json'
fuzzhttpbypass -u https://example.test/admin --checks auth --bearer TOKEN --cookie-value admin
fuzzhttpbypass -u https://example.test/admin --path-variant /ADMIN --header-variant 'X-Allow: yes'
fuzzhttpbypass --request-file captured-request.txt --request-proto https --success-regex 'Private Data'
```

The tool sends a baseline GET and a random missing sibling path, then probes
the selected categories. It does not follow redirects. Each finding is sent
again before reporting it. For header, method, authentication and protocol
findings, it also tries the same variation on a missing path to reject generic
responses.

| Classification | Meaning |
| --- | --- |
| `confirmed` | A repeatable 2xx response contains `--success-regex`, absent from the baseline and missing-path control. |
| `candidate` | A repeatable response changes a denied or redirecting baseline to a 2xx response with content or a new cookie name, and differs from the missing-path control. Verify it manually. |
| `changed` | A repeatable response differs but does not establish access. Shown with `--show-changed` or in JSON. |

Results include the probe category, method, URL, added headers, status,
redirect location, size, SHA-256 digest, and whether the body changed between
repeats. Cookie names and a change indicator are included; cookie and
credential values are redacted.
The baseline's response cookies are carried into subsequent requests unless a
`--cookie` or Cookie header is supplied.

## Checks

- **Paths:** trailing and duplicate slashes, dot and parent segments, encoded
  separators, semicolon and dot suffixes, and case changes.
- **Methods:** HEAD, POST, OPTIONS, TRACE, PROPFIND, an invented method, and
  common method override headers. `--unsafe-methods` adds PUT, PATCH, DELETE.
- **Headers:** forwarding IP, host, protocol and path headers, plus Referer,
  Origin and User-Agent variants. `-i` adds an IP candidate.
- **Auth:** Basic or NTLM credentials explicitly supplied with repeated
  `--basic USER:PASS`, `--ntlm DOMAIN\USER:PASS`, or `--bearer TOKEN`.
  `--cookie-value` replaces each observed cookie value in turn. The tool
  does not guess passwords by default.
- **Protocol:** Accept, Content-Type, Range, Cache-Control, and
  X-Requested-With variants.

Use `--checks` to select categories, `--max-requests` to cap probes per URL,
`--rate` and `--concurrency` to bound traffic, and `--timeout` to limit
individual requests. Responses are capped at 1 MiB by default; adjust with
`--max-response-bytes`. `-b` disables TLS certificate verification.
`--path-variant` and `--header-variant` add application specific probes.
The `--request-file` option imports an HTTP/1.0 or HTTP/1.1 request line,
headers, and body from a captured request. The tool recalculates
`Content-Length`; it rejects duplicate or folded headers and
`Transfer-Encoding` templates, which require exact wire-level handling.
Literal dot path probes use Python's HTTP/1.1 client, which requires a direct
connection; when `--proxy` is set, those probes appear as request errors in
the JSON report. NTLM probes also use HTTP/1.1.

The old Wfuzz `-W` filter and `-f` examples are removed. Use
`--success-regex`, `--show-changed`, and the JSON report.

## Testing

```sh
python3 -m unittest discover -s tests -v
```

Tests use a local HTTP server; they do not contact external targets.
