# FuzzHTTPBypass

This tool use fuuzzing to try to bypass unknown authentication methods, who knows...

This is mainly for CTFs.

## Installation

You only need to have installed wfuzz

```bash
pip3 install wfuzz
```

## Features

- [+] Get and show GET code, cookies sent by server and contentent if redirect (all of this in the provided url)
- [+] Fuzz **HTTP Verbs(Methods)**: GET, HEAD, POST, DELETE, CONNECT, OPTIONS, TRACE, PUT, INVENTED
- [+] Fuzz **HTTP Headers**: Forwarded, X-Forwarded-For, X-ProxyUser-Ip, Referer, User-Agent, Cookies
- [+] Fuzz **HTTP Authentication**: Basic and NTLM
- [+] Filter by code or by strings (appearing or not)
- [+] Autocontained

## Example

Show responses that do not return code 403 of url http://example.com/index.php

`./fuzzhttpbypass.py -f notcontains,403 -u http://example.com/index.php`

Responses that do not contains the code 240 (show all) in http://example.com/index.php

`./fuzzhttpbypass.py -f notcontains,240 -u http://example.com/index.php`

Responses that do not contains the word "Invalid" in http://example.com/index.php (Currently, the Wfuzz API has problems with spaces so whe can't use them)

`./fuzzhttpbypass.py -f notcontains,Invalid -u http://example.com/index.php`

