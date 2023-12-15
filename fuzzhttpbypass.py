#!/usr/bin/python3

import argparse
import string
import socket
import sys
import requests
import os
import signal

from wfuzz.api import get_session
from bs4 import BeautifulSoup, Comment

def parse_main_args(args=None):
    parser = argparse.ArgumentParser(description='Simple web fuzzer.')
    parser.add_argument('-u', '--url', required=True, help='URL to test (http://example.com/index.php)')
    parser.add_argument('-f', '--filter', required=True,
                        help='Select filter if form: contains/notcontains,<code>/<string> (--filter contains,200) (--filter notcontains "Invalid Access")')
    parser.add_argument('-i', '--ip', default="", help='Specify IP for impersonation via HTTP headers')
    
    args = parser.parse_args()
    return args.url, args.ip, args.filter

def color_print(to_print):
    colors = {'[i] ': '\033[1;33;40m', '[+] ': '\033[1;32;40m', '[c] ': '\033[1;34;40m', '[-] ': '\033[0;31;47m'}
    for prefix, color_code in colors.items():
        if prefix in to_print:
            print(color_code + to_print + '\033[0m')
            return
    print(to_print)

def get_parts_from_url(url):
    proto, rest = url.split("//")
    domain = rest.split("/")[0]
    path = "/" + "/".join(rest.split("/")[1:]) if len(rest.split("/")) > 1 else "/"
    return proto, domain, path

def get_ips_from_domain(domain):
    domain = domain.split(":")[0]
    ips = socket.gethostbyname_ex(domain)[2]
    color_print("[i] Found IP(s) for domain {}: {}".format(domain, ", ".join(ips)))
    return ips

def is_ip(param):
    return not any(c.isalpha() for c in param) and param.count(".") == 4

def fuzz_paths(url, filter2use, proxy):
    color_print("[+] Fuzzing Path variations...")
    paths = "%2e-%252e-%ef%bc%8f"
    url_parts = url.split("/")
    url_parts.insert(-1, "FUZZ")
    url = "/".join(url_parts)
    wfuzz(["-z list," + paths], filter2use, proxy, "", url)

def fuzz_methods(url, filter2use, proxy):
    color_print("[+] Fuzzing HTTP Verbs (methods)...")
    methods = "GET-HEAD-POST-DELETE-CONNECT-OPTIONS-TRACE-PUT-INVENTED"
    wfuzz(["-z list," + methods], filter2use, proxy, " -X FUZZ", url)

    proto, domain, path = get_parts_from_url(url)
    if path.count("/") == 1:
        for p in ["index.php", "index", "index.html", "index.asp", "index.aspx", ""]:
            if path.split("/")[1] != p:
                wfuzz(["-z list," + methods], filter2use, proxy, "-X FUZZ", proto + "//" + domain + "/" + p)

def fuzz_headers(url, ips, filter2use, proxy, cookies, passwords):
    color_print("[+] Fuzzing HTTP Headers...")
    headers_to_fuzz = [
        ('Forwarded', 'for=FUZZ;by=FUZ2Z;host=FUZ3Z;proto=FUZ4Z'),
        ('X-Forwarded-For', 'FUZZ'),
        ('X-Originating-IP', 'FUZZ'),
        ('X-Remote-IP', 'FUZZ'),
        ('X-Remote-Addr', 'FUZZ'),
        ('X-ProxyUser-Ip', 'FUZZ'),
        ('Referer', 'FUZZ'),
        ('User-Agent', 'FUZZ')
    ]

    for header, fuzz_values in headers_to_fuzz:
        wfuzz(["-z list," + fuzz_values], filter2use, proxy, f"-H {header}:{fuzz_values}", url)

    if cookies:
        wfuzz(["-z list," + passwords], filter2use, proxy, " ".join([f"-b {c.name}=FUZZ" for c in cookies]), url)

def fuzz_authentication(url, filter2use, proxy, users, passwords):
    color_print("[+] Fuzzing HTTP Authentication...")
    auth_types = ['Basic', 'NTLM']

    for auth_type in auth_types:
        wfuzz(["-z list," + users], filter2use, proxy, f"--{auth_type} FUZZ:FUZZ", url)
        wfuzz(["-z list," + users, "-z list," + passwords], filter2use, proxy, f"--{auth_type} FUZZ:FUZ2Z", url)

def find_comments(text):
    for comments in soup.findAll(text=lambda text: isinstance(text, Comment)):
        comments.extract()

def wfuzz(lists, filter2use, proxy, extra, url):
    cmd = " ".join(lists) + f" {filter2use} {proxy} {extra} --req-delay 30 --conn-delay 30 {url}"
    cmd = " ".join(cmd.split())
    color_print("[c] Trying: " + cmd)
    for r in get_session(cmd).fuzz():
        print(r)

def main():
    url, ip, f2u = parse_main_args(sys.argv[1:])
    proxy = ""  # If you use the proxy the HTTP methods POST and PUT stuck the program, so don't use a proxy until this is fixed!!

    if len(f2u.split(",")) != 2:
        color_print("[-] Error, bad filter selected")
        sys.exit(2)

    if f2u.split(",")[0] == "contains":
        filter2use = "--s"
    elif f2u.split(",")[0] == "notcontains":
        filter2use = "--h"
    else:
        color_print("[-] Error, bad filter selected")
        sys.exit(2)

    if f2u.split(",")[1].isdigit():
        filter2use += "c " + f2u.split(",")[1]
    else:
        filter2use += 's "' + f2u.split(",")[1] + "'"

    if proxy is not None and proxy != "":
        proxy = "-p " + proxy

    users = "admin-administrator-root-anonymous-ftp-guest-superadmin-tomcat-user-test-public-mysql"
    passwords = "admin-administrator-password-123456-12345678-root-toor-qwerty-anonymous-True"
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
        # Add more user agents as needed
    ]

    with open("/tmp/list-ua.txt", 'w') as f:
        for ua in user_agents:
            f.write(ua + "\n")

    r = requests.get(url)
    status_code = r.status_code
    body = r.text
    resp_length = len(body)
    cookies = r.cookies
    is_redir = r.is_redirect or r.is_permanent_redirect or (status_code > 299 and status_code < 400)

    color_print("[i] Making a simple GET request the returned code was {} and the length of the body was {}".format(status_code, resp_length))
    
    if cookies:
        color_print("[i] The web wanted to set these cookies: ")
        for c in cookies:
            print("{}={}".format(c.name, c.value))
    
    if is_redir and resp_length > 0:
        color_print("[i] Hey, the web is redirecting us but it has some content, take a look:")
        color_print(body)

    proto, domain, path = get_parts_from_url(url)
    ips = ["127.0.0.1", "8.8.4.4"] + [ip] if ip != "" else ["127.0.0.1", "8.8.4.4"]
    ips += get_ips_from_domain(domain) if not is_ip(domain) else []
    ips = "-".join(ips)
    color_print("[i] IPs that are going to be used for FUZZING: {}".format(ips))

    print("")
    fuzz_paths(url, filter2use, proxy)
    fuzz_methods(url, filter2use, proxy)
    fuzz_headers(url, ips, filter2use, proxy, cookies, passwords)
    fuzz_authentication(url, filter2use, proxy, users, passwords)

    os.kill(os.getpid(), signal.SIGTERM)

if __name__ == '__main__':
    main()
