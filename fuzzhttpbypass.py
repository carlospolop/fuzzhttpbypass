#!/usr/bin/python3

import argparse, string, socket, sys, requests, os, signal

from wfuzz.api import get_session

from bs4 import BeautifulSoup, Comment

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_main_args(args=None):
    parser = argparse.ArgumentParser(description='Process some integers.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Url to test (http://example.com/index.php)')
    group.add_argument('-L', '--url-list', help='File containing list of URLs to test')
    parser.add_argument('-W', '--wfuzz-filter', required=True, help='Pass wfuzz filter options directly (e.g., --wfuzz-filters "--hc 403,404 --hl 100")')
    parser.add_argument('-i', '--ip', default="",
                        help='Add this IP, when trying to impersonate via HTTP headers (by default the IP of the domain/IP of the URL is used)')
    parser.add_argument('-b', '--bypass-verification', action='store_true',
                        help='Bypass SSL certificate verification, useful in case the target site is misconfigured')

    args = parser.parse_args()
    return args

def color_print(to_print):
    NoC = "\033[0m"
    Y = "\033[1;33;40m"
    G = "\033[1;32;40m"
    B = "\033[1;34;40m"
    R = "\033[0;31;47m"

    if "[i] " in to_print:
        print(Y+to_print+NoC)
    elif "[+] " in to_print:
        print(G+to_print+NoC)
    elif "[c] " in to_print:
        print(B+to_print+NoC)
    elif "[-] " in to_print:
        print(R+to_print+NoC)
    else:
        print(to_print)

def getPartsFromUrl(url):
    'Get parts of a url'
    proto, rest = url.split("//")
    domain = rest.split("/")[0]
    path = "/" + "/".join(rest.split("/")[1:]) if len(rest.split("/")) > 1 else "/"
    return (proto, domain, path)

def getIPsFromDomain(domain):
    'Get all available domains from a domain'
    domain = domain.split(":")[0]
    ips = socket.gethostbyname_ex(domain)[2]
    color_print("[i] Found IP(s) for domain "+domain+": "+", ".join(ips))
    return ips

def isIP(param):
    'Check if we have a domain or an IP'
    if any(c in param for c in string.ascii_letters) or param.count(".") != 4:
        return False
    return True

def fuzzPaths(url, wfuzz_filter, proxy):
    'Method to FUZZ paths'
    color_print("[+] Fuzzing Path variations...")
    paths = "%2e-%252e-%ef%bc%8f"
    url_l = url.split("/")
    url_l.insert(-1,"FUZZ")
    if len(url_l) < 4:
        url_l.append("")

    url = "/".join(url_l)
    wfuzz(["-z list,"+paths], wfuzz_filter, proxy, "", url)

def fuzzMethods(url, wfuzz_filter, proxy):
    'Method to FUZZ http methods'
    color_print("[+] Fuzzing HTTP Verbs (methods)...")
    methods = "GET-HEAD-POST-DELETE-CONNECT-OPTIONS-TRACE-PUT-INVENTED"
    wfuzz(["-z list,"+methods], wfuzz_filter, proxy, " -X FUZZ", url)

    proto, domain, path = getPartsFromUrl(url)
    if path.count("/") == 1:
        for p in ["index.php", "index", "index.html", "index.asp", "index.aspx", ""]:
            if path.split("/")[1] != p:
                wfuzz(["-z list,"+methods], wfuzz_filter, proxy, "-X FUZZ", proto+"//"+domain+"/"+p)

def fuzzHeaders(url, ips, wfuzz_filter, proxy, cookies, passwords):
    'Method to FUZZ http headers'
    color_print("[+] Fuzzing HTTP Headers...")
    color_print("\t[+] Forwarded")
    wfuzz(["-z list,"+ips+"_hidden-_secret-unknown", "-z list,"+ips, "-z list,"+ips, "-z list,http-https"], wfuzz_filter, proxy, "-H 'Forwarded:for=FUZZ;by=FUZ2Z;host=FUZ3Z;proto=FUZ4Z'", url)
    
    color_print("\t[+] X-Originating-IP")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-Originating-IP:FUZZ", url)

    color_print("\t[+] X-Forwarded-For")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-Forwarded-For:FUZZ", url)
    
    color_print("\t[+] X-Forwarded")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-Forwarded:FUZZ", url)

    color_print("\t[+] Forwarded-For")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H Forwarded-For:FUZZ", url)
    
    color_print("\t[+] X-Remote-IP")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-Remote-IP:FUZZ", url)

    color_print("\t[+] X-Remote-Addr")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-Remote-Addr:FUZZ", url)

    color_print("\t[+] X-ProxyUser-Ip")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-ProxyUser-Ip:FUZZ", url)

    color_print("\t[+] X-Original-URL")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-Original-URL:FUZZ", url)

    color_print("\t[+] Client-IP")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H Client-IP:FUZZ", url)

    color_print("\t[+] True-Client-IP")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H True-Client-IP:FUZZ", url)

    color_print("\t[+] Cluster-Client-IP")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H Cluster-Client-IP:FUZZ", url)
    
    color_print("\t[+] X-ProxyUser-Ip")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H X-ProxyUser-Ip:FUZZ", url)
    
    color_print("\t[+] Host")
    wfuzz(["-z list,"+ips], wfuzz_filter, proxy, "-H Host:FUZZ", url)
    
    color_print("\t[+] Referer")
    wfuzz(["-z list,"+url], wfuzz_filter, proxy, "-H Referer:FUZZ", url)

    color_print("\t[+] User-Agent")
    wfuzz(["-w /tmp/list-ua.txt"], wfuzz_filter, proxy, "-H User-Agent:FUZZ", url)

    if len(cookies) > 0:
        wfuzz(["-z list,"+passwords], wfuzz_filter, proxy, " ".join([ "-b "+c.name+"=FUZZ" for c in cookies ]), url)

def fuzzAuthentication(url, wfuzz_filter, proxy, users, passwords):
    'Method to FUZZ HTTP Authentication'
    color_print("[+] Fuzzing HTTP Authentication...")
    color_print("\t[+] Basic")
    wfuzz(["-z list,"+users], wfuzz_filter, proxy, "--basic FUZZ:FUZZ", url)
    wfuzz(["-z list,"+users,"-z list,"+passwords], wfuzz_filter, proxy, "--basic FUZZ:FUZ2Z", url)

    color_print("\t[+] NTLM")
    wfuzz(["-z list,"+users], wfuzz_filter, proxy, "--ntlm FUZZ:FUZZ", url)
    wfuzz(["-z list,"+users,"-z list,"+passwords], wfuzz_filter, proxy, "--ntlm FUZZ:FUZ2Z", url)

def wfuzz(lists, wfuzz_filter, proxy, extra, url):
    'Launch wfuzz with custom options'
    cmd = " ".join(lists)+" "+wfuzz_filter+" "+proxy+" "+extra+" "+" --req-delay 30 --conn-delay 30 -Z "+url
    cmd = cmd.replace("  "," ").replace("  "," ").replace("  "," ")
    color_print("[c] Trying: "+cmd)
    try:
        for r in get_session(cmd).fuzz():
            print(r)
    except Exception as e:
        color_print("Failed "+cmd+" with error "+str(e))

def test_url(url, ip, wfuzz_filter, bypass):
    proxy = ""  # If you use the proxy the HTTP methods POST and PUT stuck the program, so don't use a proxy until this is fixed!
        
    users="admin-administrator-root-anonymous-ftp-guest-superadmin-tomcat-user-test-public-mysql"
    passwords="admin-administrator-password-123456-12345678-root-toor-qwerty-anonymous-True"
    useragents=[ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; U; Android 4.4.2; es-es; SM-T210R Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",
                "Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.8) Gecko/20050511 Firefox/1.0.4",
                "Mozilla/5.0 (Linux; Android 9; SM-G960F Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.157 Mobile Safari/537.36",
                "Googlebot", "Bingbot", "admin" ]
        
    with open("/tmp/list-ua.txt", 'w') as f:
        for ua in useragents:
            f.write(ua+"\n")

    try:
        r = requests.get(url, verify=(not bypass))
    except requests.exceptions.SSLError:
        print("\n\033[31m[!]\033[0m There was a problem resolving the SSL certificate for that site, did you enable the `-b` flag to bypass verification?")
        return

    status_code = r.status_code
    body = r.text
    resp_length = len(body)
    cookies = r.cookies
    is_redir = r.is_redirect or r.is_permanent_redirect or (status_code > 299 and status_code < 400)

    color_print("[i] Making a simple GET request the returned code was "+str(status_code)+" and the length of the body was "+str(resp_length))
    if cookies is not None and len(cookies) > 0:
        color_print("[i] The web wanted to set these cookies: ")
        for c in cookies:
            print(c.name+"="+c.value)
    if is_redir and resp_length > 0:
        color_print("[i] Hey, the web is redirecting us but it has some content, take a look:")
        color_print(body)

    proto, domain, path = getPartsFromUrl(url)
    ips = ["127.0.0.1", "8.8.4.4"] + [ip] if ip != "" else ["127.0.0.1", "8.8.4.4"]
    ips = ips + getIPsFromDomain(domain) if not isIP(domain) else ips
    ips = "-".join(ips)
    color_print("[i] IPs that are going to be used for FUZZING: "+ips)

    print("")
    fuzzPaths(url, wfuzz_filter, proxy)
    fuzzMethods(url, wfuzz_filter, proxy)
    fuzzHeaders(url, ips, wfuzz_filter, proxy, cookies, passwords)
    fuzzAuthentication(url, wfuzz_filter, proxy, users, passwords)

def main():
    args = parse_main_args(sys.argv[1:])
    
    if args.url_list:
        with open(args.url_list, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [args.url]

    for url in urls:
        color_print(f"\n[+] Testing URL: {url}")
        test_url(url, args.ip, args.wfuzz_filter, args.bypass_verification)

    os.kill(os.getpid(), signal.SIGTERM)

if __name__ == '__main__':
    main()
