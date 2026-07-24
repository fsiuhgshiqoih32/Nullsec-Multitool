from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .utils import console, header, pause, report, require_tool, run_external

requests.packages.urllib3.disable_warnings()  # we intentionally allow self-signed in labs

# Security headers we check for, with a one-line "why it matters".
SECURITY_HEADERS = {
    "Strict-Transport-Security": "forces HTTPS, blocks SSL-strip",
    "Content-Security-Policy": "mitigates XSS / injection",
    "X-Frame-Options": "clickjacking protection",
    "X-Content-Type-Options": "stops MIME sniffing",
    "Referrer-Policy": "controls referrer leakage",
    "Permissions-Policy": "limits browser feature access",
}


def _normalize(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def headers_audit() -> None:
    header("HTTP header audit", "Fetch a site and grade its security headers")
    url = _normalize(console.input("URL: ").strip())
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()

    console.print(f"[bold]{r.status_code}[/] {r.reason}  ·  final URL: [cyan]{r.url}[/]")
    interesting = ["Server", "X-Powered-By", "Set-Cookie", "Content-Type"]
    from rich.table import Table

    t = Table(title="Notable response headers")
    t.add_column("Header", style="bold")
    t.add_column("Value", style="dim", overflow="fold")
    for h in interesting:
        if h in r.headers:
            t.add_row(h, r.headers[h])
    console.print(t)

    grade = Table(title="Security headers")
    grade.add_column("Header", style="bold")
    grade.add_column("Present")
    grade.add_column("Why it matters", style="dim")
    missing = []
    for h, why in SECURITY_HEADERS.items():
        present = h in r.headers
        if not present:
            missing.append(h)
        grade.add_row(h, "[green]yes[/]" if present else "[red]MISSING[/]", why)
    console.print(grade)
    score = len(SECURITY_HEADERS) - len(missing)
    console.print(f"Score: [bold]{score}/{len(SECURITY_HEADERS)}[/] security headers present.")

    report.log("web", f"Header audit {r.url}",
               [f"- Status: {r.status_code}",
                f"- Server: {r.headers.get('Server','?')}",
                f"- Security headers: {score}/{len(SECURITY_HEADERS)}",
                f"- Missing: {', '.join(missing) or 'none'}"])
    pause()


def tls_info() -> None:
    header("TLS certificate", "Inspect the cert a host presents")
    host = console.input("Host (e.g. example.com): ").strip()
    host = urlparse(_normalize(host)).hostname or host
    port = 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
    except Exception as e:
        console.print(f"[red]TLS connection failed: {e}[/]")
        return pause()

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_after = cert.get("notAfter", "")
    days_left = "?"
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (exp - datetime.now(timezone.utc)).days
    except ValueError:
        pass
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    from rich.table import Table

    t = Table(show_header=False, box=None)
    t.add_row("Common name", subject.get("commonName", "?"))
    t.add_row("Issuer", issuer.get("commonName", "?"))
    t.add_row("Valid until", f"{not_after}  ([bold]{days_left}[/] days left)")
    t.add_row("TLS/cipher", f"{cipher[1]} · {cipher[0]}")
    t.add_row("SANs", ", ".join(sans[:8]) + (" …" if len(sans) > 8 else ""))
    console.print(t)
    if isinstance(days_left, int) and days_left < 21:
        console.print("[yellow][!] Certificate expires soon.[/]")

    report.log("web", f"TLS cert {host}",
               [f"- Issuer: {issuer.get('commonName','?')}",
                f"- Expires: {not_after} ({days_left} days)",
                f"- Cipher: {cipher[0]}"])
    pause()


def robots_and_meta() -> None:
    header("robots.txt & sitemap", "Read the paths a site advertises")
    base = _normalize(console.input("Base URL: ").strip()).rstrip("/")
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        try:
            r = requests.get(base + path, timeout=6, verify=False)
            if r.status_code == 200 and r.text.strip():
                console.print(f"\n[green]{path}[/] ({len(r.text)} bytes):")
                console.print("[dim]" + "\n".join(r.text.splitlines()[:25]) + "[/]")
            else:
                console.print(f"[dim]{path}: {r.status_code}[/]")
        except requests.RequestException as e:
            console.print(f"[dim]{path}: {e}[/]")
    pause()


def dirbrute_handoff() -> None:
    header("Directory brute-force", "Hand off to ffuf or gobuster")
    tool = "ffuf" if require_tool("ffuf") else ("gobuster" if require_tool("gobuster") else None)
    if not tool:
        return pause()
    url = _normalize(console.input("Target URL: ").strip())
    wl = console.input("Wordlist path: ").strip('"')
    if tool == "ffuf":
        run_external(["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", wl, "-mc", "200,301,302,403"])
    else:
        run_external(["gobuster", "dir", "-u", url, "-w", wl])
    pause()


def cors_check() -> None:
    header("CORS checker", "Test if a site reflects arbitrary Origins")
    url = _normalize(console.input("URL: ").strip())
    evil = "https://evil.example.com"
    try:
        r = requests.get(url, headers={"Origin": evil}, timeout=8, verify=False)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    console.print(f"Access-Control-Allow-Origin: [bold]{acao or '(none)'}[/]")
    console.print(f"Access-Control-Allow-Credentials: [bold]{acac or '(none)'}[/]")
    if acao == evil:
        console.print("[red][!] Origin is REFLECTED[/] — arbitrary sites may read responses"
                      + (" WITH credentials!" if acac.lower() == "true" else "."))
        report.log("web", f"CORS reflection {url}", ["- Origin reflected", f"- creds: {acac}"])
    elif acao == "*":
        console.print("[yellow]Wildcard ACAO[/] — open, but credentials can't be used.")
    else:
        console.print("[green]No obvious reflection.[/]")
    pause()


def http_methods() -> None:
    header("HTTP method tester", "Which verbs does the server allow?")
    url = _normalize(console.input("URL: ").strip())
    verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    from rich.table import Table
    t = Table()
    t.add_column("Method", style="bold")
    t.add_column("Status")
    t.add_column("Note", style="dim")
    for v in verbs:
        try:
            r = requests.request(v, url, timeout=6, verify=False, allow_redirects=False)
            note = ""
            if v in ("PUT", "DELETE", "TRACE") and r.status_code < 400:
                note = "[!] potentially dangerous verb enabled"
            t.add_row(v, str(r.status_code), note)
        except requests.RequestException:
            t.add_row(v, "-", "no response")
    console.print(t)
    pause()


TECH_SIGNS = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json"],
    "Drupal": ["Drupal.settings", "/sites/default/"],
    "Joomla": ["/media/jui/", "Joomla!"],
    "React": ["__REACT_DEVTOOLS", "data-reactroot", "react.production"],
    "Vue.js": ["__vue__", "data-v-"],
    "Angular": ["ng-version", "angular"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
    "jQuery": ["jquery"],
    "Cloudflare": ["cf-ray", "__cfduid"],
    "nginx": ["nginx"],
    "Apache": ["apache"],
}


def tech_fingerprint() -> None:
    header("Tech fingerprint", "Guess the stack from headers + body (whatweb-lite)")
    url = _normalize(console.input("URL: ").strip())
    try:
        r = requests.get(url, timeout=8, verify=False)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    haystack = (r.text[:200000] + " " + str(r.headers)).lower()
    found = [tech for tech, signs in TECH_SIGNS.items()
             if any(s.lower() in haystack for s in signs)]
    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")
    console.print(f"Server: [cyan]{server or '?'}[/]   X-Powered-By: [cyan]{powered or '?'}[/]")
    if found:
        console.print("Detected: " + ", ".join(f"[green]{t}[/]" for t in found))
        report.log("web", f"Tech fingerprint {url}", [f"- {', '.join(found)}"])
    else:
        console.print("[yellow]No known signatures matched.[/]")
    pause()


def wayback_urls() -> None:
    header("Wayback URLs", "Historical URLs for a domain from the Internet Archive")
    domain = console.input("Domain (e.g. example.com): ").strip()
    limit = console.input("Max results [200]: ").strip() or "200"
    url = (f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
           f"&output=text&fl=original&collapse=urlkey&limit={limit}")
    try:
        r = requests.get(url, timeout=25)
        r.raise_for_status()
    except requests.RequestException as e:
        console.print(f"[red]Wayback query failed: {e}[/]")
        return pause()
    urls = [u for u in r.text.splitlines() if u.strip()]
    if not urls:
        console.print("[yellow]No archived URLs found.[/]")
        return pause()
    # highlight interesting extensions
    interesting = [u for u in urls if any(x in u.lower() for x in
                   (".json", ".xml", ".sql", ".bak", ".env", ".config", ".zip",
                    "api", "admin", "?", ".js", ".txt", ".log"))]
    console.print(f"[bold]{len(urls)}[/] archived URLs "
                  f"([yellow]{len(interesting)}[/] potentially interesting):\n")
    for u in interesting[:40] or urls[:40]:
        console.print(f"  [dim]{u}[/]")
    report.log("web", f"Wayback URLs {domain}",
               [f"- {len(urls)} archived URLs, {len(interesting)} interesting"])
    pause()


def _param_target():
    url = _normalize(console.input("Base URL: ").strip())
    param = console.input("Parameter to inject: ").strip()
    return url, param


SSTI_PAYLOADS = {
    "{{7*7}}": "49", "${7*7}": "49", "<%= 7*7 %>": "49",
    "#{7*7}": "49", "{{7*'7'}}": "7777777", "${{7*7}}": "49",
}


def ssti_test() -> None:
    header("SSTI probe", "Detect server-side template injection")
    url, param = _param_target()
    hit = False
    for payload, expect in SSTI_PAYLOADS.items():
        try:
            r = requests.get(url, params={param: payload}, timeout=8, verify=False)
        except requests.RequestException as e:
            console.print(f"[red]{e}[/]")
            break
        if expect in r.text:
            console.print(f"[red][!] {payload}[/] evaluated -> [bold]{expect}[/] "
                          "reflected. Template injection likely.")
            report.log("web", f"SSTI {url}", [f"- {param} evaluates {payload}"])
            hit = True
    if not hit:
        console.print("[green]No template evaluation observed.[/]")
    pause()


REDIRECT_PAYLOADS = ["https://evil.example.com", "//evil.example.com",
                     "/\\evil.example.com", "https:evil.example.com",
                     "https://target.com.evil.example.com"]


def open_redirect_test() -> None:
    header("Open-redirect probe", "Does a redirect param send you off-site?")
    url, param = _param_target()
    hit = False
    for p in REDIRECT_PAYLOADS:
        try:
            r = requests.get(url, params={param: p}, timeout=8, verify=False,
                             allow_redirects=False)
        except requests.RequestException as e:
            console.print(f"[red]{e}[/]")
            break
        loc = r.headers.get("Location", "")
        if "evil.example.com" in loc:
            console.print(f"[red][!] redirects to {loc}[/] via {param}={p}")
            report.log("web", f"Open redirect {url}", [f"- {param} -> {loc}"])
            hit = True
    if not hit:
        console.print("[green]No external redirect observed.[/]")
    pause()


SSRF_TARGETS = ["http://127.0.0.1", "http://localhost", "http://0.0.0.0",
                "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]


def ssrf_test() -> None:
    header("SSRF probe", "Does a URL param fetch internal resources?")
    console.print("[bright_black]Point the callback tests at the HTTP Interceptor "
                  "catch-all listener (h -> 1) to confirm blind SSRF.[/]")
    url, param = _param_target()
    baseline = None
    from rich.table import Table
    t = Table()
    t.add_column("Injected", style="cyan", overflow="fold")
    t.add_column("Status")
    t.add_column("Len", justify="right")
    for target in SSRF_TARGETS:
        try:
            r = requests.get(url, params={param: target}, timeout=8, verify=False)
            t.add_row(target, str(r.status_code), str(len(r.content)))
            if "root:" in r.text or "ami-id" in r.text or "instance-id" in r.text:
                t.add_row("", "[red]-> internal content leaked![/]", "")
        except requests.RequestException as e:
            t.add_row(target, f"[dim]{type(e).__name__}[/]", "-")
    console.print(t)
    console.print("[bright_black]Big status/length differences vs a normal value "
                  "suggest the server fetched your URL.[/]")
    pause()


MENU = {
    "1": ("HTTP header + security audit", headers_audit),
    "2": ("TLS certificate inspector", tls_info),
    "3": ("robots.txt / sitemap / security.txt", robots_and_meta),
    "4": ("Directory brute-force (ffuf/gobuster)", dirbrute_handoff),
    "5": ("CORS misconfiguration check", cors_check),
    "6": ("HTTP method tester", http_methods),
    "7": ("Tech stack fingerprint", tech_fingerprint),
    "8": ("Wayback Machine URLs", wayback_urls),
    "9": ("SSTI probe", ssti_test),
    "10": ("Open-redirect probe", open_redirect_test),
    "11": ("SSRF probe", ssrf_test),
}
