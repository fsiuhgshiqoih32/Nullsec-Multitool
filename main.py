from __future__ import annotations

import os
import sys

# Enable ANSI colors on legacy Windows terminals, and make output UTF-8 so
# box glyphs / symbols don't crash on a cp1252 console.
os.system("")
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from rich import box
from rich.columns import Columns
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from toolkit import (__version__, adattacks, arsenal, bruteforce, catalog,
                     crypto, cryptotools, forensics, generators, hashes,
                     installer, interceptor, lolbins, metadata, network, osint,
                     passwords, payloadenc, recon, stego, vulnscan, web,
                     wordlists)
from toolkit.utils import (IS_WINDOWS, console, detect_tools, get_wsl_distro,
                           probe_tools, render_banner, report, wsl_available)

BANNER = render_banner("nullsec")

CATEGORIES = {
    "1": ("Reconnaissance", recon.MENU, "Resolve hosts, scan ports, hand off to nmap"),
    "2": ("Hashes & Cracking", hashes.MENU, "Identify, compute, crack (John/hashcat)"),
    "3": ("Crypto & Encoding", crypto.MENU, "Decode blobs, break Caesar/XOR ciphers"),
    "4": ("Passwords", passwords.MENU, "Strength checks and targeted wordlists"),
    "5": ("Web", web.MENU, "Headers/TLS/CORS/methods, dir brute, fingerprint"),
    "6": ("Network", network.MENU, "Host discovery, rDNS, ARP, local info"),
    "7": ("Payload Arsenal", arsenal.MENU, "Reverse/bind/web shells, msfvenom, listeners"),
    "8": ("Tool Catalog", catalog.MENU, "Index + launch 10,000+ real tools/exploits"),
    "9": ("Brute-force", bruteforce.MENU, "hydra login brute (native or via WSL)"),
    "v": ("Vuln Scan", vulnscan.MENU, "Nuclei ~9,000 templates: browse/search/scan"),
    "a": ("AD Attacks", adattacks.MENU, "Kerberoast / AS-REP roast (Impacket)"),
    "l": ("LOLBins", lolbins.MENU, "GTFOBins / LOLBAS abuse lookup"),
    "c": ("Cipher Lab", cryptotools.MENU, "XOR/Vigenere breakers, Morse, JWT crack"),
    "f": ("Forensics", forensics.MENU, "strings, carver, entropy, secret scanner"),
    "o": ("OSINT & DNS", osint.MENU, "Raw DNS, WHOIS, CIDR, favicon hash, dorks"),
    "m": ("Metadata", metadata.MENU, "Harvest author/software/paths from documents"),
    "g": ("Generators", generators.MENU, "Passphrases, wordlists, markov, HIBP check"),
    "w": ("Wordlists", wordlists.MENU, "Browse/search SecLists & wordlists"),
    "s": ("Steganography", stego.MENU, "Hide/extract data in text & images"),
    "p": ("Payload Forge", payloadenc.MENU, "Encoders, XSS/SQLi, shell stabilization"),
    "h": ("HTTP Interceptor", interceptor.MENU, "Catch-all listener, file server, repeater"),
    "i": ("Install Arsenal", installer.MENU, "Install the real tools (WSL BlackArch)"),
}

# System pseudo-entries (handled specially, not real categories).
SYSTEM_ITEMS = {"r": "Session Report", "t": "Tool Status", "q": "Quit"}

# External tools each category can drive. Categories not listed are pure built-in
# (always ready). Used for the live installed-tools indicator.
CATEGORY_DEPS = {
    "1": ["nmap"],
    "2": ["john", "hashcat"],
    "5": ["ffuf", "gobuster"],
    "8": ["searchsploit", "nuclei", "msfconsole"],
    "9": ["hydra"],
}

_probe_cache: dict | None = None


def _probe() -> dict:
    global _probe_cache
    if _probe_cache is None:
        alltools = sorted({t for lst in CATEGORY_DEPS.values() for t in lst})
        _probe_cache = probe_tools(alltools)
    return _probe_cache


def _cat_dot(key: str) -> str:
    """Indicator: green=ready, yellow=some tools present, red=needs install."""
    if key not in CATEGORY_DEPS:
        return "[green]●[/]"          # built-in, always usable
    probe = _probe()
    have = sum(1 for t in CATEGORY_DEPS[key] if probe.get(t))
    total = len(CATEGORY_DEPS[key])
    if have == 0:
        return "[red]○[/]"
    return "[green]●[/]" if have == total else "[yellow]◐[/]"

# Home layout: (section title, colour, [category keys]).
GROUPS = [
    ("RECON / OSINT", "cyan", ["1", "6", "o", "m", "8"]),
    ("ATTACK", "red", ["7", "9", "v", "a", "5", "p", "h", "l"]),
    ("CRYPTO / STEGO", "magenta", ["3", "c", "2", "s"]),
    ("WORDLISTS", "yellow", ["4", "g", "w"]),
    ("FORENSICS", "green", ["f"]),
    ("SYSTEM", "blue", ["i", "r", "t", "q"]),
]

_wsl_status_cache: str | None = None


def _wsl_status() -> str:
    global _wsl_status_cache
    if _wsl_status_cache is None:
        if not IS_WINDOWS:
            _wsl_status_cache = "[green]native linux[/]"
        elif wsl_available():
            _wsl_status_cache = f"{get_wsl_distro()} [green]online[/]"
        else:
            _wsl_status_cache = "[red]offline[/]"
    return _wsl_status_cache


def _total_tools() -> int:
    return sum(len(c[1]) for c in CATEGORIES.values())


def _banner_block() -> str:
    reachable = catalog.indexed_total() + arsenal.payload_count()
    return "\n".join([
        f"       =[ [bold green]nullsec[/] [green]v{__version__}[/] · offensive security framework ]",
        f"+ -- --=[ {len(CATEGORIES)} modules · {_total_tools()} tools ]",
        f"+ -- --=[ {catalog.local_count():,} cataloged · [bold]{reachable:,}[/] modules reachable ]",
        f"+ -- --=[ wsl: {_wsl_status()} · log: {len(report.entries)} ]",
    ])


def _group_panel(title: str, colour: str, keys: list[str]) -> Panel:
    tbl = Table(show_header=False, box=None, padding=(0, 1, 0, 0))
    tbl.add_column(no_wrap=True)                              # dot
    tbl.add_column(justify="right", style=f"bold {colour}", no_wrap=True)  # key
    tbl.add_column(no_wrap=True)                              # name
    for k in keys:
        if k in CATEGORIES:
            name, menu, _ = CATEGORIES[k]
            tbl.add_row(_cat_dot(k), k, f"{name} [dim]{len(menu)}[/]")
        else:
            tbl.add_row(" ", k, f"[dim]{SYSTEM_ITEMS[k]}[/]")
    return Panel(tbl, title=f"[bold {colour}]{title}[/]", border_style=colour,
                 box=box.ROUNDED, padding=(0, 1))


def show_home() -> None:
    console.clear()
    console.print(Text(BANNER.rstrip("\n"), style="bold green"))
    console.print()
    console.print(Columns([_group_panel(*g) for g in GROUPS],
                          equal=True, expand=True))
    console.print("[bright_black]  ● ready  ◐ partial  ○ needs-install   ·   "
                  "key = open module  ·  'search <term>'  ·  'help'[/]")


def cmd_help() -> None:
    console.print(Panel(
        "[bold]commands[/]\n"
        "  [cyan]<key>[/]           open a module by its key (e.g. 1, c, o, w)\n"
        "  [cyan]search <term>[/]   search the tool catalog + modules\n"
        "  [cyan]use <tool>[/]      show a catalogued tool's install/details\n"
        "  [cyan]banner[/]          redraw the banner\n"
        "  [cyan]version[/]         framework version\n"
        "  [cyan]r[/] / [cyan]t[/]             session report / external tool status\n"
        "  [cyan]help[/], [cyan]?[/]          this screen\n"
        "  [cyan]q[/]               quit",
        border_style="bright_black", box=box.SQUARE, padding=(1, 2), expand=False))
    console.input("[bright_black][enter][/] ")


def cmd_version() -> None:
    reachable = catalog.indexed_total() + arsenal.payload_count()
    console.print(f"[bold green]nullsec[/] v{__version__}  ·  {_total_tools()} tools / "
                  f"{len(CATEGORIES)} modules  ·  {catalog.local_count():,} cataloged  ·  "
                  f"{reachable:,} reachable")
    console.input("[bright_black][enter][/] ")


def cmd_search(term: str) -> None:
    term = term.strip()
    if not term:
        console.print("[yellow]usage: search <term>[/]")
        return console.input("[bright_black][enter][/] ")
    hits = [t for t in catalog.all_tools()
            if term.lower() in t[0].lower() or term.lower() in t[1].lower()
            or term.lower() in t[2].lower()]
    if not hits:
        console.print(f"[yellow]no matches for '{term}'[/]")
        return console.input("[bright_black][enter][/] ")
    tbl = Table(title=f"{len(hits)} matches for '{term}'"
                + (" (showing 40)" if len(hits) > 40 else ""))
    tbl.add_column("tool", style="bold cyan")
    tbl.add_column("cat", style="magenta")
    tbl.add_column("install", style="dim", overflow="fold")
    for name, cat, _desc, install, _binary in hits[:40]:
        tbl.add_row(name, cat, install)
    console.print(tbl)
    console.print("[bright_black]details: open Tool Catalog (8) -> search[/]")
    console.input("[bright_black][enter][/] ")


def cmd_use(name: str) -> None:
    name = name.strip()
    match = next((t for t in catalog.all_tools() if t[0].lower() == name.lower()), None)
    if not match:
        console.print(f"[yellow]'{name}' not in catalog. try: search {name}[/]")
        return console.input("[bright_black][enter][/] ")
    n, cat, desc, install, _binary = match
    console.print(f"\n[bold cyan]{n}[/] [magenta]({cat})[/]\n{desc}\n"
                  f"[dim]install:[/] {install}")
    console.input("[bright_black][enter][/] ")


def show_report() -> None:
    console.clear()
    console.print(Panel("[bold]Session report[/]", border_style="cyan", expand=False))
    if not report.entries:
        console.print("[dim]No findings logged yet. Recon/web/network modules add "
                      "entries here as you use them.[/]")
        return console.input("\n[dim]Press Enter…[/]")
    from rich.markdown import Markdown

    console.print(Markdown(report.as_markdown()))
    choice = Prompt.ask("\nsave as [m]arkdown, save as [h]tml, [c]lear, or [b]ack",
                        choices=["m", "h", "c", "b"], default="b")
    if choice == "m":
        console.print(f"[green]Saved:[/] {report.save()}")
        console.input("\n[dim]Press Enter…[/]")
    elif choice == "h":
        console.print(f"[green]Saved:[/] {report.save_html()}")
        console.input("\n[dim]Press Enter…[/]")
    elif choice == "c":
        report.clear()
        console.print("[yellow]Cleared.[/]")
        console.input("\n[dim]Press Enter…[/]")


def show_tool_status() -> None:
    console.clear()
    console.print(Panel("[bold]External tool status[/]", border_style="cyan", expand=False))
    table = Table()
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Description", style="dim")
    for t in detect_tools():
        mark = "[green][+] installed[/]" if t.installed else "[red][-] missing[/]"
        table.add_row(t.key, mark, t.description)
    console.print(table)
    console.print("\n[dim]Missing tools just disable their module — the built-in "
                  "scanners/crackers work without them.[/]")
    console.input("\n[dim]Press Enter…[/]")


def run_category(key: str, name: str, menu: dict) -> None:
    modid = name.split()[0].lower()
    while True:
        console.clear()
        console.print(Text(BANNER.rstrip("\n"), style="bold green"))
        table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
        table.add_column(justify="right", style="bold green", no_wrap=True)
        table.add_column(no_wrap=True)
        for k, (label, _fn) in menu.items():
            table.add_row(k, label)
        table.add_row("b", "[bright_black]back[/]")
        console.print(Panel(table, title=f"[bold]{name}[/]",
                            border_style="bright_black", box=box.SQUARE, padding=(1, 2)))
        choice = Prompt.ask(f"[green]nullsec[/]([cyan]{modid}[/]) >").strip().lower()
        if choice == "b":
            return
        if choice in menu:
            console.clear()
            try:
                menu[choice][1]()
            except KeyboardInterrupt:
                console.print("\n[yellow]Cancelled.[/]")
        else:
            console.print("[red]Unknown option.[/]")


def main() -> None:
    while True:
        show_home()
        raw = Prompt.ask("\n[green]nullsec[/] >").strip()
        choice = raw.lower()
        verb = choice.split(None, 1)[0] if choice else ""
        arg = raw.split(None, 1)[1] if " " in raw else ""
        if choice in ("q", "quit", "exit"):
            return
        elif choice in ("help", "?", "h"):
            cmd_help()
        elif choice in ("banner", "clear"):
            continue
        elif choice in ("version", "-v", "--version"):
            cmd_version()
        elif verb == "search":
            cmd_search(arg)
        elif verb == "use":
            cmd_use(arg)
        elif choice == "r":
            show_report()
        elif choice == "t":
            show_tool_status()
        elif choice in CATEGORIES:
            name, menu, _desc = CATEGORIES[choice]
            run_category(choice, name, menu)
        else:
            console.print(f"[red]unknown command:[/] {raw}   "
                          "[bright_black](type 'help')[/]")
            console.input("[bright_black][enter][/] ")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Interrupted. Bye.[/]")
        sys.exit(0)
