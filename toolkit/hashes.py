"""Hashing: identify a hash, compute hashes, and drive John the Ripper."""
from __future__ import annotations

import hashlib
import re
import tempfile
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, require_tool, run_external

# (name, John --format hint, regex). Identification is heuristic — length + charset.
HASH_SIGNATURES = [
    ("MD5",          "raw-md5",    re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("NTLM",         "nt",         re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("SHA-1",        "raw-sha1",   re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("SHA-224",      "raw-sha224", re.compile(r"^[a-f0-9]{56}$", re.I)),
    ("SHA-256",      "raw-sha256", re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("SHA-384",      "raw-sha384", re.compile(r"^[a-f0-9]{96}$", re.I)),
    ("SHA-512",      "raw-sha512", re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("bcrypt",       "bcrypt",     re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$")),
    ("MD5-crypt",    "md5crypt",   re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$")),
    ("SHA-256-crypt","sha256crypt",re.compile(r"^\$5\$")),
    ("SHA-512-crypt","sha512crypt",re.compile(r"^\$6\$")),
    ("MySQL 4.1+",   "mysql-sha1", re.compile(r"^\*[A-F0-9]{40}$")),
]


def identify() -> None:
    header("Hash Identifier", "Guess the algorithm from length and format")
    h = Prompt.ask("Paste a hash").strip()
    matches = [(name, fmt) for name, fmt, rx in HASH_SIGNATURES if rx.match(h)]
    if not matches:
        console.print("[yellow]No confident match. Length =[/] "
                      f"[bold]{len(h)}[/] chars.")
        return pause()
    table = Table(title="Possible matches (most likely first)")
    table.add_column("Algorithm", style="green bold")
    table.add_column("John --format")
    for name, fmt in matches:
        table.add_row(name, fmt)
    console.print(table)
    if len(matches) > 1:
        console.print("[dim]Same-length hashes are ambiguous (e.g. MD5 vs NTLM) — "
                      "context decides which one it is.[/]")
    pause()


def calculate() -> None:
    header("Hash Calculator", "Compute digests of text or a file")
    src = Prompt.ask("Hash [t]ext or [f]ile?", choices=["t", "f"], default="t")
    if src == "t":
        data = Prompt.ask("Text").encode()
        label = "text"
    else:
        p = Path(Prompt.ask("File path").strip('"'))
        if not p.is_file():
            console.print(f"[red]No such file: {p}[/]")
            return pause()
        data = p.read_bytes()
        label = p.name

    table = Table(title=f"Digests of {label}")
    table.add_column("Algorithm", style="bold")
    table.add_column("Digest", style="green")
    for algo in ("md5", "sha1", "sha256", "sha512"):
        table.add_row(algo, hashlib.new(algo, data).hexdigest())
    console.print(table)
    pause()


def john_crack() -> None:
    header("John the Ripper", "Dictionary attack against a hash file")
    path = require_tool("john")
    if not path:
        console.print("[dim]On Windows, install the 'jumbo' build and add its /run "
                      "folder to PATH so 'john' is callable.[/]")
        return pause()

    hash_file = Prompt.ask("Path to file containing the hash(es)").strip('"')
    if not Path(hash_file).is_file():
        console.print("[red]Hash file not found.[/]")
        return pause()

    fmt = Prompt.ask("John --format (blank = let John autodetect)", default="").strip()
    wl = Prompt.ask("Wordlist path (blank = John default rules)", default="").strip('"')

    cmd = ["john"]
    if fmt:
        cmd.append(f"--format={fmt}")
    if wl:
        cmd += [f"--wordlist={wl}", "--rules"]
    cmd.append(hash_file)

    console.print("[dim]Running John. It writes cracked passwords to its pot file; "
                  "we'll show them after.[/]")
    run_external(cmd)
    console.print("\n[bold]Cracked so far:[/]")
    run_external(["john", "--show"] + ([f"--format={fmt}"] if fmt else []) + [hash_file])
    pause()


def hashcat_crack() -> None:
    header("hashcat", "GPU dictionary attack (needs an installed hashcat)")
    path = require_tool("hashcat")
    if not path:
        return pause()
    hash_file = Prompt.ask("Path to hash file").strip('"')
    if not Path(hash_file).is_file():
        console.print("[red]Hash file not found.[/]")
        return pause()
    # A few common hashcat mode numbers so the user doesn't have to memorize them.
    console.print("[dim]Common modes: 0=MD5  100=SHA1  1400=SHA256  1700=SHA512  "
                  "3200=bcrypt  1000=NTLM[/]")
    mode = Prompt.ask("hash-mode (-m)", default="0").strip()
    wl = Prompt.ask("Wordlist path").strip('"')
    if not Path(wl).is_file():
        console.print("[red]Wordlist not found.[/]")
        return pause()
    run_external(["hashcat", "-m", mode, "-a", "0", hash_file, wl])
    console.print("\n[bold]Cracked:[/]")
    run_external(["hashcat", "-m", mode, hash_file, "--show"])
    pause()


def make_demo_hashes() -> None:
    """Generate a safe practice file so the user can try John on their own data."""
    header("Make practice hashes", "Creates a local file of MD5 hashes to crack for practice")
    words = ["password", "letmein", "dragon", "hunter2", "qwerty123"]
    lines = [hashlib.md5(w.encode()).hexdigest() for w in words]
    out = Path(tempfile.gettempdir()) / "practice_md5.txt"
    out.write_text("\n".join(lines) + "\n")
    console.print(f"Wrote [cyan]{out}[/] with {len(words)} MD5 hashes of common words.")
    console.print("[dim]Point John (option above) at it with --format=raw-md5 and a "
                  "wordlist like rockyou.txt to see cracking work end to end.[/]")
    pause()


def checksum_verify() -> None:
    header("Checksum verify", "Compute a file's hash and compare to an expected value")
    p = Path(Prompt.ask("File path").strip('"'))
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    data = p.read_bytes()
    digests = {a: hashlib.new(a, data).hexdigest() for a in ("md5", "sha1", "sha256")}
    for a, d in digests.items():
        console.print(f"  [bold]{a}[/]  {d}")
    expected = Prompt.ask("\nExpected hash to compare (blank to skip)", default="").strip().lower()
    if expected:
        match = next((a for a, d in digests.items() if d == expected), None)
        if match:
            console.print(f"[bold green]MATCH[/] — file integrity confirmed ({match}).")
        else:
            console.print("[bold red]NO MATCH[/] — file differs from the expected hash!")
    pause()


MENU = {
    "1": ("Identify a hash", identify),
    "2": ("Calculate hashes (text/file)", calculate),
    "3": ("Checksum verify / compare", checksum_verify),
    "4": ("Crack with John the Ripper", john_crack),
    "5": ("Crack with hashcat (GPU)", hashcat_crack),
    "6": ("Generate practice hashes", make_demo_hashes),
}
