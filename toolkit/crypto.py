from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import urllib.parse
import zlib

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause


def _try(fn) -> str:
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 - we want to show any failure inline
        return f"[red]error: {e}[/]"


def multi_decode() -> None:
    header("Multi-decoder", "Throw a blob at every common decoding at once")
    s = Prompt.ask("Input")
    b = s.encode()
    rows = [
        ("base64", _try(lambda: base64.b64decode(s + "===").decode(errors="replace"))),
        ("base32", _try(lambda: base64.b32decode(s + "======").decode(errors="replace"))),
        ("hex", _try(lambda: bytes.fromhex(s.replace(" ", "")).decode(errors="replace"))),
        ("url", _try(lambda: urllib.parse.unquote(s))),
        ("rot13", _try(lambda: codecs.decode(s, "rot13"))),
        ("binary", _try(lambda: _from_binary(s))),
        ("ascii85", _try(lambda: base64.a85decode(s).decode(errors="replace"))),
    ]
    table = Table(title="Decodings")
    table.add_column("Scheme", style="bold cyan")
    table.add_column("Result")
    for name, val in rows:
        table.add_row(name, val)
    console.print(table)
    pause()


def _from_binary(s: str) -> str:
    bits = s.replace(" ", "")
    chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)]
    return "".join(chars)


def encode() -> None:
    header("Encoder", "Encode text into a scheme")
    s = Prompt.ask("Text")
    b = s.encode()
    rows = [
        ("base64", base64.b64encode(b).decode()),
        ("base32", base64.b32encode(b).decode()),
        ("hex", b.hex()),
        ("url", urllib.parse.quote(s)),
        ("rot13", codecs.encode(s, "rot13")),
        ("binary", " ".join(f"{c:08b}" for c in b)),
    ]
    table = Table(title="Encodings")
    table.add_column("Scheme", style="bold cyan")
    table.add_column("Result", style="green")
    for name, val in rows:
        table.add_row(name, val)
    console.print(table)
    pause()


def caesar_brute() -> None:
    header("Caesar brute-force", "All 25 shifts, so you can eyeball the plaintext")
    s = Prompt.ask("Ciphertext")
    table = Table()
    table.add_column("Shift", justify="right", style="bold")
    table.add_column("Plaintext")
    for shift in range(1, 26):
        out = "".join(
            chr((ord(c) - base + shift) % 26 + base) if c.isalpha()
            else c
            for c in s
            for base in [ord("A") if c.isupper() else ord("a")]
        )
        table.add_row(str(shift), out)
    console.print(table)
    pause()


def xor_brute() -> None:
    header("Single-byte XOR brute-force", "Try all 256 keys, rank by printable ratio")
    raw = Prompt.ask("Input as hex (e.g. 1c0111...)").replace(" ", "")
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        console.print("[red]That isn't valid hex.[/]")
        return pause()

    def printable_ratio(bs: bytes) -> float:
        good = sum(32 <= c < 127 or c in (9, 10, 13) for c in bs)
        return good / len(bs) if bs else 0

    scored = []
    for key in range(256):
        dec = bytes(c ^ key for c in data)
        scored.append((printable_ratio(dec), key, dec))
    scored.sort(reverse=True)

    table = Table(title="Top XOR-key candidates")
    table.add_column("Key", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Decoded")
    for score, key, dec in scored[:8]:
        table.add_row(f"0x{key:02x}", f"{score:.0%}", dec.decode(errors="replace"))
    console.print(table)
    pause()


def _looks_meaningful(s: str) -> bool:
    """Heuristic: does this decoded string look like a flag / readable text?"""
    if not s:
        return False
    import re
    if re.search(r"[A-Za-z0-9_]{2,}\{.*\}", s):   # flag{...}, CTF{...}
        return True
    printable = sum(1 for c in s if 32 <= ord(c) < 127)
    letters = sum(1 for c in s if c.isalpha() or c == " ")
    return len(s) >= 3 and printable / len(s) > 0.9 and letters / len(s) > 0.6


def magic_decode() -> None:
    header("Magic recursive decoder", "Auto-detect and peel encoding layers (CyberChef-style)")
    s = Prompt.ask("Input blob").strip()

    def layers(x):
        out = {}
        try:
            if len(x) % 4 == 0 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in x):
                out["base64"] = base64.b64decode(x).decode(errors="replace")
        except Exception:
            pass
        try:
            hx = x.replace(" ", "")
            if len(hx) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in hx):
                out["hex"] = bytes.fromhex(hx).decode(errors="replace")
        except Exception:
            pass
        if "%" in x:
            out["url"] = urllib.parse.unquote(x)
        out["rot13"] = codecs.decode(x, "rot13")
        try:
            if len(x) % 8 == 0 and set(x) <= set("01 "):
                out["binary"] = "".join(chr(int(x.replace(' ', '')[i:i+8], 2))
                                        for i in range(0, len(x.replace(' ', '')), 8))
        except Exception:
            pass
        return out

    seen = {s}
    queue = [(s, [])]
    found = []
    steps = 0
    while queue and steps < 400:
        cur, path = queue.pop(0)
        steps += 1
        for scheme, dec in layers(cur).items():
            if not dec or dec in seen:
                continue
            seen.add(dec)
            newpath = path + [scheme]
            if _looks_meaningful(dec) and dec != cur:
                found.append((newpath, dec))
            if len(newpath) < 6:
                queue.append((dec, newpath))

    if not found:
        console.print("[yellow]No meaningful decoding found. Try the Multi-decoder "
                      "or Cipher Lab for ciphers.[/]")
        return pause()
    found.sort(key=lambda x: len(x[0]))
    console.print("[bold]Candidate decodings (shortest chain first):[/]\n")
    for path, dec in found[:8]:
        console.print(f"[cyan]{' -> '.join(path)}[/]")
        console.print(f"  [green]{dec[:300]}[/]\n")
    pause()


def base_convert() -> None:
    header("Number-base converter", "hex / dec / bin / oct / char in one shot")
    s = Prompt.ask("Value (e.g. 0x41, 65, 0b1000001, or a single char)").strip()
    n = None
    try:
        n = int(s, 0)
    except ValueError:
        if len(s) == 1:
            n = ord(s)
    if n is None:
        console.print("[red]Couldn't parse that value.[/]")
        return pause()
    t = Table(show_header=False, box=None)
    t.add_row("Decimal", str(n))
    t.add_row("Hex", hex(n))
    t.add_row("Octal", oct(n))
    t.add_row("Binary", bin(n))
    if 0 <= n <= 0x10FFFF:
        t.add_row("Char", repr(chr(n)))
    console.print(t)
    pause()


def rot_n() -> None:
    header("ROT-N", "Rotate letters by any N (ROT13 uses 13)")
    s = Prompt.ask("Text")
    try:
        n = int(Prompt.ask("Shift N", default="13")) % 26
    except ValueError:
        console.print("[red]N must be a number.[/]")
        return pause()
    out = "".join(
        chr((ord(c) - base + n) % 26 + base) if c.isalpha() else c
        for c in s for base in [65 if c.isupper() else 97]
    )
    console.print(f"[green]{out}[/]")
    pause()


def atbash() -> None:
    header("Atbash cipher", "Mirror the alphabet (A<->Z, B<->Y ...)")
    s = Prompt.ask("Text")
    out = "".join(
        chr(base + 25 - (ord(c) - base)) if c.isalpha() else c
        for c in s for base in [65 if c.isupper() else 97]
    )
    console.print(f"[green]{out}[/]")
    pause()


def xor_key() -> None:
    header("XOR with key", "Repeating-key XOR -- symmetric encrypt/decrypt")
    text = Prompt.ask("Text (or hex, if you answer yes below)")
    key = Prompt.ask("Key (text)").encode()
    if not key:
        console.print("[red]Key required.[/]")
        return pause()
    as_hex = Prompt.ask("Input is hex?", choices=["y", "n"], default="n") == "y"
    try:
        data = bytes.fromhex(text.replace(" ", "")) if as_hex else text.encode()
    except ValueError:
        console.print("[red]Invalid hex input.[/]")
        return pause()
    out = bytes(c ^ key[i % len(key)] for i, c in enumerate(data))
    console.print(f"[bold]hex  :[/] [green]{out.hex()}[/]")
    console.print(f"[bold]b64  :[/] [green]{base64.b64encode(out).decode()}[/]")
    console.print(f"[bold]bytes:[/] [green]{out.decode(errors='replace')}[/]")
    pause()


def inflate() -> None:
    header("Decompress blob", "Inflate gzip / zlib / raw-deflate data")
    src = Prompt.ask("Input is [b]ase64 or [h]ex", choices=["b", "h"], default="b")
    s = Prompt.ask("Data")
    try:
        raw = base64.b64decode(s + "===") if src == "b" else bytes.fromhex(s.replace(" ", ""))
    except (binascii.Error, ValueError) as e:
        console.print(f"[red]Decode error: {e}[/]")
        return pause()
    for label, fn in (("gzip", gzip.decompress),
                      ("zlib", zlib.decompress),
                      ("raw deflate", lambda d: zlib.decompress(d, -15))):
        try:
            out = fn(raw)
        except Exception:
            continue
        console.print(f"[green]{label}[/] -> {out.decode(errors='replace')[:1000]}")
        return pause()
    console.print("[yellow]Not gzip / zlib / raw-deflate.[/]")
    pause()


MENU = {
    "1": ("Multi-decoder (auto-try everything)", multi_decode),
    "2": ("Magic recursive decoder", magic_decode),
    "3": ("Encoder", encode),
    "4": ("Caesar cipher brute-force", caesar_brute),
    "5": ("Single-byte XOR brute-force", xor_brute),
    "6": ("Number-base converter", base_convert),
    "7": ("ROT-N (any shift)", rot_n),
    "8": ("Atbash cipher", atbash),
    "9": ("XOR with key (encrypt/decrypt)", xor_key),
    "10": ("Decompress gzip/zlib/deflate", inflate),
}
