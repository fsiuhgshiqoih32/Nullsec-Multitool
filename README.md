```

```

# nullsec

A menu-driven, modular security toolkit in Python — one launcher bundling recon,
hashing/cracking, crypto, password, web, and network tooling, a payload arsenal,
and an index/launcher for **50,000+ real exploits and tools**. Built to **learn how
these tools actually work**, not just to run them.

> **On the "10,000+ tools" claim:** nobody hand-writes 10,000 working exploits —
> Kali ships ~600 packages, Metasploit ~2,300 modules. nullsec reaches big real
> numbers honestly: it **generates** dozens of working payloads, **curates** an
> index of real tools with install/launch, and **front-ends** the giant public
> databases — Exploit-DB (~45,000 via `searchsploit`), Nuclei (~9,000 templates),
> Metasploit (~2,300). The home screen counts what's genuinely reachable. Nothing
> is a fake stub.



## Run

```bash
cd security-multitool
pip install rich pyfiglet requests
python main.py
```

## What's inside

| Category | Module | Highlights |
|----------|--------|------------|
| Reconnaissance | `toolkit/recon.py` | From-scratch threaded TCP port scanner + banner grab (no nmap needed), plus an nmap hand-off |
| Hashes & Cracking | `toolkit/hashes.py` | Hash identifier, digest calculator, **John the Ripper** + **hashcat** drivers, practice-hash generator |
| Crypto & Encoding | `toolkit/crypto.py` | Auto multi-decoder, encoder, Caesar brute-force, single-byte XOR brute-force |
| Passwords | `toolkit/passwords.py` | Entropy/strength estimate, targeted wordlist generator (leetspeak + suffixes) |
| Web | `toolkit/web.py` | HTTP security-header audit, TLS certificate inspector, robots/sitemap/security.txt, ffuf/gobuster dir-brute |
| Network | `toolkit/network.py` | Local interface info, TCP ping-sweep host discovery (/24), reverse DNS, ARP cache |
| Payload Arsenal | `toolkit/arsenal.py` | 64 real payloads: reverse shells (25+ langs), bind shells, web shells, msfvenom builder, listeners — parametrised by your LHOST/LPORT, powershell auto-base64 |
| Tool Catalog | `toolkit/catalog.py` | 126 curated real tools (install cmd + installed-detection + launch), plus Exploit-DB / Nuclei / Metasploit front-ends and a BlackArch importer (~2,800 more) |
| Brute-force | `toolkit/bruteforce.py` | hydra login brute-force (ssh/ftp/smb/rdp/http-form…), runs natively or via WSL |
| Cipher Lab | `toolkit/cryptotools.py` | **From-scratch cryptanalysis:** repeating-key XOR breaker, Vigenère breaker, cipher identifier, Morse, rail-fence, base58, JWT decode/analyze, JWT HMAC cracker |
| Forensics | `toolkit/forensics.py` | strings, hexdump, magic-byte ID, **embedded-file carver**, entropy scan, UUID/timestamp decoders, regex **secret scanner** |
| OSINT & DNS | `toolkit/osint.py` | **Raw-packet DNS resolver**, **socket WHOIS client**, CIDR calculator, **Shodan favicon hash (MurmurHash3 by hand)**, email/subdomain permutators, dork generator |
| Generators | `toolkit/generators.py` | diceware passphrases, PIN/keyboard-walk wordlists, **Markov password generator**, hashcat-style rule mutator, **HIBP k-anonymity check** |
| Steganography | `toolkit/stego.py` | **zero-width unicode** text hiding, **whitespace** encoding, and **BMP LSB** image steg — hide & extract, all from scratch |
| Payload Forge | `toolkit/payloadenc.py` | payload multi-encoder (URL/base64/hex/unicode/HTML/mixed-case), XSS WAF-bypass variants, categorized SQLi, **shell-stabilization cheat sheet** |
| HTTP Interceptor | `toolkit/interceptor.py` | **catch-all callback listener** (blind SSRF/XSS canary), quick file server for transfers, Burp-Repeater-style request replayer |
| Install Arsenal | `toolkit/installer.py` | One-stop installer: bootstraps BlackArch in WSL, installs curated/full toolset, plus a Windows-native subset |

The **Crypto** menu also has a **magic recursive decoder** that auto-detects and
peels nested base64/hex/url/rot/binary layers until it finds a flag or readable text.

The **Cipher Lab**, **Forensics**, **OSINT**, and **Generators** tools are all
original implementations — no shelling out. The XOR/Vigenère breakers are real
cryptanalysis (key-size detection + per-column frequency/χ² analysis), the DNS
resolver and WHOIS client build and parse packets over raw sockets, and the
favicon hasher reimplements MurmurHash3 to match Shodan's `http.favicon.hash`.

### Cross-platform

nullsec detects its platform: on **Windows** it bridges into WSL (auto-detecting the
distro — arch/kali/ubuntu/debian) to drive Linux tools; on **Linux/macOS** every
tool resolves natively with no WSL layer. The installer picks pacman/apt/dnf/brew
accordingly.

## Installing the real tools

nullsec's built-in modules work with no installs. To light up the external tools
(nmap, metasploit, hydra, sqlmap, nuclei, aircrack…), use **home menu → `i`**:

- **Windows:** the installer drives your **WSL Arch** distro, bootstraps the
  **BlackArch** repo, and `pacman`-installs the toolset. nullsec then detects and
  runs those tools through WSL automatically (paths are translated). Two GUI tools
  (Nmap, Wireshark) need a UAC prompt — install them natively with:
  ```
  winget install -e --id Nmap.Nmap; winget install -e --id WiresharkFoundation.Wireshark
  ```
- **Linux:** it uses pacman (Arch/BlackArch) or apt (Kali/Debian) directly.

The `install_arsenal.sh` / `install_windows_native.sh` scripts are the same logic,
runnable standalone.

Plus a **session report** (`r` on the home menu): recon/web/network findings are
logged as you go and can be saved to a timestamped Markdown file.

Built-in scanners/crackers use only the Python standard library (+`requests` for
web). Heavy external tools (John, hashcat, nmap, ffuf, gobuster, hydra) are
**optional** — the toolkit auto-detects what's installed (menu option `t`) and only
enables those modules.

## First thing to try

1. `python main.py` → `2` (Hashes) → `5` to generate a file of practice MD5 hashes.
2. Grab a wordlist (e.g. `rockyou.txt`) and install John the Ripper (jumbo build).
3. `2` → `3`, point John at the practice file with format `raw-md5` and your wordlist.
4. Watch it crack `password`, `letmein`, etc. — the full pipeline end to end.

Then try `6` → `2` to discover live hosts on your own LAN, and `5` → `1` to grade a
website's security headers.

## Architecture

Each category is a module exposing a `MENU` dict of `{key: (label, function)}`.
`main.py` just renders menus and dispatches. **Adding a tool = write one function
and add one line to a `MENU`.** That's the whole extension model.

## Roadmap ideas

- Packet sniffing / deeper network analysis (scapy)
- hydra / network login brute hand-off (detector already wired)
- Config file for default wordlist paths and timeouts
- Export report to HTML as well as Markdown
```
