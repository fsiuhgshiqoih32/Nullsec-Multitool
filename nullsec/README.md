# nullsec

A menu-driven security multitool — recon, password cracking, crypto and cipher breaking, forensics, steganography, OSINT, web/API testing, email/phishing analysis, and IOC extraction, all behind one prompt. Most of it runs on pure Python with no setup, while heavier tools like nmap, sqlmap, hydra, nuclei, and metasploit light up automatically once they're installed (natively or through WSL). See [USAGE.md](USAGE.md) to get it running.

Quick start: `pip install -r requirements.txt` then `python main.py`. Optional extras (`cryptography`, `pillow`, `dnspython`) unlock a few extra tools and degrade gracefully when they're missing.

> Authorized use only — your own machines, lab VMs, and CTF / training targets.

_Made by anonymous._
