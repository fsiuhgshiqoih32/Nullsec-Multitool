from __future__ import annotations

import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from .utils import IS_WINDOWS, console, header, pause, report

# Ports we knock on to decide "is this host alive" without needing ICMP/admin.
PROBE_PORTS = (445, 139, 135, 80, 443, 22, 3389)


def local_info() -> None:
    header("Local network info", "Who am I on the network")
    hostname = socket.gethostname()
    local_ip = _primary_ip()
    t = Table(show_header=False, box=None)
    t.add_row("Hostname", hostname)
    t.add_row("Primary IP", local_ip)
    t.add_row("Likely subnet", _subnet_of(local_ip) + ".0/24" if local_ip else "?")
    try:
        _, _, addrs = socket.gethostbyname_ex(hostname)
        t.add_row("All addresses", ", ".join(addrs))
    except socket.gaierror:
        pass
    console.print(t)
    pause()


def _primary_ip() -> str:
    """Trick: open a UDP socket 'to' a public IP; the OS picks our outbound iface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _subnet_of(ip: str) -> str:
    return ".".join(ip.split(".")[:3]) if ip else ""


def _host_alive(ip: str, timeout: float) -> tuple[str, bool, list[int]]:
    open_ports = []
    for port in PROBE_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return ip, bool(open_ports), open_ports


def ping_sweep() -> None:
    header("Host discovery", "TCP ping-sweep of your /24 — finds live hosts, no admin")
    default_subnet = _subnet_of(_primary_ip())
    subnet = console.input(f"Subnet first three octets [[cyan]{default_subnet}[/]]: ").strip() or default_subnet
    timeout = float(console.input("Per-probe timeout (s) [0.3]: ").strip() or "0.3")
    ips = [f"{subnet}.{i}" for i in range(1, 255)]

    alive: list[tuple[str, list[int]]] = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"), console=console) as prog:
        task = prog.add_task(f"Sweeping {subnet}.0/24", total=len(ips))
        with ThreadPoolExecutor(max_workers=256) as pool:
            futs = [pool.submit(_host_alive, ip, timeout) for ip in ips]
            for fut in as_completed(futs):
                ip, up, ports = fut.result()
                if up:
                    alive.append((ip, ports))
                prog.advance(task)

    if not alive:
        console.print("[yellow]No hosts responded on the probe ports. "
                      "They may still be up but firewalled.[/]")
        return pause()

    t = Table(title=f"Live hosts on {subnet}.0/24")
    t.add_column("IP", style="green bold")
    t.add_column("Hostname", style="cyan")
    t.add_column("Open probe ports")
    lines = []
    for ip, ports in sorted(alive, key=lambda x: int(x[0].split(".")[-1])):
        name = _reverse_dns(ip)
        t.add_row(ip, name, ", ".join(map(str, ports)))
        lines.append(f"- {ip} ({name}) ports {ports}")
    console.print(t)
    report.log("network", f"Host discovery {subnet}.0/24", [f"{len(alive)} live hosts:"] + lines)
    pause()


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "-"


def reverse_lookup() -> None:
    header("Reverse DNS", "IP -> hostname")
    ip = console.input("IP: ").strip()
    console.print(f"{ip} -> [cyan]{_reverse_dns(ip)}[/]")
    pause()


def arp_cache() -> None:
    header("ARP cache", "Devices your machine has recently talked to (arp -a)")
    try:
        out = subprocess.run(["arp", "-a"], text=True, capture_output=True, timeout=10)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Couldn't run arp: {e}[/]")
        return pause()
    console.print("[dim]" + out.stdout.strip() + "[/]")
    pause()


def sniff() -> None:
    header("Packet capture", "tcpdump filter builder (root/admin required)")
    from .utils import resolve_tool, run_tool
    if not resolve_tool("tcpdump"):
        console.print("[yellow]tcpdump not installed[/] — [cyan]apt install tcpdump[/]")
        return pause()
    iface = Prompt.ask("Interface", default="any")
    filt = Prompt.ask("BPF filter (e.g. 'port 80 or port 443', 'host 10.0.0.5')",
                      default="tcp")
    count = Prompt.ask("Packet count (0 = until Ctrl-C)", default="50")
    args = ["-i", iface, "-nn", "-A", filt]
    if count != "0":
        args = ["-c", count] + args
    console.print("[bright_black]Capturing creds in cleartext protocols (FTP/HTTP/telnet) "
                  "is a classic MITM finding. Authorized networks only.[/]")
    run_tool("tcpdump", args)
    pause()


def traceroute() -> None:
    header("Traceroute", "Trace the hops to a host (uses the OS tool)")
    target = Prompt.ask("Host/IP", default="8.8.8.8").strip()
    cmd = (["tracert", "-d", "-h", "20", target] if IS_WINDOWS
           else ["traceroute", "-n", "-m", "20", target])
    try:
        subprocess.run(cmd, timeout=120)
    except FileNotFoundError:
        console.print("[red]traceroute/tracert not found on PATH.[/]")
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]{e}[/]")
    pause()


def public_ip() -> None:
    header("Public IP", "Your internet-facing address + ISP/geo")
    try:
        d = requests.get("http://ip-api.com/json/", timeout=8).json()
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    t = Table(show_header=False, box=None)
    for label, key in (("Public IP", "query"), ("ISP", "isp"), ("Org", "org"),
                       ("AS", "as"), ("City", "city"), ("Country", "country")):
        t.add_row(label, str(d.get(key, "?")))
    console.print(t)
    report.log("network", "Public IP", [f"- {d.get('query')} ({d.get('isp')})"])
    pause()


def mac_vendor() -> None:
    header("MAC vendor lookup", "Resolve an OUI (first 3 bytes) to a manufacturer")
    mac = Prompt.ask("MAC address (e.g. 00:1A:2B:3C:4D:5E)").strip()
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=8)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    if r.status_code == 200 and r.text.strip():
        console.print(f"[bold green]{r.text.strip()}[/]")
    else:
        console.print("[yellow]No vendor found for that OUI.[/]")
    pause()


MENU = {
    "1": ("Local network info", local_info),
    "2": ("Host discovery (ping-sweep /24)", ping_sweep),
    "3": ("Reverse DNS lookup", reverse_lookup),
    "4": ("ARP cache (local devices)", arp_cache),
    "5": ("Packet capture (tcpdump)", sniff),
    "6": ("Traceroute", traceroute),
    "7": ("Public IP + geo", public_ip),
    "8": ("MAC vendor (OUI) lookup", mac_vendor),
}
