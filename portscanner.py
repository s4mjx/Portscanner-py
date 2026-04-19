#!/usr/bin/env python3
"""
portscanner.py — TCP port scanner with banner grabbing
Author : s4mjx
GitHub : github.com/s4mjx
Usage  : python3 portscanner.py -t 10.10.10.1 -p 1-1000 -T 200 --timeout 1
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── ANSI colors ───────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ── Common service names (fallback si socket.getservbyport falla) ─────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 1433: "MSSQL", 11211: "Memcached",
}

def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return COMMON_PORTS.get(port, "Unknown")

def grab_banner(host: str, port: int, timeout: float) -> str:
    """Intenta leer el banner que el servicio envía al conectar."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # HTTP necesita que enviemos algo primero
            if port in (80, 8080, 8443, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            raw = s.recv(1024)
            banner = raw.decode("utf-8", errors="ignore").strip()
            # Solo primera línea, limpia
            first_line = banner.splitlines()[0] if banner else ""
            return first_line[:80] if first_line else ""
    except Exception:
        return ""

def scan_port(host: str, port: int, timeout: float) -> dict | None:
    """Devuelve info del puerto si está abierto, None si está cerrado."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        banner  = grab_banner(host, port, timeout)
        service = get_service(port)
        return {"port": port, "service": service, "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def parse_ports(port_range: str) -> list[int]:
    """Acepta '80', '1-1000', o '22,80,443'."""
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{RED}[!] No se pudo resolver el host: {target}{RESET}")
        sys.exit(1)

def print_banner_header(target: str, ip: str, ports: list[int], threads: int):
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════╗
║           portscanner.py  by s4mjx          ║
╚══════════════════════════════════════════════╝{RESET}
{YELLOW}  Target  :{RESET} {target} ({ip})
{YELLOW}  Ports   :{RESET} {ports[0]}–{ports[-1]} ({len(ports)} puertos)
{YELLOW}  Threads :{RESET} {threads}
{YELLOW}  Started :{RESET} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'─' * 48}
  {'PORT':<8} {'SERVICE':<14} {'BANNER'}
{'─' * 48}""")

def main():
    parser = argparse.ArgumentParser(
        description="TCP port scanner con banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplos:\n"
               "  python3 portscanner.py -t 10.10.10.1\n"
               "  python3 portscanner.py -t 10.10.10.1 -p 1-65535 -T 500\n"
               "  python3 portscanner.py -t scanme.nmap.org -p 22,80,443",
    )
    parser.add_argument("-t", "--target",  required=True,   help="Host o IP objetivo")
    parser.add_argument("-p", "--ports",   default="1-1024", help="Rango de puertos (default: 1-1024)")
    parser.add_argument("-T", "--threads", type=int, default=200, help="Hilos concurrentes (default: 200)")
    parser.add_argument("--timeout",       type=float, default=1.0, help="Timeout por conexión en segundos (default: 1)")
    parser.add_argument("-o", "--output",  help="Guardar resultados en un archivo .txt")
    args = parser.parse_args()

    target = args.target
    ip     = resolve_host(target)
    ports  = parse_ports(args.ports)

    print_banner_header(target, ip, ports, args.threads)

    open_ports = []
    results_lines = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    # Ordenar por número de puerto
    open_ports.sort(key=lambda x: x["port"])

    for r in open_ports:
        banner_str = f"  {YELLOW}{r['banner']}{RESET}" if r["banner"] else ""
        line = f"  {GREEN}{r['port']:<8}{RESET} {CYAN}{r['service']:<14}{RESET}{banner_str}"
        print(line)
        results_lines.append(f"{r['port']:<8} {r['service']:<14} {r['banner']}")

    total = len(open_ports)
    print(f"\n{'─' * 48}")
    print(f"  {GREEN}{BOLD}{total} puerto(s) abierto(s){RESET} encontrados en {target}")
    print(f"  Finalizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Scan de {target} ({ip})\n")
            f.write(f"{'PORT':<8} {'SERVICE':<14} BANNER\n")
            f.write("─" * 48 + "\n")
            for line in results_lines:
                f.write(line + "\n")
        print(f"  {CYAN}[+] Resultados guardados en: {args.output}{RESET}\n")

if __name__ == "__main__":
    main()
