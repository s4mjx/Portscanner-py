#!/usr/bin/env python3
"""
portscanner.py v3 — Advanced Network Reconnaissance Tool
Author  : s4mjx
GitHub  : github.com/s4mjx
License : MIT

Features:
  - Concurrent TCP scanning with banner grabbing & version detection
  - Smart OS fingerprinting (TTL + service-based fallback)
  - UDP scanning with protocol-aware probes
  - CVE hints and enumeration tips per service
  - Live progress bar
  - Vuln mode: highlight only ports with known CVEs
  - Export: TXT / JSON / CSV
  - Nmap-style organized final report

Usage:
  python3 portscanner.py -t 10.10.10.1
  sudo python3 portscanner.py -t 10.10.10.1 -p 1-65535 -T 500 --udp --vuln
  python3 portscanner.py -t 10.10.10.1 -p 22,80,443,445 --json --csv
"""

import socket
import argparse
import sys
import json
import csv
import struct
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  COLOR SYSTEM                                                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
LGREEN  = "\033[92m"   # open ports, headers, key info
GREEN   = "\033[32m"
RED     = "\033[91m"   # CVE tags, critical
CYAN    = "\033[96m"   # TCP label, service names
YELLOW  = "\033[93m"   # warnings, tips, UDP
MAGENTA = "\033[95m"   # UDP label
WHITE   = "\033[97m"   # target, values
GRAY    = "\033[90m"   # secondary info, progress
ORANGE  = "\033[38;5;214m"  # version strings
BLUE    = "\033[94m"   # OS info
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SERVICE DATABASE                                                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 79: "Finger", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    111: "RPCBind", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE", 502: "Modbus", 514: "Syslog", 515: "LPD",
    587: "SMTP-Sub", 623: "IPMI", 631: "IPP", 636: "LDAPS", 873: "rsync",
    902: "VMware", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS5",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1883: "MQTT",
    2049: "NFS", 2181: "Zookeeper", 2375: "Docker", 2376: "Docker-TLS",
    2379: "etcd", 3000: "Grafana", 3128: "Squid", 3306: "MySQL",
    3389: "RDP", 4369: "RabbitMQ", 4444: "Metasploit", 4848: "GlassFish",
    5000: "Docker-Reg", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    6443: "K8s-API", 7001: "WebLogic", 7474: "Neo4j", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "SonarQube", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "ES-Cluster", 11211: "Memcached",
    15672: "RabbitMQ-UI", 27017: "MongoDB", 50000: "SAP", 50070: "Hadoop",
}

# ── CVE / tip database  ───────────────────────────────────────────────────────
# Format: (ID, description, severity)   severity: CRITICAL / HIGH / MEDIUM / INFO
CVE_DB = {
    "FTP": [
        ("CVE-2011-2523", "vsftpd 2.3.4 backdoor — instant shell on port 6200", "CRITICAL"),
        ("CVE-2010-4221", "ProFTPD 1.3.3c mod_site_exec RCE", "HIGH"),
        ("INFO", "Check for anonymous login: ftp <target>  →  user: anonymous", "INFO"),
        ("INFO", "Try credential bruteforce: hydra -L users.txt -P pass.txt ftp://<target>", "INFO"),
    ],
    "SSH": [
        ("CVE-2023-38408", "OpenSSH ssh-agent remote code execution", "CRITICAL"),
        ("CVE-2018-10933", "libssh 0.6+ authentication bypass", "CRITICAL"),
        ("CVE-2016-6515", "OpenSSH DoS via long passwords", "MEDIUM"),
        ("INFO", "Enumerate supported auth methods: ssh -v user@<target>", "INFO"),
        ("INFO", "Bruteforce: hydra -L users.txt -P pass.txt ssh://<target>", "INFO"),
    ],
    "Telnet": [
        ("CRITICAL", "Cleartext protocol — sniff credentials with Wireshark/tcpdump", "CRITICAL"),
        ("INFO", "Try default creds: admin/admin, root/root, cisco/cisco", "INFO"),
    ],
    "SMTP": [
        ("CVE-2020-7247", "OpenSMTPD remote code execution (LPE + RCE)", "CRITICAL"),
        ("CVE-2014-1692", "Exim heap overflow", "HIGH"),
        ("INFO", "User enumeration: VRFY user  /  EXPN list", "INFO"),
        ("INFO", "Test open relay: MAIL FROM:<x@x.com>  RCPT TO:<victim@gmail.com>", "INFO"),
    ],
    "DNS": [
        ("CVE-2020-1350", "SIGRed — Windows DNS Server unauthenticated RCE", "CRITICAL"),
        ("CVE-2008-1447", "Kaminsky DNS cache poisoning", "HIGH"),
        ("INFO", "Zone transfer: dig axfr @<target> <domain>", "INFO"),
        ("INFO", "Version enum: dig version.bind CHAOS TXT @<target>", "INFO"),
        ("INFO", "Subdomain bruteforce: gobuster dns -d <domain> -w subdomains.txt", "INFO"),
    ],
    "HTTP": [
        ("INFO", "Directory enum: gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt", "INFO"),
        ("INFO", "Tech detection: whatweb http://<target>  /  wappalyzer", "INFO"),
        ("INFO", "Check HTTP methods: curl -v -X OPTIONS http://<target>", "INFO"),
        ("INFO", "Scan with Nikto: nikto -h http://<target>", "INFO"),
    ],
    "HTTPS": [
        ("INFO", "TLS audit: sslscan <target>  /  testssl.sh <target>", "INFO"),
        ("INFO", "Check cert: openssl s_client -connect <target>:443", "INFO"),
        ("INFO", "Directory enum: gobuster dir -u https://<target> -w common.txt -k", "INFO"),
    ],
    "Kerberos": [
        ("INFO", "AS-REP Roasting (no preauth required): impacket-GetNPUsers domain/ -usersfile users.txt", "INFO"),
        ("INFO", "Kerberoasting: impacket-GetUserSPNs domain/user:pass -request", "INFO"),
        ("INFO", "User enum: kerbrute userenum --dc <target> -d domain users.txt", "INFO"),
    ],
    "MSRPC": [
        ("INFO", "Enumerate RPC endpoints: impacket-rpcdump @<target>", "INFO"),
        ("INFO", "NULL session: rpcclient -U '' -N <target>", "INFO"),
        ("INFO", "Enum users via RPC: rpcclient -U '' -N <target> -c 'enumdomusers'", "INFO"),
    ],
    "NetBIOS-SSN": [
        ("INFO", "Related to SMB — enumerate shares and users", "INFO"),
        ("INFO", "nbtscan <target>/24  to map NetBIOS names on the network", "INFO"),
    ],
    "LDAP": [
        ("INFO", "Anonymous bind enum: ldapsearch -x -H ldap://<target> -b 'DC=domain,DC=com'", "INFO"),
        ("INFO", "Full AD dump: ldapdomaindump -u 'domain\\user' -p pass <target>", "INFO"),
        ("INFO", "BloodHound collection: bloodhound-python -u user -p pass -d domain -ns <target> -c All", "INFO"),
    ],
    "SMB": [
        ("CVE-2017-0144", "EternalBlue MS17-010 — unauthenticated RCE (used by WannaCry)", "CRITICAL"),
        ("CVE-2020-0796", "SMBGhost — Windows 10 1903/1909 RCE via SMBv3", "CRITICAL"),
        ("CVE-2021-44142", "Samba out-of-bounds RCE < 4.13.17", "CRITICAL"),
        ("INFO", "Check EternalBlue: nmap --script smb-vuln-ms17-010 -p445 <target>", "INFO"),
        ("INFO", "Null session shares: smbclient -L //<target> -N", "INFO"),
        ("INFO", "Enumerate: netexec smb <target> --shares --users --pass-pol", "INFO"),
    ],
    "RDP": [
        ("CVE-2019-0708", "BlueKeep — pre-auth RCE on Windows 7/2008 (wormable)", "CRITICAL"),
        ("CVE-2019-1182", "DejaBlue — pre-auth RCE on Windows 10/2019", "CRITICAL"),
        ("CVE-2019-0887", "RDP path traversal via clipboard", "HIGH"),
        ("INFO", "Check BlueKeep: nmap --script rdp-vuln-ms12-020 -p3389 <target>", "INFO"),
        ("INFO", "Bruteforce: hydra -L users.txt -P pass.txt rdp://<target>", "INFO"),
    ],
    "MySQL": [
        ("CVE-2012-2122", "Auth bypass via timing attack — any password works", "CRITICAL"),
        ("CVE-2016-6662", "MySQL RCE via malicious config injection", "HIGH"),
        ("INFO", "Connect: mysql -h <target> -u root  (try empty password)", "INFO"),
        ("INFO", "Check for UDF exploitation for privilege escalation", "INFO"),
    ],
    "MSSQL": [
        ("CVE-2020-0618", "SQL Server Reporting Services RCE", "CRITICAL"),
        ("INFO", "Enable xp_cmdshell: EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;", "INFO"),
        ("INFO", "Connect: impacket-mssqlclient domain/user:pass@<target>", "INFO"),
        ("INFO", "Enum: netexec mssql <target> -u user -p pass --local-auth", "INFO"),
    ],
    "PostgreSQL": [
        ("INFO", "Connect: psql -h <target> -U postgres", "INFO"),
        ("INFO", "File read: COPY (SELECT '') TO '/etc/passwd' PROGRAM 'cat /etc/passwd'", "INFO"),
        ("INFO", "RCE via COPY: COPY cmd FROM PROGRAM 'id'", "INFO"),
    ],
    "Redis": [
        ("CVE-2022-0543", "Lua sandbox escape — RCE in Redis < 6.2.6", "CRITICAL"),
        ("CVE-2022-35977", "Integer overflow leading to heap corruption", "HIGH"),
        ("INFO", "Unauthenticated access: redis-cli -h <target>", "INFO"),
        ("INFO", "Write SSH key: redis-cli -h <target> config set dir /root/.ssh", "INFO"),
        ("INFO", "Write cron: config set dir /var/spool/cron/crontabs", "INFO"),
    ],
    "MongoDB": [
        ("INFO", "Connect without auth: mongosh <target>:27017", "INFO"),
        ("INFO", "Dump all DBs: db.adminCommand({listDatabases:1})", "INFO"),
        ("INFO", "NoSQLi in web apps: use $where, $regex, $gt operators", "INFO"),
    ],
    "VNC": [
        ("CVE-2019-15681", "LibVNC 0.9.1 memory leak — info disclosure", "HIGH"),
        ("CVE-2020-14399", "LibVNCClient double-free", "HIGH"),
        ("INFO", "Bruteforce: hydra -P pass.txt vnc://<target>", "INFO"),
        ("INFO", "Connect: vncviewer <target>", "INFO"),
    ],
    "WinRM-HTTP": [
        ("INFO", "Connect with valid creds: evil-winrm -i <target> -u user -p pass", "INFO"),
        ("INFO", "Check auth: netexec winrm <target> -u user -p pass", "INFO"),
        ("INFO", "Kerberos auth: evil-winrm -i <target> -r DOMAIN", "INFO"),
    ],
    "WinRM-HTTPS": [
        ("INFO", "Connect: evil-winrm -i <target> -u user -p pass -S", "INFO"),
    ],
    "NFS": [
        ("INFO", "List exports: showmount -e <target>", "INFO"),
        ("INFO", "Mount share: mount -t nfs <target>:/share /mnt/nfs", "INFO"),
        ("INFO", "Check for no_root_squash — allows root access to mounted share", "INFO"),
    ],
    "SNMP": [
        ("CVE-2017-6736", "Cisco IOS SNMP remote code execution", "CRITICAL"),
        ("INFO", "Enumerate with community 'public': snmpwalk -v2c -c public <target>", "INFO"),
        ("INFO", "Bruteforce community string: onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>", "INFO"),
    ],
    "Docker": [
        ("INFO", "Unauthenticated API: curl http://<target>:2375/containers/json", "INFO"),
        ("INFO", "Escape to host: docker -H tcp://<target>:2375 run -v /:/mnt alpine chroot /mnt sh", "INFO"),
    ],
    "Elasticsearch": [
        ("CVE-2014-3120", "RCE via Groovy sandbox bypass (< 1.6)", "CRITICAL"),
        ("INFO", "List all indices: curl http://<target>:9200/_cat/indices?v", "INFO"),
        ("INFO", "Dump index: curl http://<target>:9200/<index>/_search?size=9999", "INFO"),
    ],
    "Jupyter": [
        ("INFO", "Access notebook: http://<target>:8888  (check for token-free access)", "INFO"),
        ("INFO", "RCE via cell: import os; os.popen('id').read()", "INFO"),
    ],
    "rsync": [
        ("INFO", "List modules: rsync <target>::", "INFO"),
        ("INFO", "Download module: rsync -av <target>::module /local/path", "INFO"),
        ("INFO", "Upload backdoor if write access: rsync shell.php <target>::module/shell.php", "INFO"),
    ],
    "TFTP": [
        ("INFO", "Download config: tftp -i <target> get running-config", "INFO"),
        ("INFO", "Often used on routers/switches — try Cisco/Juniper config files", "INFO"),
    ],
    "Memcached": [
        ("INFO", "Connect: nc <target> 11211  then: stats  /  stats slabs  /  stats items", "INFO"),
        ("INFO", "Dump keys: stats cachedump <slab> 0", "INFO"),
    ],
    "Oracle": [
        ("CVE-2012-1675", "TNS Poison — man-in-the-middle on Oracle DB", "HIGH"),
        ("INFO", "SID enum: odat sidguesser -s <target>", "INFO"),
        ("INFO", "Connect: sqlplus user/pass@<target>:1521/SID", "INFO"),
    ],
    "Grafana": [
        ("CVE-2021-43798", "Grafana path traversal — read any file (e.g. grafana.db)", "CRITICAL"),
        ("CVE-2021-27358", "Snapshot SSRF", "HIGH"),
        ("INFO", "Default creds: admin:admin", "INFO"),
    ],
    "Kibana": [
        ("CVE-2019-7609", "Kibana Timelion RCE — prototype pollution to RCE", "CRITICAL"),
        ("INFO", "Access: http://<target>:5601  — check for unauthenticated access", "INFO"),
    ],
    "RPCBind": [
        ("INFO", "Enumerate RPC services: rpcinfo -p <target>", "INFO"),
        ("INFO", "Often exposes NFS, NIS — check for mountd/nfs in output", "INFO"),
    ],
    "IPMI": [
        ("CVE-2013-4786", "IPMI 2.0 RAKP — hash disclosure, crack offline with hashcat", "CRITICAL"),
        ("INFO", "Enumerate: nmap -sU --script ipmi-version -p623 <target>", "INFO"),
        ("INFO", "Hash dump: msfconsole → use auxiliary/scanner/ipmi/ipmi_dumphashes", "INFO"),
    ],
    "Modbus": [
        ("INFO", "Industrial control system protocol — no authentication", "INFO"),
        ("INFO", "Enumerate: nmap --script modbus-discover -p502 <target>", "INFO"),
    ],
    "WebLogic": [
        ("CVE-2020-14882", "Oracle WebLogic unauthenticated RCE", "CRITICAL"),
        ("CVE-2019-2725", "WebLogic deserialize RCE", "CRITICAL"),
        ("INFO", "Default creds: weblogic:weblogic  /  weblogic:welcome1", "INFO"),
    ],
    "GlassFish": [
        ("CVE-2011-0807", "GlassFish arbitrary file read", "HIGH"),
        ("INFO", "Admin console: http://<target>:4848  — default: admin:adminadmin", "INFO"),
    ],
    "Zookeeper": [
        ("INFO", "Connect: echo ruok | nc <target> 2181", "INFO"),
        ("INFO", "No auth by default — dump config and data", "INFO"),
    ],
    "etcd": [
        ("INFO", "List all keys: curl http://<target>:2379/v3/keys  (Kubernetes secrets!)", "INFO"),
        ("INFO", "Dump: etcdctl --endpoints=http://<target>:2379 get / --prefix", "INFO"),
    ],
    "Squid": [
        ("INFO", "Use as HTTP proxy: curl -x http://<target>:3128 http://internal-host/", "INFO"),
        ("INFO", "May allow access to internal network segments", "INFO"),
    ],
    "AMQP": [
        ("INFO", "RabbitMQ — try default creds: guest:guest", "INFO"),
        ("INFO", "Management UI usually on port 15672", "INFO"),
    ],
    "Hadoop": [
        ("INFO", "HDFS web UI — browse filesystem unauthenticated", "INFO"),
        ("INFO", "Execute commands via YARN ResourceManager API", "INFO"),
    ],
}


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  OS FINGERPRINTING                                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# TTL-based OS detection
TTL_OS_MAP = [
    (64,  "Linux / Unix / Android"),
    (128, "Windows"),
    (254, "Solaris / AIX"),
    (255, "Cisco IOS / Network Device"),
]

# Service-based OS inference (when ICMP is blocked)
# Maps a frozenset of service names → (OS guess, confidence)
SERVICE_OS_SIGNATURES = [
    ({"SMB", "MSRPC", "NetBIOS-SSN", "Kerberos"}, "Windows (Active Directory environment)", "HIGH"),
    ({"SMB", "MSRPC", "NetBIOS-SSN"},              "Windows",                                "HIGH"),
    ({"SMB", "MSRPC"},                              "Windows",                                "MEDIUM"),
    ({"WinRM-HTTP", "RDP"},                         "Windows Server",                         "HIGH"),
    ({"RDP"},                                        "Windows",                                "MEDIUM"),
    ({"NetBIOS-SSN"},                                "Windows or Samba (Linux)",               "LOW"),
    ({"SSH", "NFS", "RPCBind"},                      "Linux / Unix",                           "HIGH"),
    ({"SSH", "MySQL"},                               "Linux (common LAMP stack)",              "MEDIUM"),
    ({"SSH", "PostgreSQL"},                          "Linux",                                  "MEDIUM"),
    ({"SSH"},                                        "Linux / Unix / macOS",                   "LOW"),
]

def guess_os_by_ttl(ttl: int) -> str:
    for limit, name in TTL_OS_MAP:
        if ttl <= limit:
            return name
    return "Unknown"

def guess_os_by_services(open_services: list[str]) -> tuple[str, str] | None:
    """
    Infers the OS from the combination of detected services.
    Returns (os_name, confidence) or None if no match found.
    """
    service_set = set(open_services)
    for signature_set, os_name, confidence in SERVICE_OS_SIGNATURES:
        # Check if all services in the signature are present
        if signature_set.issubset(service_set):
            return (os_name, confidence)
    return None

def guess_os_by_ephemeral_ports(open_ports: list[int]) -> str | None:
    """
    Windows uses ephemeral ports in 49152-65535 (IANA standard).
    Linux uses 32768-60999. If we see many ports in 49152+, it's likely Windows.
    """
    windows_ephemeral = [p for p in open_ports if 49152 <= p <= 65535]
    linux_ephemeral   = [p for p in open_ports if 32768 <= p < 49152]
    if len(windows_ephemeral) >= 3:
        return "Windows (ephemeral port range 49152-65535)"
    if len(linux_ephemeral) >= 3 and not windows_ephemeral:
        return "Linux (ephemeral port range 32768-60999)"
    return None

def get_ttl(host: str, timeout: float = 2.0) -> int | None:
    """
    Sends a raw ICMP echo request and reads the TTL from the IP header.
    Requires root privileges to open a raw socket.
    """
    if os.geteuid() != 0:
        return None
    try:
        icmp_proto = socket.getprotobyname("icmp")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        sock.settimeout(timeout)

        def checksum(data: bytes) -> int:
            s = 0
            for i in range(0, len(data), 2):
                w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
                s = (s + w) & 0xFFFF
            return ~s & 0xFFFF

        payload = b"s4mjx_portscan"
        header  = struct.pack("bbHHh", 8, 0, 0, 1, 1)
        chk     = checksum(header + payload)
        packet  = struct.pack("bbHHh", 8, 0, chk, 1, 1) + payload

        sock.sendto(packet, (host, 0))
        raw, _ = sock.recvfrom(1024)
        sock.close()
        return raw[8]  # TTL is byte 8 of the IP header
    except Exception:
        return None


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  BANNER GRABBING & VERSION DETECTION                                         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# HTTP probes for common web ports
HTTP_PORTS = {80, 8080, 8443, 443, 3000, 8888, 9000, 9090, 15672, 50070}

# Regex patterns to extract version strings from banners
VERSION_PATTERNS = [
    # SSH: "SSH-2.0-OpenSSH_8.4p1 Debian-2+deb11u2"
    (re.compile(r"SSH-\d+\.\d+-(\S+)", re.I),             "SSH"),
    # FTP: "220 ProFTPD 1.3.5e Server"  or  "220 vsFTPd 3.0.3"
    (re.compile(r"220[- ].*?(ProFTPD|vsFTPd|FileZilla|Pure-FTPd)[^\r\n]*", re.I), "FTP"),
    # SMTP: "220 mail.example.com ESMTP Postfix (Debian/GNU)"
    (re.compile(r"220[- ][^\r\n]*?(Postfix|Exim|Sendmail|Exchange)[^\r\n]*", re.I), "SMTP"),
    # HTTP Server header: "Server: Apache/2.4.41 (Ubuntu)"
    (re.compile(r"Server:\s*([^\r\n]+)", re.I),            "HTTP"),
    # Generic version: "220 Pure-FTPd [privsep] [TLS]"
    (re.compile(r"\b(\d+\.\d+[\.\d]*)\b"),                 "generic"),
]

def parse_version(banner: str, service: str) -> str:
    """
    Tries to extract a clean version string from the raw banner.
    Returns the version or empty string if nothing useful is found.
    """
    if not banner:
        return ""
    for pattern, svc_hint in VERSION_PATTERNS:
        if svc_hint in ("generic", service):
            m = pattern.search(banner)
            if m:
                return m.group(1)[:50].strip()
    return ""

def grab_banner(host: str, port: int, timeout: float) -> str:
    """
    Connects to the port and reads whatever the service sends.
    For HTTP ports, sends a HEAD request first to get response headers.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                s.sendall(
                    b"HEAD / HTTP/1.0\r\n"
                    b"Host: " + host.encode() + b"\r\n"
                    b"User-Agent: Mozilla/5.0\r\n\r\n"
                )
            raw    = s.recv(2048)
            banner = raw.decode("utf-8", errors="ignore").strip()
            # Keep the full banner for version parsing, return first line for display
            first  = banner.splitlines()[0] if banner else ""
            return first[:100] if first else ""
    except Exception:
        return ""


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TCP / UDP SCANNING                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return COMMON_PORTS.get(port, "Unknown")

def get_cve_hints(service: str) -> list[tuple[str, str, str]]:
    return CVE_DB.get(service, [])

def scan_tcp(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        banner  = grab_banner(host, port, timeout)
        service = get_service(port)
        version = parse_version(banner, service)
        return {
            "port":    port,
            "proto":   "tcp",
            "state":   "open",
            "service": service,
            "version": version,
            "banner":  banner,
            "cves":    get_cve_hints(service),
        }
    except Exception:
        return None

# Protocol-aware UDP probes — generic \x00*4 gets ignored by most services
UDP_PROBES = {
    53:   b"\xde\xad\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,   # NTP client request
    137:  b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    161:  b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x00\x05\x00",
    500:  b"\x00" * 20 + b"\x01\x10\x02\x00" + b"\x00" * 4,
    623:  b"\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5\x00\x00\x00\x00",  # IPMI
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",  # mDNS
}
UDP_COMMON_PORTS = [53, 69, 111, 123, 137, 161, 162, 500, 514, 623, 1194, 1900, 4500, 5353]

def scan_udp(host: str, port: int, timeout: float) -> dict | None:
    try:
        sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        probe = UDP_PROBES.get(port, b"\x00" * 4)
        sock.sendto(probe, (host, port))
        banner = ""
        try:
            data, _ = sock.recvfrom(1024)
            banner  = data.decode("utf-8", errors="ignore").strip()[:100]
        except socket.timeout:
            # UDP silence ≠ closed; mark as open|filtered (nmap behavior)
            pass
        sock.close()
        service = get_service(port)
        return {
            "port":    port,
            "proto":   "udp",
            "state":   "open" if banner else "open|filtered",
            "service": service,
            "version": "",
            "banner":  banner,
            "cves":    get_cve_hints(service),
        }
    except Exception:
        return None


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  PORT RANGE PARSER                                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def parse_ports(port_range: str) -> list[int]:
    """
    Accepts: "80"  /  "1-1024"  /  "22,80,443"  /  "1-1024,8080,8443"
    """
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"\n{RED}[!] Could not resolve host: {target}{RESET}")
        sys.exit(1)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TERMINAL OUTPUT                                                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

print_lock = Lock()
BAR_WIDTH  = 40

def progress_bar(done: int, total: int) -> str:
    pct    = done / total
    filled = int(BAR_WIDTH * pct)
    bar    = f"{LGREEN}{'█' * filled}{GRAY}{'░' * (BAR_WIDTH - filled)}"
    return f"\r  {GRAY}[{bar}{GRAY}] {LGREEN}{done}{GRAY}/{total}{RESET}  "

def severity_color(severity: str) -> str:
    return {
        "CRITICAL": RED,
        "HIGH":     ORANGE,
        "MEDIUM":   YELLOW,
        "INFO":     GRAY,
    }.get(severity, GRAY)

def print_port_result(r: dict, vuln_only: bool = False):
    """
    Prints a single open port with service, version, banner and CVE hints.
    If vuln_only is True, only ports with CVE entries are printed.
    """
    has_cves = any(e[2] in ("CRITICAL", "HIGH", "MEDIUM") for e in r["cves"])
    if vuln_only and not has_cves:
        return

    proto_str   = f"{CYAN}TCP{RESET}" if r["proto"] == "tcp" else f"{MAGENTA}UDP{RESET}"
    state_str   = f"{LGREEN}{r['state']}{RESET}" if r["state"] == "open" else f"{YELLOW}{r['state']}{RESET}"
    version_str = f"  {ORANGE}{r['version']}{RESET}" if r["version"] else ""
    banner_str  = f"  {GRAY}{r['banner']}{RESET}"    if r["banner"] and not r["version"] else ""

    with print_lock:
        sys.stdout.write("\r" + " " * 76 + "\r")
        # Port line
        print(
            f"  {LGREEN}{r['port']:<7}{RESET}"
            f"{proto_str}  "
            f"{state_str:<18}"
            f"{LGREEN}{r['service']:<18}{RESET}"
            f"{version_str}{banner_str}"
        )
        # CVE / tip lines
        for cve_id, desc, severity in r["cves"]:
            sc  = severity_color(severity)
            tag = f"{sc}[{severity[:4]}]{RESET}"
            cve_label = f"{sc}{cve_id}{RESET}" if not cve_id.startswith("INFO") else ""
            sep = " — " if cve_label else ""
            print(f"  {'':<7}   {tag} {cve_label}{sep}{GRAY}{desc}{RESET}")

def print_header(target: str, ip: str, ports: list[int], threads: int,
                 udp: bool, vuln_only: bool, has_root: bool, start_time: str):
    udp_s  = f"{LGREEN}enabled{RESET}"  if udp      else f"{GRAY}disabled{RESET}"
    vuln_s = f"{RED}ON — showing CVE ports only{RESET}" if vuln_only else f"{GRAY}off{RESET}"
    root_s = f"{LGREEN}yes — TTL fingerprinting active{RESET}" if has_root else f"{YELLOW}no — run with sudo for ICMP OS detection{RESET}"
    print(f"""
{LGREEN}{BOLD}╔══════════════════════════════════════════════════════╗
║           portscanner.py  ·  by s4mjx  ·  v3.0      ║
╚══════════════════════════════════════════════════════╝{RESET}
{LGREEN}  Target     :{RESET} {WHITE}{target} ({ip}){RESET}
{LGREEN}  Port range :{RESET} {ports[0]}–{ports[-1]}  ({len(ports)} ports)
{LGREEN}  Threads    :{RESET} {threads}
{LGREEN}  UDP scan   :{RESET} {udp_s}
{LGREEN}  Vuln mode  :{RESET} {vuln_s}
{LGREEN}  Root       :{RESET} {root_s}
{LGREEN}  Started    :{RESET} {start_time}
{"─" * 54}
  {"PORT":<7} {"PROTO":<5} {"STATE":<12} {"SERVICE":<18} VERSION / BANNER
{"─" * 54}""")

def print_final_report(target: str, ip: str, open_ports: list[dict],
                        os_result: dict, elapsed: float, args):
    """
    Prints the structured final report — similar in depth to nmap -sV output
    but organized for readability and pentesting workflow.
    """
    tcp_open   = [r for r in open_ports if r["proto"] == "tcp" and r["state"] == "open"]
    udp_open   = [r for r in open_ports if r["proto"] == "udp" and r["state"] == "open"]
    udp_filt   = [r for r in open_ports if r["proto"] == "udp" and r["state"] == "open|filtered"]
    crit_ports = [r for r in open_ports if any(e[2] == "CRITICAL" for e in r["cves"])]
    high_ports = [r for r in open_ports if any(e[2] == "HIGH"     for e in r["cves"])
                  and r not in crit_ports]

    div = f"{GRAY}{'─' * 54}{RESET}"

    print(f"\n{div}")
    print(f"\n{LGREEN}{BOLD}  SCAN SUMMARY{RESET}  {GRAY}──  {target} ({ip}){RESET}\n")

    # ── OS ────────────────────────────────────────────────────────────────────
    print(f"  {LGREEN}OS Detection{RESET}")
    if os_result["method"] == "ttl":
        print(f"    {BLUE}Method    :{RESET} ICMP TTL fingerprinting")
        print(f"    {BLUE}TTL value :{RESET} {os_result['ttl']}")
        print(f"    {BLUE}OS guess  :{RESET} {WHITE}{os_result['os']}{RESET}  {GRAY}(confidence: HIGH){RESET}")
    elif os_result["method"] == "service":
        print(f"    {BLUE}Method    :{RESET} Service signature analysis (ICMP blocked)")
        print(f"    {BLUE}OS guess  :{RESET} {WHITE}{os_result['os']}{RESET}  {GRAY}(confidence: {os_result.get('confidence','?')}){RESET}")
        print(f"    {BLUE}Reason    :{RESET} {GRAY}{os_result.get('reason','')}{RESET}")
    elif os_result["method"] == "ephemeral":
        print(f"    {BLUE}Method    :{RESET} Ephemeral port range analysis")
        print(f"    {BLUE}OS guess  :{RESET} {WHITE}{os_result['os']}{RESET}")
    else:
        print(f"    {GRAY}Could not determine OS — try with sudo or add --udp{RESET}")
    print()

    # ── Open ports table ──────────────────────────────────────────────────────
    print(f"  {LGREEN}Open Ports{RESET}")
    print(f"    {GRAY}{'PORT':<7} {'PROTO':<5} {'STATE':<16} {'SERVICE':<18} VERSION{RESET}")
    print(f"    {GRAY}{'─'*66}{RESET}")
    for r in open_ports:
        proto_s   = f"{CYAN}tcp{RESET}"     if r["proto"] == "tcp"  else f"{MAGENTA}udp{RESET}"
        state_col = LGREEN if r["state"] == "open" else YELLOW
        ver_s     = f"{ORANGE}{r['version']}{RESET}" if r["version"] else f"{GRAY}{r['banner'][:40]}{RESET}" if r["banner"] else ""
        print(
            f"    {LGREEN}{r['port']:<7}{RESET}"
            f"{proto_s}  "
            f"{state_col}{r['state']:<16}{RESET}"
            f"{LGREEN}{r['service']:<18}{RESET}"
            f"{ver_s}"
        )
    print()

    # ── Critical findings ─────────────────────────────────────────────────────
    if crit_ports or high_ports:
        print(f"  {RED}{BOLD}Critical & High Risk Findings{RESET}")
        for r in crit_ports + high_ports:
            for cve_id, desc, sev in r["cves"]:
                if sev in ("CRITICAL", "HIGH"):
                    sc = severity_color(sev)
                    print(f"    {sc}[{sev}]{RESET} Port {LGREEN}{r['port']}/{r['proto']}{RESET} ({r['service']}) — {sc}{cve_id}{RESET}")
                    print(f"    {GRAY}         {desc}{RESET}")
        print()

    # ── Recommended next steps ────────────────────────────────────────────────
    print(f"  {LGREEN}Recommended Next Steps{RESET}")
    printed_steps = set()
    priority_services = ["SMB", "RDP", "MSRPC", "Kerberos", "LDAP", "WinRM-HTTP",
                         "WinRM-HTTPS", "MySQL", "MSSQL", "PostgreSQL", "Redis",
                         "MongoDB", "Docker", "Elasticsearch", "NFS", "SNMP",
                         "HTTP", "HTTPS", "SSH", "FTP"]
    for svc in priority_services:
        matching = [r for r in open_ports if r["service"] == svc]
        for r in matching:
            for cve_id, desc, sev in r["cves"]:
                if sev == "INFO" and desc not in printed_steps:
                    print(f"    {GRAY}►{RESET} [{LGREEN}{r['service']}{RESET}:{r['port']}] {desc}")
                    printed_steps.add(desc)

    # ── Statistics ────────────────────────────────────────────────────────────
    print(f"\n{div}")
    print(f"  {LGREEN}TCP open      :{RESET} {LGREEN}{len(tcp_open)}{RESET}")
    if args.udp:
        print(f"  {MAGENTA}UDP open      :{RESET} {MAGENTA}{len(udp_open)}{RESET}  {GRAY}({len(udp_filt)} open|filtered){RESET}")
    print(f"  {RED}Critical CVEs :{RESET} {RED}{len(crit_ports)}{RESET}  ports affected")
    print(f"  {ORANGE}High CVEs     :{RESET} {ORANGE}{len(high_ports)}{RESET}  ports affected")
    print(f"  {LGREEN}Scan time     :{RESET} {elapsed:.1f}s")
    print(f"  {LGREEN}Completed     :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  EXPORT                                                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def export_txt(results: list[dict], target: str, ip: str, os_result: dict, path: str):
    with open(path, "w") as f:
        f.write(f"# portscanner.py v3 — s4mjx\n")
        f.write(f"Target  : {target} ({ip})\n")
        f.write(f"OS      : {os_result.get('os', 'N/A')}\n")
        f.write(f"Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("─" * 60 + "\n")
        f.write(f"{'PORT':<7} {'PROTO':<5} {'STATE':<16} {'SERVICE':<18} VERSION\n")
        f.write("─" * 60 + "\n")
        for r in results:
            f.write(f"{r['port']:<7} {r['proto'].upper():<5} {r['state']:<16} {r['service']:<18} {r['version'] or r['banner']}\n")
            for cve_id, desc, sev in r["cves"]:
                f.write(f"         [{sev}] {cve_id} — {desc}\n")
    print(f"  {LGREEN}[+] TXT   :{RESET} {path}")

def export_json(results: list[dict], target: str, ip: str, os_result: dict, path: str):
    data = {
        "meta": {
            "tool": "portscanner.py v3 — s4mjx",
            "target": target,
            "ip": ip,
            "os": os_result,
            "scan_date": datetime.now().isoformat(),
        },
        "open_ports": results,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  {LGREEN}[+] JSON  :{RESET} {path}")

def export_csv(results: list[dict], path: str):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["port", "proto", "state", "service", "version", "banner", "cve_ids", "severity"])
        for r in results:
            cve_ids = "; ".join(c[0] for c in r["cves"] if not c[0].startswith("INFO"))
            sevs    = "; ".join(c[2] for c in r["cves"] if not c[0].startswith("INFO"))
            w.writerow([r["port"], r["proto"], r["state"], r["service"],
                        r["version"], r["banner"], cve_ids, sevs])
    print(f"  {LGREEN}[+] CSV   :{RESET} {path}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MAIN                                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def main():
    parser = argparse.ArgumentParser(
        description="portscanner.py v3 — Advanced TCP/UDP network reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 portscanner.py -t 10.10.10.1\n"
            "  sudo python3 portscanner.py -t 10.10.10.1 -p 1-65535 -T 500 --udp\n"
            "  sudo python3 portscanner.py -t 10.10.10.1 -p 1-65535 --udp --vuln --json --csv\n"
            "  python3 portscanner.py -t 10.10.10.1 -p 22,80,139,443,445 -o report.txt\n"
        ),
    )
    parser.add_argument("-t",  "--target",  required=True,          help="Target host or IP address")
    parser.add_argument("-p",  "--ports",   default="1-1024",       help="Port range: 1-65535 / 22,80,443 / 1-1000,8080 (default: 1-1024)")
    parser.add_argument("-T",  "--threads", type=int, default=200,  help="Concurrent threads (default: 200)")
    parser.add_argument("--timeout",        type=float, default=1.0,help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--udp",            action="store_true",    help="Enable UDP scan on common ports")
    parser.add_argument("--vuln",           action="store_true",    help="Show only ports with known CVEs (Critical/High/Medium)")
    parser.add_argument("-o",  "--output",  help="Save report to .txt file")
    parser.add_argument("--json",           action="store_true",    help="Export results to JSON")
    parser.add_argument("--csv",            action="store_true",    help="Export results to CSV")
    args = parser.parse_args()

    target    = args.target
    ip        = resolve_host(target)
    ports     = parse_ports(args.ports)
    has_root  = (os.geteuid() == 0)
    t_start   = time.time()
    start_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print_header(target, ip, ports, args.threads, args.udp, args.vuln, has_root, start_str)

    # ── OS detection: ICMP TTL ────────────────────────────────────────────────
    os_result = {"method": "none", "os": "Unknown"}
    if has_root:
        sys.stdout.write(f"  {GRAY}[*] ICMP TTL fingerprinting...{RESET}")
        sys.stdout.flush()
        ttl = get_ttl(ip)
        if ttl:
            os_name   = guess_os_by_ttl(ttl)
            os_result = {"method": "ttl", "os": os_name, "ttl": ttl}
            sys.stdout.write(f"\r  {BLUE}[OS]{RESET} {WHITE}{os_name}{RESET}  {GRAY}(TTL={ttl}){RESET}                    \n")
        else:
            sys.stdout.write(f"\r  {YELLOW}[OS]{RESET} {GRAY}No ICMP response — will infer from services{RESET}                    \n")
        sys.stdout.flush()
    else:
        print(f"  {YELLOW}[OS]{RESET} {GRAY}Run with sudo to enable ICMP TTL fingerprinting{RESET}")

    print(f"\n  {'PORT':<7} {'PROTO':<5} {'STATE':<12} {'SERVICE':<18} VERSION / BANNER")
    print(f"{'─' * 54}")

    # ── TCP scan ──────────────────────────────────────────────────────────────
    open_ports: list[dict] = []
    done = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_tcp, ip, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            done += 1
            sys.stdout.write(progress_bar(done, len(ports)))
            sys.stdout.flush()
            result = future.result()
            if result:
                open_ports.append(result)
                print_port_result(result, vuln_only=args.vuln)

    # ── UDP scan ──────────────────────────────────────────────────────────────
    if args.udp:
        sys.stdout.write("\r" + " " * 76 + "\r")
        print(f"\n{'─' * 54}")
        print(f"  {MAGENTA}[*] UDP scan — {len(UDP_COMMON_PORTS)} common ports...{RESET}\n")
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_udp, ip, p, args.timeout * 2): p for p in UDP_COMMON_PORTS}
            for future in as_completed(futures):
                r = future.result()
                if r:
                    open_ports.append(r)
                    print_port_result(r, vuln_only=args.vuln)

    # ── OS inference from services (TTL fallback) ─────────────────────────────
    if os_result["method"] == "none" or (os_result["method"] == "ttl" and "Unknown" in os_result["os"]):
        all_services = [r["service"] for r in open_ports]
        all_port_nums = [r["port"] for r in open_ports]

        svc_guess = guess_os_by_services(all_services)
        eph_guess = guess_os_by_ephemeral_ports(all_port_nums)

        if svc_guess:
            os_name, confidence = svc_guess
            matched = [s for s in all_services if s in str(SERVICE_OS_SIGNATURES)]
            os_result = {
                "method":     "service",
                "os":         os_name,
                "confidence": confidence,
                "reason":     f"Detected services: {', '.join(set(all_services))}",
            }
            sys.stdout.write("\r" + " " * 76 + "\r")
            print(f"\n  {BLUE}[OS]{RESET} {WHITE}{os_name}{RESET}  {GRAY}(method: service fingerprint, confidence: {confidence}){RESET}")
        elif eph_guess:
            os_result = {"method": "ephemeral", "os": eph_guess}
            sys.stdout.write("\r" + " " * 76 + "\r")
            print(f"\n  {BLUE}[OS]{RESET} {WHITE}{eph_guess}{RESET}  {GRAY}(method: ephemeral port range analysis){RESET}")

    # ── Sort results ──────────────────────────────────────────────────────────
    open_ports.sort(key=lambda x: (x["proto"] != "tcp", x["port"]))

    # ── Final report ──────────────────────────────────────────────────────────
    elapsed = time.time() - t_start
    sys.stdout.write("\r" + " " * 76 + "\r")
    print_final_report(target, ip, open_ports, os_result, elapsed, args)

    # ── Exports ───────────────────────────────────────────────────────────────
    base = f"scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if args.output:
        export_txt(open_ports, target, ip, os_result, args.output)
    if args.json:
        export_json(open_ports, target, ip, os_result, base + ".json")
    if args.csv:
        export_csv(open_ports, base + ".csv")
    if args.output or args.json or args.csv:
        print()


if __name__ == "__main__":
    main()
