# portscanner.py v3

Advanced TCP/UDP network reconnaissance tool — built in Python with zero external dependencies.

Designed as a serious pentesting utility and HTB companion. Structured output inspired by nmap -sV, with CVE intelligence, smart OS fingerprinting, and multi-format export built in.

---

## Features

| Feature | Description |
|---------|-------------|
| TCP scanning | Concurrent threads — handles 65k ports efficiently |
| Banner grabbing | Reads raw service banners + HTTP response headers |
| Version detection | Parses SSH, FTP, SMTP, HTTP Server headers automatically |
| OS fingerprinting | ICMP TTL (primary) + service signature + ephemeral port fallback |
| UDP scanning | 14 common UDP ports with protocol-aware probes (DNS, NTP, SNMP, IPMI...) |
| CVE database | 40+ services mapped to CVEs with severity: CRITICAL / HIGH / MEDIUM |
| Tip database | Enumeration commands per service (gobuster, crackmapexec, impacket...) |
| Vuln mode | `--vuln` — show only ports with known CVEs, ignore the rest |
| Progress bar | Live scan progress in green |
| Final report | Structured summary: OS, open ports table, critical findings, next steps |
| Multi-export | .txt / .json / .csv |

---

## Requirements

Pure Python 3.10+ — no pip, no virtualenv, no dependencies.

```bash
python3 --version  # must be 3.10+
```

---

## Usage

```bash
python3 portscanner.py -t <target> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Target host or IP | required |
| `-p` | Port range: `1-65535`, `22,80,443`, `1-1000,8080` | `1-1024` |
| `-T` | Concurrent threads | `200` |
| `--timeout` | Connection timeout in seconds | `1.0` |
| `--udp` | UDP scan on 14 common ports | off |
| `--vuln` | Show only ports with CVE entries | off |
| `-o` | Save report as .txt | — |
| `--json` | Export to JSON | off |
| `--csv` | Export to CSV | off |

---

## Examples

```bash
# Quick scan — default range
python3 portscanner.py -t 10.10.10.1

# Full TCP + OS detection (sudo needed for ICMP TTL)
sudo python3 portscanner.py -t 10.10.10.1 -p 1-65535 -T 500

# Full pentest scan — TCP + UDP + vuln mode + all exports
sudo python3 portscanner.py -t 10.10.10.1 -p 1-65535 -T 500 --udp --vuln --json --csv

# Target specific ports, save txt report
python3 portscanner.py -t 10.10.10.1 -p 22,80,139,443,445,3389,5985 -o report.txt

# HTB typical workflow
sudo python3 portscanner.py -t 10.129.X.X -p 1-65535 -T 500 --udp --json
```

---

## OS Detection — 3 methods in cascade

The tool tries three methods in order, falling back gracefully if each fails:

**1. ICMP TTL fingerprinting** (requires sudo) — sends a raw ICMP echo and reads the TTL byte from the IP header. Different OS families reset the TTL to different starting values (Linux=64, Windows=128, Cisco=255).

**2. Service signature matching** — if ICMP is blocked (very common on HTB machines and firewalls), the tool looks at the combination of detected services and matches it against known OS profiles. Seeing `MSRPC + NetBIOS-SSN + SMB + Kerberos` together is an unambiguous Windows Active Directory signature.

**3. Ephemeral port range analysis** — Windows assigns dynamic RPC ports in the 49152-65535 range (IANA standard). Linux uses 32768-60999. If three or more ports appear in the Windows range, it's reported as Windows even with no other evidence.

---

## CVE Coverage (selected)

| Service | Notable CVEs |
|---------|-------------|
| SMB 445 | EternalBlue MS17-010, SMBGhost CVE-2020-0796 |
| RDP 3389 | BlueKeep CVE-2019-0708, DejaBlue CVE-2019-1182 |
| Redis 6379 | Lua sandbox escape CVE-2022-0543 |
| WebLogic 7001 | CVE-2020-14882, CVE-2019-2725 |
| Grafana 3000 | Path traversal CVE-2021-43798 |
| IPMI 623 | Hash disclosure CVE-2013-4786 |
| Kerberos 88 | AS-REP Roasting, Kerberoasting (with impacket commands) |
| LDAP 389 | Full AD enumeration commands included |
| + 35 more | ... |

---

## Final Report Structure

After the scan, the tool generates a structured report section with:

- OS detection result and method used
- Clean open ports table with version strings
- Critical & High severity findings grouped
- Recommended next steps — actual commands to run on each detected service

---

## Legal disclaimer

For authorized testing and educational purposes only.  
Never scan systems without explicit written permission.

---

## Author

**s4mjx** — HTB player · studying pentesting · CJCA → CPTS → CAPE  
AI Security / Red Teaming specialization track
