# portscanner

TCP port scanner with banner grabbing — implemented in Python and Go for performance comparison.

Built as a learning exercise while studying penetration testing through Hack The Box.

---

## Features

- Concurrent scanning (threads in Python / goroutines in Go)
- Banner grabbing on open ports
- Service name detection
- Output to `.txt` file
- Clean terminal output with ANSI colors

---

## Python version

### Requirements

No external dependencies — pure stdlib.

```bash
python3 portscanner.py -t <target> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Target host or IP | required |
| `-p` | Port range (`1-1000`, `22,80,443`) | `1-1024` |
| `-T` | Number of threads | `200` |
| `--timeout` | Connection timeout (seconds) | `1.0` |
| `-o` | Save results to file | — |

### Examples

```bash
# Default scan (ports 1-1024)
python3 portscanner.py -t 10.10.10.1

# Full range with 500 threads
python3 portscanner.py -t 10.10.10.1 -p 1-65535 -T 500

# Specific ports, save output
python3 portscanner.py -t 10.10.10.1 -p 22,80,443,8080 -o results.txt
```

---

## Go version

### Build

```bash
go build -o portscanner portscanner.go
```

### Usage

```bash
./portscanner -t <target> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Target host or IP | required |
| `-p` | Port range | `1-1024` |
| `-T` | Goroutines | `500` |
| `-timeout` | Connection timeout (seconds) | `1.0` |
| `-o` | Save results to file | — |

### Examples

```bash
./portscanner -t 10.10.10.1
./portscanner -t 10.10.10.1 -p 1-65535 -T 1000
./portscanner -t 10.10.10.1 -p 22,80,443 -o results.txt
```

---

## Python vs Go — performance comparison

| Metric | Python | Go |
|--------|--------|----|
| Concurrency model | Threads (GIL-limited) | Goroutines (true parallel) |
| Startup time | ~0.1s | ~0.01s |
| 1-1024 ports (LAN) | ~2–4s | ~0.5–1s |
| 1-65535 ports (LAN) | ~15–30s | ~3–8s |
| Memory usage | Higher | Lower |
| Binary distribution | Needs Python | Single static binary |

Go is significantly faster for large port ranges due to true concurrency with goroutines and no GIL overhead.

---

## Legal disclaimer

This tool is for **authorized testing and educational purposes only**.  
Never scan systems you do not own or have explicit written permission to test.

---

## Author

**s4mjx** — HTB player, studying penetration testing  
[Hack The Box profile](https://app.hackthebox.com/profile/)
