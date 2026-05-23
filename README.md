# ⬡ NetProbe

Fast network discovery and port scanner built for pentesters and network engineers.

```
  ⬡ NetProbe
  Speed with Intelligence — by Muhammad Shawon

  interface  wlan0
  target     192.168.0.0/24

  3 host(s) discovered

  ●  192.168.0.103    Wizard
  ●  192.168.0.111    _gateway
  ●  192.168.0.141
```

---

## Features

**Network Discovery**
- ICMP echo scan — fast host discovery across any subnet
- Auto subnet detection from a network interface
- TCP fallback mode (`-f`) — catches hosts that silently block ICMP
- Reverse DNS lookup for discovered hosts
- Method badges in fallback mode — see exactly how each host was found

**Port Scanning**
- Randomized port order — avoids sequential scan signatures
- Jitter — random delay variation to break timing patterns
- Rate limiting — stays under WAF/IDS thresholds
- Presets — `lan` for speed, `public` for stealth
- `--fast` flag — boost speed on public targets when needed
- Honeypot detection — open ratio, response uniformity, banner mismatch analysis

---

## Install

**Requirements:** Go 1.22+

```bash
git clone https://github.com/penguinshero/netprobe.git
cd netprobe
go mod tidy
go build -o netprobe .
```

Grant raw socket access so `sudo` is never needed:

```bash
sudo setcap cap_net_raw+ep ./netprobe
```

> Run this once after every build.

Optionally move to PATH:

```bash
sudo mv ./netprobe /usr/local/bin/netprobe
```

---

## Usage

```
netprobe [flags]

Discovery:
  -i, --interface        Network interface to scan (e.g. eth0, wlan0)
  -r, --range            Target subnet in CIDR notation (e.g. 192.168.1.0/24)
  -f, --fallback         TCP fallback for ICMP-filtered hosts

Port Scanning:
  -t, --target           Target IP address
  -p, --ports            Ports: 22,80  |  1-1000  |  - (all)
      --top              Scan top 1000 common ports
      --preset           Scan profile: lan (default) | public
      --fast             Increase speed for public targets
      --honeypot-detect  Analyze results for honeypot indicators

Other:
  -h, --help             Help for netprobe
```

---

## Examples

**Network Discovery**

```bash
# auto-detect subnet from interface
netprobe -i wlan0

# scan a specific range
netprobe -r 192.168.1.0/24

# fallback mode — also catches ICMP-filtered hosts
netprobe -i wlan0 -f
```

Fallback mode shows how each host was found:

```
  3 host(s) discovered

  ●  192.168.0.103    icmp    Wizard
  ●  192.168.0.111    icmp    _gateway
  ●  192.168.0.150    tcp:22
```

**Port Scanning**

```bash
# top 1000 ports on a LAN target
netprobe -t 192.168.0.1 --top --preset lan

# specific ports on a public target
netprobe -t 8.8.8.8 -p 22,80,443 --preset public

# full port range, faster
netprobe -t 8.8.8.8 -p- --preset public --fast

# with honeypot detection
netprobe -t 192.168.0.1 --top --preset lan --honeypot-detect
```

Port scan output:

```
  3 open port(s) on 192.168.0.1

  PORT        STATE     SERVICE
  ──────────────────────────────
  22/tcp      open      ssh
  80/tcp      open      http
  443/tcp     open      https
```

Honeypot detection output:

```
  ⚠ honeypot indicators   confidence MEDIUM

  open ratio            38%           [!]
  response uniformity   2.1ms         [!]
  banner check          no mismatch   ok
```

---

## How it works

**Discovery — ICMP scan**
Sends echo requests across the subnet using a single shared raw socket. A /24 finishes in under 3 seconds.

**Discovery — TCP fallback (`-f`)**
After ICMP, unresponsive hosts get re-probed on ports `22, 80, 443, 8080, 8443`. Catches devices behind ICMP-blocking firewalls.

**Port scan presets**

| Preset | Threads | Timeout | Rate | Jitter |
|--------|---------|---------|------|--------|
| `lan` | 500 | 800ms | 500/sec | off |
| `public` | 75 | 3s | 15/sec | on |
| `public --fast` | 150 | 1.5s | 50/sec | on |

**Honeypot detection (`--honeypot-detect`)**
Runs three checks after scanning — open port ratio, response time uniformity, and banner mismatch. Two or more indicators trigger a warning with a confidence level.

---

## Permissions

NetProbe uses raw ICMP sockets. Grant the capability once after each build:

```bash
sudo setcap cap_net_raw+ep ./netprobe
```

This is safer than running as root — it grants only the raw socket capability, nothing else.

---

## Roadmap

- [ ] Service and version detection
- [ ] JSON and plain-text output formats
- [ ] OS fingerprinting
- [ ] Input from file (target list)

---

## Author

**Muhammad Shawon** — [@penguinshero](https://github.com/penguinshero)
