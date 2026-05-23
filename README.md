# ⬡ NetProbe

Fast network discovery tool with ICMP scanning and TCP fallback — built for pentesters and network engineers.

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

- ICMP echo scan — fast host discovery across any subnet
- TCP fallback mode (`-f`) — catches hosts that silently block ICMP
- Auto subnet detection from a network interface
- Reverse DNS lookup for discovered hosts
- Method badges in fallback mode — see exactly how each host was found
- Clean, modern terminal UI with live spinner

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

Optionally move it to your PATH:

```bash
sudo mv ./netprobe /usr/local/bin/netprobe
```

---

## Usage

```
netprobe [flags]

Flags:
  -i, --interface   Network interface to scan (e.g. eth0, wlan0)
  -r, --range       Target subnet in CIDR notation (e.g. 192.168.1.0/24)
  -f, --fallback    Also probe via TCP when a host doesn't respond to ICMP
  -h, --help        Help for netprobe
```

### Examples

```bash
# auto-detect subnet from interface
netprobe -i wlan0

# scan a specific range
netprobe -r 192.168.1.0/24

# fallback mode — also catches ICMP-filtered hosts
netprobe -i wlan0 -f
netprobe -r 10.0.0.0/24 -f
```

### Fallback mode output

When `-f` is used, each host shows how it was discovered:

```
  ●  192.168.0.103    icmp      Wizard
  ●  192.168.0.111    icmp      _gateway
  ●  192.168.0.150    tcp:22
  ●  192.168.0.201    tcp:443   router.local
```

---

## How it works

**Normal scan (`-i` / `-r`)**
Sends ICMP echo requests across the subnet using a single shared raw socket. Fast and lightweight — a /24 finishes in under 3 seconds.

**Fallback scan (`-f`)**
After ICMP completes, any host that didn't reply gets re-probed over TCP on ports `22, 80, 443, 8080, 8443`. Useful against firewalls that drop ICMP but leave services exposed.

---

## Permissions

NetProbe uses raw ICMP sockets. Instead of running as root every time, set the capability once after each build:

```bash
sudo setcap cap_net_raw+ep ./netprobe
```

This grants only the raw socket capability — not full root access.

---

## Roadmap

- [ ] Port scanner (SYN + connect scan)
- [ ] Service/version detection
- [ ] JSON and plain-text output
- [ ] CIDR range from file

---

## Author

**Muhammad Shawon** — [@penguinshero](https://github.com/penguinshero)
