# NET-STRIKE

**Network auditing framework for Kali Linux** - one terminal console that drives **Nmap, Masscan,
TShark, Netdiscover and enum4linux-ng**, correlates everything into a single host inventory, derives
findings, and writes a detailed **HTML + JSON** report.

```
███╗   ███╗███████╗████████╗███████╗ █████╗ ██╗  ██╗███╗   ██╗ █████╗ ███████╗
████╗ ████║██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚██╗██╔╝████╗  ██║██╔══██╗██╔════╝
██╔████╔██║███████╗   ██║   █████╗  ███████║ ╚███╔╝ ██╔██╗ ██║███████║█████╗
██║╚██╔╝██║╚════██║   ██║   ██╔══╝  ██╔══██║ ██╔██╗ ██║██╔══██║██╔══╝
██║ ╚═╝ ██║███████║   ██║   ██║     ██║  ██║██╔╝ ██╗██║ ╚████║██║  ██║██║
╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
```

> **Authorized use only.** NET-STRIKE sends active probes. Use it on networks you own or have
> **written permission** to test, and on lab environments. See [Scope & safety](#scope--safety).

## Features

| Capability | Tool(s) | What it does |
|---|---|---|
| Network discovery | netdiscover, nmap | ARP sweep (/24, /16) + nmap host sweep |
| Host identification | nmap, ping | MAC vendor, hostname, TTL fingerprint, nmap OS detection |
| Port scanning | masscan, nmap | Fast masscan sweep, automatic nmap fallback |
| Service enumeration | nmap | `-sV` + default scripts per host, parallel |
| SMB / Windows enumeration | enum4linux-ng | Null session, shares, users, groups, SMBv1/signing |
| Traffic analysis | tshark | Scope-filtered passive capture or offline pcap analysis |
| Findings | built-in | Exposure/configuration rules with severity + remediation |
| Reporting | built-in | Self-contained dark HTML report + structured JSON |

**Terminal UI:** animated gradient banner, boot sequence, live pipeline dashboard (status indicators,
progress bar, live log stream, running stats). **Zero third-party Python dependencies.**

## Install (Kali Linux)

```bash
sudo apt update
sudo apt install -y nmap masscan tshark netdiscover enum4linux-ng python3
git clone <your-repo> net-strike && cd net-strike      # or unzip the archive
chmod +x netstrike.py
sudo ./netstrike.py check                               # toolchain + privilege check
```

Python 3.9+ is required. `requirements.txt` lists no packages: everything uses the standard library.
Most features need **root** (ARP, masscan, OS detection, capture) - run with `sudo`.

## Usage

```bash
sudo ./netstrike.py                                   # interactive console
sudo ./netstrike.py scan 192.168.56.0/24              # standard profile
sudo ./netstrike.py scan 10.0.0.5 -p quick            # fast triage of one host
sudo ./netstrike.py scan 192.168.56.0/24 -p full -i eth0 --duration 60
sudo ./netstrike.py scan 10.10.0.1-50 -m discovery,hostid,portscan --ports 22,80,443,445
sudo ./netstrike.py scan 192.168.56.0/24 --i-am-authorized --no-anim   # CI / non-interactive
./netstrike.py analyze capture.pcapng                 # offline traffic analysis (no packets sent)
./netstrike.py report reports/netstrike-<id>/report.json   # re-render the HTML report
./netstrike.py check                                  # tools, privileges, scope policy
```

### `scan` options

| Option | Default | Description |
|---|---|---|
| `targets` | - | IP, CIDR (max /16), range (`10.0.0.1-50`, `10.0.0.1-10.0.0.50`) or hostname |
| `-i, --iface` | auto | Interface for ARP / masscan / capture |
| `-p, --profile` | standard | `quick`, `standard`, `full` |
| `-m, --modules` | per profile | `discovery,hostid,portscan,services,smb,traffic` |
| `--ports` | per profile | e.g. `22,80,443` or `1-10000` |
| `--rate` | 1000 | Packets/sec (max 25000) |
| `--duration` | per profile | Traffic capture seconds |
| `--threads` | 3 | Parallel nmap service scans |
| `--timing` | 4 | nmap `-T` template (1-5) |
| `--no-scripts` | off | Skip nmap default scripts |
| `-o, --out` | `./reports` | Output directory |
| `-f, --format` | `html,json` | Report formats |
| `--scope-file` | `~/.netstrike/scope.txt` | Extra authorized networks |
| `--i-am-authorized` | off | Non-interactive authorization confirmation |
| `--no-anim`, `--no-banner` | off | Plain output / skip banner |

### Profiles

| Profile | Modules | Ports | Capture |
|---|---|---|---|
| `quick` | discovery, hostid, portscan, services | ~40 common ports | - |
| `standard` | all | 1-10000 | 20 s |
| `full` | all | 1-65535 | 45 s |

## Scope & safety

NET-STRIKE is built to be hard to point at the wrong thing:

1. **Private/lab ranges only by default** - RFC 1918, loopback and link-local. Any other address must
   be listed in `~/.netstrike/scope.txt` (see `scope.example.txt`).
2. **Size cap** - a single run cannot cover more than a /16.
3. **Authorization gate** - you must type `I AM AUTHORIZED` (or pass `--i-am-authorized`) every run.
4. **Audit log** - every run is appended to `~/.netstrike/audit.log` (mode 0600).
5. **Scope is re-checked** - every host reported by any tool is validated against the scope before it
   is stored or scanned; stray results (e.g. `10.9.9.9`) are dropped with a warning.
6. **Netdiscover is never widened** - it only supports /8,/16,/24, so it runs only on exact /16 or /24
   targets rather than probing a larger range than you authorized.
7. **Capture is scope-filtered** - the tshark BPF filter is built from your targets.
8. **No shell** - tools are executed with argument lists, ports/interfaces are strictly validated.
9. **Untrusted output** - terminal output is stripped of escape sequences; the HTML report escapes
   every value and ships with a restrictive Content-Security-Policy.

What NET-STRIKE deliberately does **not** do: exploit anything, brute-force credentials, match versions
to CVEs, or extract credentials/payloads from traffic. Findings are exposure/configuration evidence
(e.g. anonymous FTP, SMB signing not required, clear-text protocols seen, one IP claimed by two MACs).

## Output

```
reports/netstrike-20261110-221337/
├── report.html          # self-contained report (no external resources), mode 0600
├── report.json          # full structured data (schema netstrike-report/1), mode 0600
├── netstrike.log        # complete raw log incl. tool output
├── discovery.xml, hostid-os.xml, services-<ip>.xml, masscan.lst, capture.pcapng,
└── enum4linux-<ip>.json # raw tool artifacts
```

The directory is created 0700 and handed back to the invoking user when run through `sudo`.

## Architecture

```
netstrike.py              CLI: argparse, boot sequence, interactive console, commands
netstrike/
├── config.py             constants, tool registry, profiles, safety limits
├── term.py               ANSI primitives: truecolor/256-colour, gradients, safe truncation
├── banner.py             MSTFAXNAF art, orange gradient, reveal + shimmer animation
├── ui.py                 live dashboard, log stream, tables, prompts, results summary
├── scope.py              target parsing, scope policy, authorization, audit log
├── runner.py             safe subprocess runner (streaming, timeouts, group kill), tool detection
├── models.py             Host / Port / Finding / Traffic / Session dataclasses
├── parsers.py            nmap XML, masscan, netdiscover, enum4linux-ng, tshark aggregation
├── context.py            shared Context handed to every module (scope-aware host registry)
├── engine.py             orchestration, error isolation, Ctrl+C handling, report phase
├── findings.py           exposure / configuration rules
├── modules/              discovery · hostid · portscan · services · smb · traffic
└── reporting/            json_report · html_report
tests/                    28 unit + integration tests, fake_bin/ simulated toolchain
```

Each module exposes `run(ctx) -> (status, detail)`; it may raise `ModuleSkipped` (missing tool or
prerequisite) or `ModuleError`. The engine isolates failures, so one broken tool never aborts the audit,
and Ctrl+C stops child processes (whole process group) and still writes a **partial report**.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

The integration tests run the real CLI against `tests/fake_bin/` - small executables that imitate
nmap, masscan, netdiscover, tshark, enum4linux-ng and ping - so the pipeline, scope guard, report
escaping, Ctrl+C handling and graceful degradation are verified without touching a network.
You can use the same trick for a dry run (no real tools needed):

```bash
chmod +x tests/fake_bin/*
PATH="$PWD/tests/fake_bin:$PATH" python3 netstrike.py scan 192.168.56.0/24 --i-am-authorized --duration 2
```

## Notes & limitations

* IPv4 only. Netdiscover is ARP-based, so it only sees the local L2 segment.
* Masscan uses its own TCP stack: scanning the machine you run it from (or loopback) will not work, so
  NET-STRIKE falls back to nmap there. In NAT/VM networks masscan may need `--router-mac`; failures
  also trigger the nmap fallback.
* Live capture needs root, or dumpcap capabilities (`sudo dpkg-reconfigure wireshark-common`).
* OS detection (`nmap -O`) needs root and at least one open and one closed port for good accuracy; the
  TTL heuristic is only a rough hint.
* Tool flags/output follow the documented CLIs of nmap 7.9x, masscan 1.3, tshark 4.x, netdiscover 0.10
  and enum4linux-ng 1.3. Parsers are defensive and warn instead of crashing if output differs.
  Run `./netstrike.py check` after upgrades.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `masscan ... falling back to nmap` | Run as root; avoid scanning your own IP; check `-i` |
| `capture produced no data` | Run with sudo or fix wireshark-common capabilities; check `-i` |
| `netdiscover supports /16 and /24 only` | Expected for other prefix lengths; nmap covers them |
| Garbled box characters | Use a UTF-8 terminal (`echo $LANG`); NET-STRIKE falls back to ASCII |
| No colours | `NO_COLOR` set, or not a TTY. Set `COLORTERM=truecolor` for the full gradient |

## License / disclaimer

Provided for lawful security auditing. You are solely responsible for obtaining authorization before
scanning any system. The authors accept no liability for misuse.
