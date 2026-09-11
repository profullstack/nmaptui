# Scan types

nmaptui runs nmap. Every scan is one **technique** (how ports are probed) plus the options a **profile** presets: ports, timing, detection and scripts. The builder shows the exact command before anything runs, and `nmaptui profiles` prints the same table as this page from the code.

Root matters. Anything that needs raw sockets says so below. Without root, run `sudo -v` and start with `--sudo`, run nmaptui itself as root, or pick the TCP connect technique.

## Techniques

| Technique | Flag | Root | What it does |
|---|---|---|---|
| TCP SYN (half-open) (`syn`) | `-sS` | yes | Sends a SYN and reads the reply without completing the handshake. Fast, quiet in application logs, and the default when you are root. |
| TCP connect (`connect`) | `-sT` | no | Completes the handshake through the OS socket API. Works for any user; every probe shows up in the target's logs. |
| UDP (`udp`) | `-sU` | yes | Sends UDP datagrams and reads ICMP unreachable replies. Slow, because closed ports answer at a rate-limited trickle. Combine with a port list or top ports. |
| TCP SYN + UDP (`syn+udp`) | `-sS -sU` | yes | Both in one run. Twice the packets, one result set. |
| TCP ACK (firewall map) (`ack`) | `-sA` | yes | Never finds open ports. It tells you which ports a stateful firewall filters and which it lets through, which is what you want when mapping rules. |
| TCP window (`window`) | `-sW` | yes | ACK scan that reads the TCP window size of the RST to tell open from closed on some stacks. |
| TCP NULL (`null`) | `-sN` | yes | No flags set. Slips past some stateless filters; Windows answers RST to everything, so it only works against RFC-compliant stacks. |
| TCP FIN (`fin`) | `-sF` | yes | FIN only. Same trade-offs as NULL. |
| TCP Xmas (`xmas`) | `-sX` | yes | FIN, PSH and URG lit up. Same trade-offs as NULL. |
| TCP Maimon (`maimon`) | `-sM` | yes | FIN/ACK probe for BSD-derived stacks that drop it on open ports. |
| Ping sweep (no ports) (`ping`) | `-sn` | no | Host discovery only. Which addresses answer, no port probes. |
| List targets (no packets) (`list`) | `-sL` | no | Expands the target spec and resolves names. Sends nothing. Use it to check what a CIDR or range covers before scanning. |

Pick one in the builder under Scan > Technique, or on the command line with `-sT`, `-sS`, `-sU` or `-sn`. Any other technique goes through the builder or a profile.

Detection options add to whichever technique you pick: `-sV` probes open ports for product and version, `-O` fingerprints the operating system (root), `-sC` runs the default NSE scripts, `--script <expr>` runs a chosen set, `-A` turns all four on plus traceroute.

## Profiles

Each profile is a starting point. Change any field afterwards and the command underneath updates. Targets survive a profile change.

### Quick scan (`quick`)

Top 100 TCP ports, fast timing, no version probes.

```sh
nmap -sS -F -T4 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P quick --start
```

### Quick scan plus (`quick-plus`)

Top 100 ports with light version detection and OS fingerprinting.

```sh
nmap -sS -F -T4 -sV -O --version-intensity 2 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P quick-plus --start
```

### Regular (`regular`)

nmap's defaults: top 1000 TCP ports, SYN scan, no extras.

```sh
nmap -sS -T3 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P regular --start
```

### Intense (`intense`)

Top 1000 ports, versions, OS, default scripts and traceroute.

```sh
nmap -sS -T4 -A 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P intense --start
```

### Intense + UDP (`intense-udp`)

Intense, plus the top UDP ports. Slow.

```sh
nmap -sS -sU -T4 -A 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P intense-udp --start
```

### Intense, all TCP ports (`intense-all`)

Every TCP port with versions, OS and scripts.

```sh
nmap -sS -p 1-65535 -T4 -A 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P intense-all --start
```

### Intense, no ping (`intense-noping`)

Intense against hosts that drop ping probes.

```sh
nmap -sS -T4 -A -Pn 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P intense-noping --start
```

### Ping sweep (`ping`)

Which hosts are up. No ports.

```sh
nmap -sn -T4 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P ping --start
```

### Quick traceroute (`traceroute`)

Ping sweep with a route to each host.

```sh
nmap -sn -T4 --traceroute 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P traceroute --start
```

### Safe default scripts (`safe-scripts`)

Versions plus the default NSE script set.

```sh
nmap -sS -T4 -sV -sC 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P safe-scripts --start
```

### Vulnerability scripts (`vuln`)

Versions plus the NSE vuln category. Noisy, can crash fragile services.

```sh
nmap -sS -T4 -sV --script vuln 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P vuln --start
```

### Discovery scripts (`discovery`)

Versions plus the NSE discovery category.

```sh
nmap -sS -T4 -sV --script discovery 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P discovery --start
```

### Web services (`web`)

Common HTTP ports with titles, headers and certificates.

```sh
nmap -sS -p 80,443,8000,8008,8080,8443,8888 -T4 -sV --script http-title,http-headers,http-server-header,ssl-cert 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P web --start
```

### Windows / SMB (`smb`)

SMB, RDP and WinRM with OS discovery and share enumeration.

```sh
nmap -sS -p 135,139,445,3389,5985,5986 -T4 -sV --script smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares,rdp-ntlm-info 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P smb --start
```

### Databases (`databases`)

Database ports with version probes.

```sh
nmap -sS -p 1433,1521,3306,5432,5984,6379,7474,8086,9042,9200,11211,27017 -T4 -sV 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P databases --start
```

### Top 100 UDP (`udp-top`)

The 100 most common UDP ports with versions.

```sh
nmap -sU --top-ports 100 -T4 -sV 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P udp-top --start
```

### Slow comprehensive (`slow`)

SYN + UDP, all scripts that are safe, every evasion off. Very slow.

```sh
nmap -sS -sU -T4 -A --script 'default or (discovery and safe)' -Pn -PE -PP -PS80,443 -PA3389 -PU40125 -PY 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P slow --start
```

### Unprivileged (`connect`)

TCP connect scan with versions. Works without root.

```sh
nmap -sT -T4 -sV 10.0.0.0/24
```

```sh
nmaptui 10.0.0.0/24 -P connect --start
```

## Examples

Sweep a subnet to see what is up, no ports:

```sh
nmaptui 10.0.0.0/24 -P ping --start
```

The quick look at a new box, as an ordinary user:

```sh
nmaptui 10.0.0.5 -P connect --start
```

Everything on one host: all TCP ports, versions, OS, scripts, traceroute:

```sh
sudo nmaptui 10.0.0.5 -P intense-all --start
```

Web servers across a range, with titles and certificates:

```sh
nmaptui 10.0.0.0/24 -P web --start
```

Windows estate: SMB, RDP, WinRM, OS discovery, shares:

```sh
sudo nmaptui 10.0.0.0/24 -P smb --start
```

Vulnerability scripts against one service you own:

```sh
sudo nmaptui 10.0.0.7 -p 3306,6379 --script vuln --start
```

Hosts that drop ping, with a port list of your own and polite timing:

```sh
sudo nmaptui 10.0.0.9 -sS -Pn -p 22,23,80,443,8443 -T2 --start
```

UDP services, top 100 only, because UDP is slow:

```sh
sudo nmaptui 10.0.0.1 -P udp-top --start
```

Targets from a file, excluding the gateway, results to CSV afterwards:

```sh
sudo nmaptui -iL hosts.txt -P safe-scripts --start
nmaptui print ~/.local/share/nmaptui/scans/<id>.xml --format csv -o hosts.csv
```

What changed since last week:

```sh
nmaptui diff last-week.xml today.xml
```

## Timing

`-T0` to `-T5`. Profiles use T4, which assumes a fast, reliable network and is right for a LAN. Use T2 or T3 across a WAN or against fragile embedded devices, T1 or T0 only when you are trying not to be noticed and have hours to spare.

## Ports

Empty means nmap's default 1000. `-F` is the top 100. `--top-ports 200` any number. `-p 22,80,443`, `-p 1-1024`, `-p-` for all 65535, `-p U:53,T:80` to split by protocol. An explicit port list wins over `-F` and `--top-ports`.
