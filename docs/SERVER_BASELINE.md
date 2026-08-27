# Server baseline (read-only inventory)

Captured **2026-08-27** before any change was made to the host, as the pre-flight for
installing this node beside pre-existing, unrelated services.

No secret value appears in this document. Environment files, database URLs, tokens,
private keys and passphrases were **never read** — only their existence and file mode
were checked. The host's public IP address is deliberately omitted from this repository.

## Host

| Item | Value |
| --- | --- |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | Linux 6.8.0-111-generic |
| Architecture | x86-64 |
| Virtualisation | KVM (Hetzner vServer) |
| CPU | 2 vCPU, AMD EPYC-Genoa |
| RAM | 3.7 GiB total / **1.4 GiB available** at capture |
| Swap | 4.0 GiB file, 2.1 GiB used |
| Disk `/` | 75 GB total, 14 GB used, **58 GB free (20 %)** |
| Inodes `/` | 4 862 256 total, 209 385 used (**5 %**) |

## Toolchain present before this project

| Tool | Version |
| --- | --- |
| Node.js | v22.22.2 |
| npm | 10.9.7 |
| Python | 3.12.3 (`/usr/bin/python3.12`), `venv` module available |
| `uv` | absent → installed for this project into `~/.local/bin` (user-local, no OS change) |
| Docker | absent |
| git | 2.43.0 |
| gh | 2.45.0 |
| PostgreSQL | 17.9 |

`uv` was the only toolchain addition, and it is a single user-owned binary. Python 3.12
was already present, so **no system-wide interpreter change was required.**

## Processes running before this project

Three pre-existing Node applications, managed by an existing PM2 instance owned by an
unrelated operating account. This node adds **no** PM2 process; it runs as its own
systemd service under its own Linux user. None of the three was stopped, restarted or
modified.

| Managed process | Listening on | Public host |
| --- | --- | --- |
| pre-existing app A | `127.0.0.1:3000` | mapped by the reverse proxy |
| pre-existing app B | `127.0.0.1:3001` | mapped by the reverse proxy |
| pre-existing app C | `127.0.0.1:3002` | mapped by the reverse proxy |

Additional non-PM2 listeners were observed on `3017`, `3137`, `3139`, `4071`, `4081`.
They belong to other work on this host and were left untouched.

## System services running before this project

`caddy`, `postgresql@17-main`, `redis-server`, `pm2-<operator>`, `ssh`, `fail2ban`,
`cron`, `atd`, plus the standard Ubuntu units. Only **one new unit** was added by this
project: `technocore-agent.service`.

## Reverse proxy

Caddy is active with six site blocks, each reverse-proxying to a loopback port. The
existing Caddyfile was **not modified** — see `docs/OPERATIONS.md` for why (the intended
hostname for this node has no DNS record yet, so no proxy block was added).

## Scheduled work

No user crontab. `/etc/cron.d` holds only distribution defaults (`e2scrub_all`,
`sysstat`). systemd timers are all distribution defaults (apt, logrotate, fstrim,
man-db, sysstat, tmpfiles). This project adds **no** cron entry and **no** timer; its
daily protocol watcher is an in-process asyncio loop inside its own service.

## Port selection

Ports `3020`–`3029` were all free. This node binds the lowest free one, **`127.0.0.1:3020`**,
loopback-only. It never binds `0.0.0.0`.

## Headroom verdict

Available RAM (1.4 GiB) exceeds the 1 GiB threshold and free disk (58 GB) exceeds the
5 GB threshold, and a free loopback port exists. **Co-residency is safe**: no pre-existing
service needed to be stopped or suspended, and none was. The reversible-suspension
procedure that would have applied otherwise is documented in `docs/RESTORE_CORESIDENT_SERVICE.md`
and was **not executed**.
