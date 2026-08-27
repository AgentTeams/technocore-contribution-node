# Operations

## Deployment shape

The node runs as its **own systemd service under its own Linux user**, deliberately not
alongside anything else on the host:

| | |
| --- | --- |
| Service | `technocore-agent.service` |
| User / group | `technocore-agent` (no shell, no sudo, no home) |
| Bind | `127.0.0.1:3020` — loopback only, never `0.0.0.0` |
| Code | `/opt/technocore-agent` (read-only to the service) |
| State | `/var/lib/technocore-agent` (the only writable path) |
| Config | `/etc/technocore-agent` (root-owned, `0700`) |
| Key | `/etc/technocore-agent/identity.pem` (`0600`) |
| Passphrase | `/etc/technocore-agent/identity.pass` (`0600`) |

## Install

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin technocore-agent
sudo install -d -o root -g root -m 700 /etc/technocore-agent
sudo install -d -o technocore-agent -g technocore-agent -m 700 /var/lib/technocore-agent

# The passphrase, written straight to a 0600 file — never through a shell pipeline,
# where it would land in the process list and possibly in a shell history.
sudo touch /etc/technocore-agent/identity.pass
sudo chmod 600 /etc/technocore-agent/identity.pass
sudo openssl rand -out /etc/technocore-agent/identity.pass -base64 48
sudo chmod 600 /etc/technocore-agent/identity.pass

sudo install -m 640 -o root -g technocore-agent deploy/node.env.example \
     /etc/technocore-agent/node.env

# One production identity, generated once, kept.
sudo -u technocore-agent /opt/technocore-agent/.venv/bin/technocore-node keygen \
     --path /etc/technocore-agent/identity.pem \
     --passphrase-file /etc/technocore-agent/identity.pass

sudo install -m 644 deploy/technocore-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now technocore-agent
```

The key must be readable by the service user but writable by nobody else. Where `keygen`
runs as root instead, `chown technocore-agent /etc/technocore-agent/identity.pem` and
leave the mode at `0600`.

## Hardening

The unit sets, and `systemd-analyze security technocore-agent` will confirm:

`NoNewPrivileges` · `PrivateTmp` · `ProtectSystem=strict` · `ProtectHome=true` ·
`ProtectKernelTunables` · `ProtectKernelModules` · `ProtectControlGroups` ·
`ProtectProc=invisible` · `PrivateDevices` · `RestrictSUIDSGID` · `RestrictRealtime` ·
`RestrictNamespaces` · `LockPersonality` · `MemoryDenyWriteExecute` ·
`SystemCallFilter=@system-service` · empty `CapabilityBoundingSet` and
`AmbientCapabilities` · `ReadWritePaths=/var/lib/technocore-agent` ·
`MemoryMax=512M` · `TasksMax=128` · `Restart=on-failure`.

`IPAddressAllow`/`IPAddressDeny` are **not** used to allowlist the upstream by address:
the origin resolves to a CDN whose addresses change, so an address allowlist would be
either wrong or so wide it means nothing. The containment is in the code instead — a
compiled-in origin allowlist, checked at config load and again at client construction,
with no code path from a message to an arbitrary fetch.

## Reverse proxy

Add a **new** site block; never repoint an existing one. See
`deploy/Caddyfile.example`:

```
agent.example.com {
    encode zstd gzip
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
        -Server
    }
    request_body { max_size 64KB }
    reverse_proxy 127.0.0.1:3020
}
```

Back up, validate, then reload — never replace the whole config:

```bash
sudo cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak.$(date -u +%Y%m%dT%H%M%SZ)
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

**Only add the block once DNS already points at this host.** Without a record, Caddy
cannot obtain a certificate, and the block is dead weight that also risks a reload
failure. Until then the service is complete and reachable on loopback.

## Runbook

```bash
systemctl status technocore-agent
journalctl -u technocore-agent -f            # structured JSON, redacted
curl -s localhost:3020/healthz
curl -s localhost:3020/readyz
curl -s localhost:3020/v1/metrics

technocore-node did                          # public identity, no network
technocore-node snapshot                     # capture the upstream manifest
technocore-node metrics                      # read the ledger directly
technocore-node testnet-status
```

### Key backup and restore drill

```bash
sudo install -d -o root -g root -m 700 /root/technocore-agent-backup
sudo cp -p /etc/technocore-agent/identity.pem  /root/technocore-agent-backup/
sudo cp -p /etc/technocore-agent/identity.pass /root/technocore-agent-backup/
sudo sha256sum /root/technocore-agent-backup/identity.pem

# Prove the backup still yields the production DID. Writes nothing.
technocore-node verify-backup /root/technocore-agent-backup/identity.pem
```

The drill decrypts the backup **in memory**, derives the DID, and compares. It never
writes a key anywhere and never returns key material. Run it after any change to the key
or its passphrase — a backup nobody has restored is a hope, not a backup.

### Database integrity

```bash
sudo -u technocore-agent sqlite3 /var/lib/technocore-agent/state.db "PRAGMA integrity_check;"
```

`/readyz` runs the same check and returns 503 if it fails.

### If the upstream protocol changes

`/v1/protocol-status` reports it and the journal carries a warning. **Nothing changes
automatically** — no code edit, no pull request, no feature flag flipped. Read the diff,
decide, and deploy deliberately.

## What this node never touches

It has no access to anything else on the host: not another application's code, its
configuration, its database, or its credentials. `ProtectSystem=strict` plus a
`ReadWritePaths` of exactly one directory is the enforcement; the dedicated unprivileged
user is the second layer.
