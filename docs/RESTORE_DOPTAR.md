# Restoring a co-resident service

This node was installed beside pre-existing, unrelated applications on a shared host. It
was designed so that no such application had to be stopped, reconfigured, or touched — and
during installation, none was.

This document exists for the case where that stops being true.

## What was done to the host

| Change | Reversible by |
| --- | --- |
| Created the `technocore-agent` system user | `userdel technocore-agent` |
| Created `/etc/technocore-agent` and `/var/lib/technocore-agent` | `rm -rf` both, after backing up the key |
| Installed `technocore-agent.service` | `systemctl disable --now`, then remove the unit |
| Bound `127.0.0.1:3020` | Stopping the service frees it |
| Installed `uv` into the operator's `~/.local/bin` | Delete the two binaries |

Nothing else. No pre-existing process manager, reverse-proxy configuration, database,
environment file, or application directory was read, modified, or restarted.

## Removing this node entirely

```bash
sudo systemctl disable --now technocore-agent
sudo rm /etc/systemd/system/technocore-agent.service
sudo systemctl daemon-reload

# Back the key up FIRST if the identity might ever be used again — it cannot be
# regenerated, and every published receipt points at it.
sudo cp -p /etc/technocore-agent/identity.pem /root/technocore-agent-identity.pem.bak

sudo rm -rf /etc/technocore-agent /var/lib/technocore-agent
sudo userdel technocore-agent
```

## If this node has to yield resources

The node is small — one process, a 512 MB memory cap, and a SQLite file. If a co-resident
service needs the headroom anyway, stop this one rather than degrading anything else:

```bash
sudo systemctl stop technocore-agent      # reversible; state and key are untouched
sudo systemctl start technocore-agent     # resumes from its stored cursor and nonce
```

Stopping is safe at any point. The mailbox cursor and the nonce high-water mark are on
disk, so a restart resumes rather than replaying — and inbound jobs simply wait in the
mailbox until the node reads them.

## If a co-resident service was suspended for this one

It should not have been, and it was not. Should that ever become necessary, record before
acting — the current process state, the deployed commit, the reverse-proxy target, and the
service's own health check — and restore in the reverse order. Never delete another
service's data, configuration, or credentials to make room; suspension is reversible and
deletion is not.
